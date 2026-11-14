import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import type { AuditIntegrity, AuditRecord } from "@signhold/core";
import { canonicalJson, sha256Hex } from "@signhold/core";

export const GENESIS_HASH = "0".repeat(64);
export const HASH_ALG = "sha256-v1";

/** The record without its integrity envelope: what gets hashed. */
export type AuditBody = Omit<AuditRecord, "integrity">;

/** sha256(canonicalJson({ ...body, seq, prevHash })). */
export function computeRecordHash(body: AuditBody, seq: number, prevHash: string): string {
  const { integrity: _drop, ...rest } = body as AuditRecord;
  return sha256Hex(canonicalJson({ ...rest, seq, prevHash, alg: HASH_ALG }));
}

// ---- Ed25519 signing ----

export interface AuditSigner {
  readonly keyId: string;
  readonly publicKeyPem: string;
  sign(hashHex: string): string; // base64
}

export interface AuditVerifierKey {
  keyId: string;
  publicKey: KeyObject;
}

export function keyIdOf(publicKey: KeyObject): string {
  const der = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return sha256Hex(der).slice(0, 16);
}

/** Load an Ed25519 private key from PEM (PKCS#8) or a 32-byte seed in base64/hex. */
export function loadEd25519PrivateKey(material: string): KeyObject {
  const trimmed = material.trim();
  if (trimmed.includes("-----BEGIN")) return createPrivateKey({ key: trimmed, format: "pem" });
  let seed: Buffer;
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) seed = Buffer.from(trimmed, "hex");
  else seed = Buffer.from(trimmed, "base64");
  if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes (hex, base64 or PKCS#8 PEM)");
  // PKCS#8 prefix for Ed25519 (RFC 8410): 302e020100300506032b657004220420 || seed
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({ key: Buffer.concat([prefix, seed]), format: "der", type: "pkcs8" });
}

export function loadEd25519PublicKey(material: string): KeyObject {
  const trimmed = material.trim();
  if (trimmed.includes("-----BEGIN")) return createPublicKey({ key: trimmed, format: "pem" });
  let raw: Buffer;
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) raw = Buffer.from(trimmed, "hex");
  else raw = Buffer.from(trimmed, "base64");
  if (raw.length !== 32) throw new Error("Ed25519 public key must be 32 bytes (hex, base64 or SPKI PEM)");
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({ key: Buffer.concat([prefix, raw]), format: "der", type: "spki" });
}

export function createEd25519Signer(privateKey: KeyObject): AuditSigner {
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("audit signing key must be Ed25519");
  const publicKey = createPublicKey(privateKey);
  const keyId = keyIdOf(publicKey);
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    keyId,
    publicKeyPem,
    sign(hashHex: string): string {
      return edSign(null, Buffer.from(hashHex, "utf8"), privateKey).toString("base64");
    },
  };
}

/** Generates an ephemeral Ed25519 key pair (dev mode). */
export function generateEphemeralSigner(): AuditSigner {
  const { privateKey } = generateKeyPairSync("ed25519");
  return createEd25519Signer(privateKey);
}

export function verifyRecordSignature(hashHex: string, signatureB64: string, publicKey: KeyObject): boolean {
  try {
    return edVerify(null, Buffer.from(hashHex, "utf8"), publicKey, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}

// ---- Chain sealing & verification ----

export interface SealOptions {
  signer?: AuditSigner;
}

/** Attach `integrity` to a record body, chaining it onto `prev`. */
export function sealRecord(body: AuditBody, prev: AuditIntegrity | undefined, opts: SealOptions = {}): AuditRecord {
  const seq = prev ? prev.seq + 1 : 0;
  const prevHash = prev ? prev.hash : GENESIS_HASH;
  const hash = computeRecordHash(body, seq, prevHash);
  const integrity: AuditIntegrity = { seq, prevHash, hash, alg: HASH_ALG };
  if (opts.signer) {
    integrity.signature = opts.signer.sign(hash);
    integrity.keyId = opts.signer.keyId;
  }
  return { ...(body as AuditRecord), integrity };
}

export interface VerifyFailure {
  seq: number;
  id: string;
  reason: "missing_integrity" | "hash_mismatch" | "broken_link" | "seq_gap" | "bad_signature" | "unsigned" | "unknown_key";
  detail?: string;
}

export interface VerifyResult {
  ok: boolean;
  checked: number;
  signedCount: number;
  firstSeq?: number;
  lastSeq?: number;
  lastHash?: string;
  failures: VerifyFailure[];
}

export interface VerifyOptions {
  /** Public keys accepted for signatures, by keyId. */
  publicKeys?: ReadonlyMap<string, KeyObject>;
  /** When true every record must carry a valid signature. */
  requireSignatures?: boolean;
  /**
   * Expected `prevHash` of the first record in `records` (hash of the record
   * preceding the slice). Defaults to GENESIS_HASH when the first record has seq 0,
   * otherwise the first record's own `prevHash` is trusted (partial verification).
   */
  expectedPrevHash?: string;
  /** Stop at first failure. Default false (collect up to maxFailures). */
  failFast?: boolean;
  maxFailures?: number;
}

/** Walk `records` (in chain order) and verify hashes, links, sequence and signatures. */
export function verifyChain(records: Iterable<AuditRecord>, opts: VerifyOptions = {}): VerifyResult {
  const result: VerifyResult = { ok: true, checked: 0, signedCount: 0, failures: [] };
  const maxFailures = opts.maxFailures ?? 100;
  let expectedPrev: string | undefined = opts.expectedPrevHash;
  let expectedSeq: number | undefined;

  const fail = (f: VerifyFailure): boolean => {
    result.ok = false;
    if (result.failures.length < maxFailures) result.failures.push(f);
    return Boolean(opts.failFast);
  };

  for (const rec of records) {
    const integ = rec.integrity;
    result.checked++;
    if (!integ) {
      if (fail({ seq: -1, id: rec.id, reason: "missing_integrity" })) break;
      continue;
    }
    if (result.firstSeq === undefined) {
      result.firstSeq = integ.seq;
      if (expectedPrev === undefined) expectedPrev = integ.seq === 0 ? GENESIS_HASH : integ.prevHash;
      expectedSeq = integ.seq;
    }
    if (integ.seq !== expectedSeq) {
      if (fail({ seq: integ.seq, id: rec.id, reason: "seq_gap", detail: `expected ${expectedSeq}` })) break;
      expectedSeq = integ.seq;
    }
    if (integ.prevHash !== expectedPrev) {
      if (fail({ seq: integ.seq, id: rec.id, reason: "broken_link", detail: `expected prevHash ${expectedPrev}` })) break;
    }
    const recomputed = computeRecordHash(rec, integ.seq, integ.prevHash);
    if (recomputed !== integ.hash) {
      if (fail({ seq: integ.seq, id: rec.id, reason: "hash_mismatch", detail: `recomputed ${recomputed}` })) break;
    }
    if (integ.signature) {
      result.signedCount++;
      const pk = integ.keyId ? opts.publicKeys?.get(integ.keyId) : undefined;
      if (!pk) {
        if (opts.publicKeys && opts.publicKeys.size > 0) {
          if (fail({ seq: integ.seq, id: rec.id, reason: "unknown_key", detail: integ.keyId })) break;
        }
      } else if (!verifyRecordSignature(integ.hash, integ.signature, pk)) {
        if (fail({ seq: integ.seq, id: rec.id, reason: "bad_signature" })) break;
      }
    } else if (opts.requireSignatures) {
      if (fail({ seq: integ.seq, id: rec.id, reason: "unsigned" })) break;
    }
    expectedPrev = integ.hash;
    expectedSeq = integ.seq + 1;
    result.lastSeq = integ.seq;
    result.lastHash = integ.hash;
  }
  return result;
}
