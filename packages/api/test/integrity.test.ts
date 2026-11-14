import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { AuditRecord } from "@signhold/core";
import { canonicalJson, sha256Hex } from "@signhold/core";
import { InMemoryAuditStore, JsonlAuditStore } from "../src/audit.js";
import {
  GENESIS_HASH,
  computeRecordHash,
  createEd25519Signer,
  generateEphemeralSigner,
  keyIdOf,
  loadEd25519PrivateKey,
  loadEd25519PublicKey,
  sealRecord,
  verifyChain,
} from "../src/integrity.js";
import { stringifyWithBigints } from "../src/serialization.js";
import { createServer } from "../src/server.js";
import { FROM, FakeAdapter, FakeEngine, intentId, okSimulation, requestBody, testPolicy } from "./fakes.js";

const execFileP = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));

function body(n: number): Omit<AuditRecord, "integrity"> {
  return {
    id: `0000000${n}-0000-4000-8000-000000000000`.slice(-36),
    recordedAt: "2026-01-01T00:00:00.000Z",
    intent: { id: intentId(n), chain: "evm", from: FROM, value: BigInt(n) * 10n ** 18n, data: "0x00" },
    context: { agentId: "a", now: new Date("2026-01-01T00:00:00Z") },
    decision: { intentId: intentId(n), verdict: "allow", findings: [], riskScore: 1, explanation: "ok", simulation: okSimulation(), policyId: "p", policyVersion: 1, evaluatedAt: "2026-01-01T00:00:00.000Z" },
  };
}

describe("canonicalJson", () => {
  it("sorts keys recursively, stringifies bigints and dates, drops undefined", () => {
    const a = canonicalJson({ b: 1n, a: { z: [3n, undefined, { y: 1, x: 2 }], d: new Date(0) }, u: undefined });
    const b = canonicalJson({ u: undefined, a: { d: new Date(0), z: [3n, undefined, { x: 2, y: 1 }] }, b: 1n });
    expect(a).toBe(b);
    expect(a).toBe('{"a":{"d":"1970-01-01T00:00:00.000Z","z":["3",null,{"x":2,"y":1}]},"b":"1"}');
    expect(() => canonicalJson({ n: Number.NaN })).toThrow();
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});

describe("sealRecord / verifyChain", () => {
  it("chains records and detects tampering anywhere in the chain", () => {
    const r0 = sealRecord(body(0), undefined);
    const r1 = sealRecord(body(1), r0.integrity);
    const r2 = sealRecord(body(2), r1.integrity);
    expect(r0.integrity).toMatchObject({ seq: 0, prevHash: GENESIS_HASH, alg: "sha256-v1" });
    expect(r1.integrity?.prevHash).toBe(r0.integrity?.hash);
    expect(r0.integrity?.hash).toBe(computeRecordHash(body(0), 0, GENESIS_HASH));
    expect(verifyChain([r0, r1, r2])).toMatchObject({ ok: true, checked: 3, firstSeq: 0, lastSeq: 2, failures: [] });

    // Tamper with a verdict in the middle: hash mismatch at 1 (link from 2 still consistent).
    const forged = { ...r1, decision: { ...r1.decision, verdict: "block" as const } };
    const res = verifyChain([r0, forged, r2]);
    expect(res.ok).toBe(false);
    expect(res.failures.map((f) => f.reason)).toEqual(["hash_mismatch"]);

    // Re-seal the forged record so its own hash is valid: the next link breaks.
    const resealed = sealRecord({ ...forged, integrity: undefined } as AuditRecord, r0.integrity);
    const res2 = verifyChain([r0, resealed, r2]);
    expect(res2.failures.map((f) => f.reason)).toEqual(["broken_link"]);

    // Deleting a record from the middle is a seq gap + broken link.
    const res3 = verifyChain([r0, r2]);
    expect(res3.failures.map((f) => f.reason)).toEqual(expect.arrayContaining(["seq_gap", "broken_link"]));

    // Legacy record without integrity.
    expect(verifyChain([r0, body(1) as AuditRecord]).failures[0].reason).toBe("missing_integrity");
  });

  it("verifies partial ranges starting mid-chain", () => {
    const r0 = sealRecord(body(0), undefined);
    const r1 = sealRecord(body(1), r0.integrity);
    const r2 = sealRecord(body(2), r1.integrity);
    expect(verifyChain([r1, r2]).ok).toBe(true);
    expect(verifyChain([r1, r2], { expectedPrevHash: r0.integrity!.hash }).ok).toBe(true);
    expect(verifyChain([r1, r2], { expectedPrevHash: "ff".repeat(32) }).ok).toBe(false);
  });

  it("signs with Ed25519 and detects bad / missing / unknown-key signatures", () => {
    const signer = generateEphemeralSigner();
    const other = generateEphemeralSigner();
    const r0 = sealRecord(body(0), undefined, { signer });
    const r1 = sealRecord(body(1), r0.integrity, { signer });
    expect(r0.integrity?.signature).toBeTruthy();
    expect(r0.integrity?.keyId).toBe(signer.keyId);

    const keys = new Map([[signer.keyId, loadEd25519PublicKey(signer.publicKeyPem)]]);
    expect(verifyChain([r0, r1], { publicKeys: keys, requireSignatures: true })).toMatchObject({ ok: true, signedCount: 2 });

    const badSig = { ...r1, integrity: { ...r1.integrity!, signature: other.sign(r1.integrity!.hash) } };
    expect(verifyChain([r0, badSig], { publicKeys: keys }).failures[0].reason).toBe("bad_signature");

    const unknown = { ...r1, integrity: { ...r1.integrity!, keyId: "deadbeef" } };
    expect(verifyChain([r0, unknown], { publicKeys: keys }).failures[0].reason).toBe("unknown_key");

    const unsigned = sealRecord(body(1), r0.integrity);
    expect(verifyChain([r0, unsigned], { publicKeys: keys, requireSignatures: true }).failures[0].reason).toBe("unsigned");
    expect(verifyChain([r0, unsigned], { publicKeys: keys }).ok).toBe(true);
  });

  it("loads keys from seed hex/base64 and PEM with a stable keyId", () => {
    const seed = "11".repeat(32);
    const a = createEd25519Signer(loadEd25519PrivateKey(seed));
    const b = createEd25519Signer(loadEd25519PrivateKey(Buffer.from(seed, "hex").toString("base64")));
    expect(a.keyId).toBe(b.keyId);
    expect(keyIdOf(loadEd25519PublicKey(a.publicKeyPem))).toBe(a.keyId);
    expect(() => loadEd25519PrivateKey("abcd")).toThrow(/32 bytes/);
  });
});

describe("chained audit stores", () => {
  let dir: string;
  beforeEach(async () => (dir = await mkdtemp(join(tmpdir(), "signhold-integrity-"))));
  afterEach(async () => rm(dir, { recursive: true, force: true }));

  it("InMemoryAuditStore seals sequentially even under concurrent writes", async () => {
    const s = new InMemoryAuditStore({ signer: generateEphemeralSigner() });
    await Promise.all(Array.from({ length: 20 }, (_, i) => s.record(body(i) as AuditRecord)));
    const all = await s.range(0, 100);
    expect(all.map((r) => r.integrity?.seq)).toEqual(Array.from({ length: 20 }, (_, i) => i));
    expect(verifyChain(all).ok).toBe(true);
    expect((await s.headIntegrity())?.seq).toBe(19);
    expect(await s.range(5, 7)).toHaveLength(3);
    expect(await s.range(50, 60)).toEqual([]);
  });

  it("JsonlAuditStore continues the chain across restarts and the CLI verifies / rejects tampering", async () => {
    const file = join(dir, "audit.jsonl");
    const signer = generateEphemeralSigner();
    const s1 = new JsonlAuditStore(file, { signer });
    for (let i = 0; i < 3; i++) await s1.record(body(i) as AuditRecord);
    const s2 = new JsonlAuditStore(file, { signer });
    await s2.record(body(3) as AuditRecord);
    const chain = await s2.range(0, 10);
    expect(chain.map((r) => r.integrity?.seq)).toEqual([0, 1, 2, 3]);
    expect(chain[3].integrity?.prevHash).toBe(chain[2].integrity?.hash);
    expect(verifyChain(chain).ok).toBe(true);

    const pem = join(dir, "pub.pem");
    await writeFile(pem, signer.publicKeyPem);
    const script = join(here, "..", "scripts", "verify-audit.ts");
    const tsx = join(here, "..", "..", "..", "node_modules", ".bin", "tsx");
    const okRun = await execFileP(tsx, [script, file, "--public-key", pem, "--require-signatures"]);
    expect(okRun.stdout).toContain("OK: audit chain verified");

    // Tamper: flip a verdict in line 2.
    const lines = (await readFile(file, "utf8")).trim().split("\n");
    const rec = JSON.parse(lines[1]);
    rec.decision.verdict = "block";
    lines[1] = stringifyWithBigints(rec);
    await writeFile(file, lines.join("\n") + "\n");
    const failRun = await execFileP(tsx, [script, file, "--json"]).catch((e: { code: number; stdout: string }) => e);
    expect(failRun.code).toBe(1);
    expect(JSON.parse(failRun.stdout).failures[0].reason).toBe("hash_mismatch");
  });
});

describe("GET /v1/audit/verify", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("walks and verifies the chain; reports tampering in a mutated store", async () => {
    const signer = generateEphemeralSigner();
    const audit = new InMemoryAuditStore({ signer });
    app = await createServer({
      engine: new FakeEngine(),
      adapters: { evm: new FakeAdapter("evm") },
      policies: new Map([[testPolicy.id, testPolicy]]),
      audit,
      logger: false,
      rateLimit: false,
      env: "test",
      auditPublicKeys: new Map([[signer.keyId, loadEd25519PublicKey(signer.publicKeyPem)]]),
    });
    for (let i = 0; i < 5; i++) {
      const b = requestBody();
      (b.intent as Record<string, unknown>).id = intentId(i);
      expect((await app.inject({ method: "POST", url: "/v1/check", payload: b })).statusCode).toBe(200);
    }
    const all = await app.inject({ method: "GET", url: "/v1/audit/verify" });
    expect(all.statusCode).toBe(200);
    expect(all.json()).toMatchObject({ ok: true, checked: 5, signedCount: 5, from: 0, to: 4, headSeq: 4, failures: [] });

    const part = await app.inject({ method: "GET", url: "/v1/audit/verify?from=2&to=3&requireSignatures=true" });
    expect(part.json()).toMatchObject({ ok: true, checked: 2, firstSeq: 2, lastSeq: 3 });
    expect((await app.inject({ method: "GET", url: "/v1/audit/verify?from=3&to=2" })).statusCode).toBe(400);

    // Mutate the in-memory record in place (simulates a compromised store).
    const victim = (await audit.range(1, 1))[0];
    victim.decision.verdict = "block";
    const res = await app.inject({ method: "GET", url: "/v1/audit/verify" });
    expect(res.json().ok).toBe(false);
    expect(res.json().failures[0]).toMatchObject({ seq: 1, reason: "hash_mismatch" });

    // Each returned audit record exposes its integrity envelope.
    const one = await app.inject({ method: "GET", url: `/v1/audit/${victim.id}` });
    expect(one.json().integrity).toMatchObject({ seq: 1, keyId: signer.keyId });
  });
});
