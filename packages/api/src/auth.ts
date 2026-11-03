import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { sha256Hex } from "@agentguard/core";

/** API key configuration. Raw keys are hashed immediately and never retained. */
export interface ApiKeyConfig {
  /** Stable identity recorded in audit/logs. Never the key itself. */
  id: string;
  /** The raw secret presented in `x-api-key`. */
  key: string;
  /** Optional dedicated HMAC secret for request signing; defaults to the key. */
  signingSecret?: string;
}

interface StoredKey {
  id: string;
  keyHash: Buffer; // sha256(key), 32 bytes
  signingSecretHash: Buffer; // sha256(signingSecret ?? key), used as HMAC key
}

const ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;

/** Short, non-reversible fingerprint of a secret (for logs / default ids). */
export function fingerprint(secret: string): string {
  return sha256Hex(secret).slice(0, 12);
}

/**
 * Parse `AGENTGUARD_API_KEYS`: comma-separated entries of either `<key>` or
 * `<id>:<key>`. An id is only recognised when it matches [A-Za-z0-9_.-]{1,64}
 * and is followed by a non-empty key; otherwise the whole entry is the key and
 * the id is derived from its fingerprint.
 */
export function parseApiKeysEnv(raw: string | undefined): ApiKeyConfig[] {
  if (!raw) return [];
  const out: ApiKeyConfig[] = [];
  for (const entry of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    const idx = entry.indexOf(":");
    if (idx > 0 && ID_RE.test(entry.slice(0, idx)) && entry.length > idx + 1) {
      out.push({ id: entry.slice(0, idx), key: entry.slice(idx + 1) });
    } else {
      out.push({ id: `key-${fingerprint(entry)}`, key: entry });
    }
  }
  return out;
}

export function normalizeApiKeys(keys: ReadonlyArray<string | ApiKeyConfig> | undefined): ApiKeyConfig[] {
  const out: ApiKeyConfig[] = [];
  for (const k of keys ?? []) {
    if (typeof k === "string") {
      const key = k.trim();
      if (key) out.push({ id: `key-${fingerprint(key)}`, key });
    } else if (k && typeof k.key === "string" && k.key.trim()) {
      if (!ID_RE.test(k.id)) throw new Error(`invalid api key id '${k.id}': must match ${ID_RE}`);
      out.push({ id: k.id, key: k.key.trim(), signingSecret: k.signingSecret });
    }
  }
  const ids = new Set<string>();
  for (const k of out) {
    if (ids.has(k.id)) throw new Error(`duplicate api key id '${k.id}'`);
    ids.add(k.id);
  }
  return out;
}

function sha256(s: string): Buffer {
  return createHash("sha256").update(s, "utf8").digest();
}

/**
 * Holds API keys as SHA-256 hashes. `identify()` compares the hash of the
 * presented key against every stored hash with `timingSafeEqual`, without early
 * exit, so response time does not depend on which (if any) key matched.
 */
export class ApiKeyring {
  private readonly keys: StoredKey[];

  constructor(configs: ReadonlyArray<string | ApiKeyConfig>) {
    this.keys = normalizeApiKeys(configs).map((c) => ({
      id: c.id,
      keyHash: sha256(c.key),
      signingSecretHash: sha256(c.signingSecret ?? c.key),
    }));
  }

  get size(): number {
    return this.keys.length;
  }

  get ids(): string[] {
    return this.keys.map((k) => k.id);
  }

  /** Returns the key id when `presented` matches a configured key, else undefined. */
  identify(presented: string | undefined): string | undefined {
    if (typeof presented !== "string" || presented.length === 0 || presented.length > 4096) return undefined;
    const h = sha256(presented);
    let match: StoredKey | undefined;
    for (const k of this.keys) {
      // Constant-time per key; no early exit.
      if (timingSafeEqual(h, k.keyHash)) match = k;
    }
    return match?.id;
  }

  /** HMAC-SHA256 key material for request signing of a given key id. */
  private signingKey(id: string): Buffer | undefined {
    return this.keys.find((k) => k.id === id)?.signingSecretHash;
  }

  /** Compute the expected signature for a key id. Exposed for the server and tests. */
  sign(id: string, input: SignatureInput): string | undefined {
    const key = this.signingKey(id);
    if (!key) return undefined;
    return computeSignature(key, input);
  }

  /** Constant-time comparison of a presented signature (`v1=<hex>`) for a key id. */
  verifySignature(id: string, presented: string, input: SignatureInput): boolean {
    const key = this.signingKey(id);
    if (!key) return false;
    const expected = computeSignature(key, input);
    const a = Buffer.from(expected, "utf8");
    const b = Buffer.from(presented, "utf8");
    if (a.length !== b.length) {
      // Still burn a comparison so the length mismatch is not observable.
      timingSafeEqual(a, a);
      return false;
    }
    return timingSafeEqual(a, b);
  }
}

/** Inputs covered by the request signature. */
export interface SignatureInput {
  timestamp: string; // unix milliseconds, decimal string
  nonce: string;
  method: string;
  /** Path including query string, e.g. `/v1/check`. */
  path: string;
  body: string; // raw request body ("" for GET)
}

export const SIGNATURE_VERSION = "v1";

/** Canonical string that is HMAC'd: v1 \n ts \n nonce \n METHOD \n path \n sha256(body). */
export function signatureBaseString(input: SignatureInput): string {
  return [SIGNATURE_VERSION, input.timestamp, input.nonce, input.method.toUpperCase(), input.path, sha256Hex(input.body)].join(
    "\n",
  );
}

/**
 * HMAC-SHA256 over the base string. `keyMaterial` is sha256(signingSecret) so
 * a raw secret never has to be held after construction. Clients MUST derive the
 * same material: HMAC key = sha256(secret) (raw bytes).
 */
export function computeSignature(keyMaterial: Buffer, input: SignatureInput): string {
  const mac = createHmac("sha256", keyMaterial).update(signatureBaseString(input), "utf8").digest("hex");
  return `${SIGNATURE_VERSION}=${mac}`;
}

/** Derive HMAC key material from a raw secret (shared with the SDK). */
export function signingKeyMaterial(secret: string): Buffer {
  return sha256(secret);
}

/** Bounded nonce cache with TTL for replay protection. */
export class NonceCache {
  private readonly seen = new Map<string, number>();
  constructor(
    private readonly ttlMs: number,
    private readonly maxEntries = 100_000,
    private readonly now: () => number = Date.now,
  ) {}

  /** Returns true when the nonce is fresh (and records it); false when replayed. */
  consume(key: string): boolean {
    const t = this.now();
    this.prune(t);
    if (this.seen.has(key)) return false;
    if (this.seen.size >= this.maxEntries) {
      // Evict the oldest insertion (Map preserves insertion order).
      const oldest = this.seen.keys().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    this.seen.set(key, t + this.ttlMs);
    return true;
  }

  get size(): number {
    return this.seen.size;
  }

  private prune(now: number): void {
    // Cheap incremental prune: stop at the first live entry (insertion order ~ expiry order).
    for (const [k, exp] of this.seen) {
      if (exp > now) break;
      this.seen.delete(k);
    }
  }
}
