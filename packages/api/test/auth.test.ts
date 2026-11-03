import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { ApiKeyring, NonceCache, computeSignature, parseApiKeysEnv, signatureBaseString, signingKeyMaterial } from "../src/auth.js";
import { InMemoryAuditStore } from "../src/audit.js";
import { stringifyWithBigints } from "../src/serialization.js";
import { createServer } from "../src/server.js";
import type { ServerOptions } from "../src/types.js";
import { FakeAdapter, FakeEngine, requestBody, testPolicy } from "./fakes.js";

async function build(opts: Partial<ServerOptions> = {}) {
  const audit = new InMemoryAuditStore();
  const app = await createServer({
    engine: new FakeEngine(),
    adapters: { evm: new FakeAdapter("evm") },
    policies: new Map([[testPolicy.id, testPolicy]]),
    audit,
    logger: false,
    rateLimit: false,
    env: "test",
    ...opts,
  });
  return { app, audit };
}

describe("ApiKeyring", () => {
  it("stores only hashes and identifies keys by id", () => {
    const ring = new ApiKeyring([{ id: "ops", key: "secret-1" }, "plain-key"]);
    expect(ring.size).toBe(2);
    expect(ring.identify("secret-1")).toBe("ops");
    expect(ring.identify("plain-key")).toMatch(/^key-[0-9a-f]{12}$/);
    expect(ring.identify("secret-2")).toBeUndefined();
    expect(ring.identify("")).toBeUndefined();
    expect(ring.identify(undefined)).toBeUndefined();
    // No raw key material retained anywhere on the instance.
    expect(JSON.stringify(ring)).not.toContain("secret-1");
    expect(JSON.stringify(ring)).not.toContain("plain-key");
  });

  it("rejects duplicate ids and malformed ids", () => {
    expect(() => new ApiKeyring([{ id: "a", key: "x" }, { id: "a", key: "y" }])).toThrow(/duplicate/);
    expect(() => new ApiKeyring([{ id: "bad id!", key: "x" }])).toThrow(/invalid api key id/);
  });

  it("parses AGENTGUARD_API_KEYS with optional id prefixes", () => {
    const keys = parseApiKeysEnv(" ops:abc , def ,, trading:ghi:with:colons ");
    expect(keys.map((k) => k.id)).toEqual(["ops", expect.stringMatching(/^key-/), "trading"]);
    expect(keys[2].key).toBe("ghi:with:colons");
    expect(parseApiKeysEnv(undefined)).toEqual([]);
  });

  it("verifies HMAC signatures in constant time and rejects tampering", () => {
    const ring = new ApiKeyring([{ id: "ops", key: "secret-1" }]);
    const input = { timestamp: "1700000000000", nonce: "abcdefgh", method: "post", path: "/v1/check", body: '{"a":1}' };
    const sig = ring.sign("ops", input)!;
    expect(sig).toMatch(/^v1=[0-9a-f]{64}$/);
    expect(computeSignature(signingKeyMaterial("secret-1"), input)).toBe(sig);
    expect(ring.verifySignature("ops", sig, input)).toBe(true);
    expect(ring.verifySignature("ops", sig, { ...input, body: '{"a":2}' })).toBe(false);
    expect(ring.verifySignature("ops", sig, { ...input, path: "/v1/audit" })).toBe(false);
    expect(ring.verifySignature("ops", "v1=00", input)).toBe(false);
    expect(ring.verifySignature("nope", sig, input)).toBe(false);
    expect(signatureBaseString(input).split("\n")).toHaveLength(6);
  });
});

describe("NonceCache", () => {
  it("rejects replays, expires entries and bounds its size", () => {
    let t = 1000;
    const c = new NonceCache(100, 2, () => t);
    expect(c.consume("a")).toBe(true);
    expect(c.consume("a")).toBe(false);
    expect(c.consume("b")).toBe(true);
    expect(c.consume("c")).toBe(true); // evicts "a"
    expect(c.size).toBe(2);
    t = 1201;
    expect(c.consume("b")).toBe(true); // expired, so fresh again
  });
});

describe("server auth", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("refuses to start in production without keys", async () => {
    await expect(build({ apiKeys: [], env: "production" })).rejects.toThrow(/production/);
    const built = await build({ apiKeys: ["k"], env: "production" });
    app = built.app;
    expect((await app.inject({ method: "GET", url: "/healthz" })).statusCode).toBe(200);
  });

  it("attaches the key identity to the audit record and never the key itself", async () => {
    const built = await build({ apiKeys: [{ id: "ops-bot", key: "super-secret" }] });
    app = built.app;
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody(), headers: { "x-api-key": "super-secret" } });
    expect(res.statusCode).toBe(200);
    const rec = await built.audit.get(res.json().auditId);
    expect(rec?.principal?.apiKeyId).toBe("ops-bot");
    expect(rec?.principal?.requestId).toBe(res.headers["x-request-id"]);
    expect(rec?.principal?.signed).toBe(false);
    expect(stringifyWithBigints(rec)).not.toContain("super-secret");
  });

  it("does not accept keys that are prefixes or differ in length", async () => {
    ({ app } = await build({ apiKeys: ["abcdef"] }));
    for (const k of ["abcde", "abcdefg", "ABCDEF", " abcdef"]) {
      expect((await app.inject({ method: "POST", url: "/v1/check", payload: requestBody(), headers: { "x-api-key": k } })).statusCode).toBe(401);
    }
  });
});

describe("HMAC request signing", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());
  const KEY = "signing-secret";

  function signedHeaders(body: string, overrides: Partial<{ ts: string; nonce: string; path: string; method: string; key: string }> = {}) {
    const ts = overrides.ts ?? String(Date.now());
    const nonce = overrides.nonce ?? randomUUID().replace(/-/g, "");
    const sig = computeSignature(signingKeyMaterial(overrides.key ?? KEY), {
      timestamp: ts,
      nonce,
      method: overrides.method ?? "POST",
      path: overrides.path ?? "/v1/check",
      body,
    });
    return { "x-api-key": KEY, "content-type": "application/json", "x-agentguard-signature": sig, "x-agentguard-timestamp": ts, "x-agentguard-nonce": nonce };
  }

  it("accepts a valid signature and marks the audit record as signed", async () => {
    const built = await build({ apiKeys: [{ id: "ops", key: KEY }] });
    app = built.app;
    const body = JSON.stringify(requestBody());
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: body, headers: signedHeaders(body) });
    expect(res.statusCode).toBe(200);
    expect((await built.audit.get(res.json().auditId))?.principal?.signed).toBe(true);
  });

  it("rejects replayed nonces, stale timestamps, tampered bodies and partial headers", async () => {
    ({ app } = await build({ apiKeys: [{ id: "ops", key: KEY }], signing: { windowMs: 5 * 60_000 } }));
    const body = JSON.stringify(requestBody());
    const headers = signedHeaders(body);
    expect((await app.inject({ method: "POST", url: "/v1/check", payload: body, headers })).statusCode).toBe(200);
    const replay = await app.inject({ method: "POST", url: "/v1/check", payload: body, headers });
    expect(replay.statusCode).toBe(401);
    expect(replay.json().message).toMatch(/nonce/);

    const stale = await app.inject({ method: "POST", url: "/v1/check", payload: body, headers: signedHeaders(body, { ts: String(Date.now() - 6 * 60_000) }) });
    expect(stale.statusCode).toBe(401);
    expect(stale.json().message).toMatch(/window/);

    const tampered = JSON.stringify(requestBody({ policyId: testPolicy.id }));
    expect((await app.inject({ method: "POST", url: "/v1/check", payload: tampered, headers: signedHeaders(body) })).statusCode).toBe(401);

    const wrongKey = await app.inject({ method: "POST", url: "/v1/check", payload: body, headers: signedHeaders(body, { key: "other" }) });
    expect(wrongKey.statusCode).toBe(401);
    expect(wrongKey.json().error).toBe("invalid_signature");

    const partial = { ...signedHeaders(body) } as Record<string, string>;
    delete partial["x-agentguard-nonce"];
    expect((await app.inject({ method: "POST", url: "/v1/check", payload: body, headers: partial })).statusCode).toBe(401);
  });

  it("can require signatures on every authenticated request", async () => {
    ({ app } = await build({ apiKeys: [{ id: "ops", key: KEY }], signing: { required: true } }));
    const unsigned = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody(), headers: { "x-api-key": KEY } });
    expect(unsigned.statusCode).toBe(401);
    expect(unsigned.json().message).toMatch(/required/);
    const get = await app.inject({ method: "GET", url: "/v1/audit?limit=1", headers: signedHeaders("", { method: "GET", path: "/v1/audit?limit=1" }) });
    expect(get.statusCode).toBe(200);
  });
});
