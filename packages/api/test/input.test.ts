import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { InMemoryAuditStore } from "../src/audit.js";
import { LIMITS, parseCheckRequest } from "../src/serialization.js";
import { createServer } from "../src/server.js";
import type { ServerOptions } from "../src/types.js";
import { FROM, INTENT_ID, FakeAdapter, FakeEngine, SOL_FROM, TO, requestBody, testPolicy } from "./fakes.js";

async function build(opts: Partial<ServerOptions> = {}) {
  const app = await createServer({
    engine: new FakeEngine(),
    adapters: { evm: new FakeAdapter("evm"), solana: new FakeAdapter("solana") },
    policies: new Map([[testPolicy.id, testPolicy]]),
    audit: new InMemoryAuditStore(),
    logger: false,
    rateLimit: false,
    env: "test",
    ...opts,
  });
  return app;
}

const intent = (o: Record<string, unknown> = {}) => ({ ...requestBody().intent, ...o });
const ok = (o: Record<string, unknown> = {}) => parseCheckRequest(requestBody({ intent: intent(o) }));
const bad = (o: Record<string, unknown> = {}) => expect(() => ok(o)).toThrow();

describe("checkRequestSchema", () => {
  it("accepts a well-formed EVM and Solana intent", () => {
    expect(ok().intent.value).toBe(1_000_000_000_000_000_000n);
    const sol = parseCheckRequest(requestBody({ intent: { id: INTENT_ID, chain: "solana", chainId: "mainnet-beta", from: SOL_FROM, raw: "AAAA" } }));
    expect(sol.intent.chain).toBe("solana");
  });

  it("rejects unknown keys at every level", () => {
    bad({ extra: 1 });
    expect(() => parseCheckRequest(requestBody({ context: { agentId: "a", extra: 1 } }))).toThrow();
    expect(() => parseCheckRequest({ ...requestBody(), extra: 1 })).toThrow();
  });

  it("requires intent ids to be UUIDs", () => {
    bad({ id: "intent-1" });
    bad({ id: "" });
    bad({ id: INTENT_ID.toUpperCase() + "x" });
  });

  it("validates address format per chain", () => {
    bad({ from: "0xfrom" });
    bad({ from: FROM.slice(0, -1) });
    bad({ from: FROM + "0" });
    bad({ to: "0xzz22222222222222222222222222222222222222" });
    bad({ from: SOL_FROM }); // solana address on evm chain
    expect(() => parseCheckRequest(requestBody({ intent: { id: INTENT_ID, chain: "solana", from: FROM } }))).toThrow();
    expect(() => parseCheckRequest(requestBody({ intent: { id: INTENT_ID, chain: "solana", from: "0OIl" + SOL_FROM.slice(4) } }))).toThrow(); // base58 alphabet
  });

  it("rejects chain-mismatched payload fields", () => {
    bad({ raw: "AAAA" }); // raw on evm
    expect(() => parseCheckRequest(requestBody({ intent: { id: INTENT_ID, chain: "solana", from: SOL_FROM, data: "0x00" } }))).toThrow();
  });

  it("bounds string lengths", () => {
    expect(ok({ description: "x".repeat(LIMITS.description) })).toBeTruthy();
    bad({ description: "x".repeat(LIMITS.description + 1) });
    expect(ok({ data: "0x" + "ab".repeat(LIMITS.calldataHex / 2) })).toBeTruthy();
    bad({ data: "0x" + "ab".repeat(LIMITS.calldataHex / 2 + 1) });
    bad({ data: "0xabc" }); // odd length
    bad({ data: "abcd" }); // missing prefix
    expect(ok({ metadata: { note: "x".repeat(LIMITS.metadataSerialized - 100) } })).toBeTruthy();
    bad({ metadata: { note: "x".repeat(LIMITS.metadataSerialized) } });
    expect(() => parseCheckRequest(requestBody({ context: { agentId: "x".repeat(LIMITS.id + 1) } }))).toThrow();
    expect(() => parseCheckRequest(requestBody({ policyId: "x".repeat(LIMITS.id + 1) }))).toThrow();
    expect(() => parseCheckRequest(requestBody({ context: { agentId: "a", denylist: new Array(LIMITS.listEntries + 1).fill(TO) } }))).toThrow();
  });

  it("rejects NaN / Infinity / non-integers in numeric fields", () => {
    for (const v of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1]) {
      expect(() => parseCheckRequest(requestBody({ context: { agentId: "a", spentUsdInWindow: v } }))).toThrow();
    }
    bad({ chainId: Number.NaN });
    bad({ chainId: 1.5 });
    bad({ chainId: -1 });
    bad({ value: Number.POSITIVE_INFINITY });
    bad({ value: 1.5 });
    bad({ value: "1e18" });
    bad({ value: "0x10" });
  });
});

describe("HTTP input hardening", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("rejects bodies over the limit with 413 (default 64 KiB) and honours a custom limit", async () => {
    app = await build();
    const big = requestBody({ intent: intent({ data: "0x" + "ab".repeat(40 * 1024) }) }); // ~80 KB
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: big });
    expect(res.statusCode).toBe(413);
    expect(res.json()).toMatchObject({ error: "payload_too_large", requestId: expect.any(String) });
    await app.close();

    app = await build({ bodyLimit: 256 });
    expect((await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() })).statusCode).toBe(413);
  });

  it("only accepts application/json", async () => {
    app = await build();
    const text = await app.inject({ method: "POST", url: "/v1/check", payload: JSON.stringify(requestBody()), headers: { "content-type": "text/plain" } });
    expect(text.statusCode).toBe(415);
    const form = await app.inject({ method: "POST", url: "/v1/check", payload: "a=b", headers: { "content-type": "application/x-www-form-urlencoded" } });
    expect(form.statusCode).toBe(415);
    const broken = await app.inject({ method: "POST", url: "/v1/check", payload: "{not json", headers: { "content-type": "application/json" } });
    expect(broken.statusCode).toBe(400);
    expect(broken.json().error).toBe("bad_request");
  });

  it("returns 400 with trimmed issues for invalid bodies and never echoes values", async () => {
    app = await build();
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody({ intent: intent({ id: "nope", from: "0xSECRETVALUE" }) }) });
    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.issues.map((i: { path: string }) => i.path)).toEqual(expect.arrayContaining(["intent.id", "intent.from"]));
    expect(JSON.stringify(body)).not.toContain("0xSECRETVALUE");
  });

  it("validates audit query params and ids", async () => {
    app = await build();
    expect((await app.inject({ method: "GET", url: "/v1/audit?limit=0" })).statusCode).toBe(400);
    expect((await app.inject({ method: "GET", url: "/v1/audit?limit=5&bogus=1" })).statusCode).toBe(400);
    expect((await app.inject({ method: "GET", url: "/v1/audit?cursor=abc" })).statusCode).toBe(400);
    expect((await app.inject({ method: "GET", url: "/v1/audit/not-a-uuid" })).statusCode).toBe(404);
    expect((await app.inject({ method: "GET", url: "/v1/audit/../../etc/passwd" })).statusCode).toBe(404);
  });
});

describe("rate limiting", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("is on by default", async () => {
    app = await createServer({
      engine: new FakeEngine(),
      adapters: { evm: new FakeAdapter("evm") },
      policies: new Map([[testPolicy.id, testPolicy]]),
      audit: new InMemoryAuditStore(),
      logger: false,
      env: "test",
    });
    const res = await app.inject({ method: "GET", url: "/healthz" });
    expect(res.headers["x-ratelimit-limit"]).toBe("120");
  });

  it("limits per API key and returns 429 with retry-after", async () => {
    app = await build({ apiKeys: [{ id: "a", key: "ka" }, { id: "b", key: "kb" }], rateLimit: { max: 2, timeWindowMs: 60_000 } });
    const hit = (key: string) => app.inject({ method: "POST", url: "/v1/check", payload: requestBody(), headers: { "x-api-key": key } });
    expect((await hit("ka")).statusCode).toBe(200);
    expect((await hit("ka")).statusCode).toBe(200);
    const limited = await hit("ka");
    expect(limited.statusCode).toBe(429);
    expect(limited.json()).toMatchObject({ error: "rate_limited", retryAfter: expect.any(Number), requestId: expect.any(String) });
    expect(Number(limited.headers["retry-after"])).toBeGreaterThan(0);
    // Other key unaffected.
    expect((await hit("kb")).statusCode).toBe(200);
    // Unauthenticated requests share the per-IP bucket and are still limited.
    for (let i = 0; i < 2; i++) await app.inject({ method: "POST", url: "/v1/check", payload: requestBody(), headers: { "x-api-key": "wrong" } });
    expect((await app.inject({ method: "POST", url: "/v1/check", payload: requestBody(), headers: { "x-api-key": "wrong" } })).statusCode).toBe(429);
  });
});
