import { createHmac, createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { TransactionIntent } from "@signhold/core";
import { SignholdClient, SignholdHttpError, SignholdNetworkError, sha256Hex, signRequest, signatureBaseString } from "../src/index.js";
import { decisionJson, jsonResponse, mockFetch } from "./helpers.js";

const intent: TransactionIntent = { id: "11111111-1111-4111-8111-111111111111", chain: "evm", from: "0x1111111111111111111111111111111111111111", value: 42n };
const ctx = { agentId: "agent" };

/** Reference implementation mirroring packages/api/src/auth.ts (node:crypto). */
function referenceSignature(secret: string, ts: string, nonce: string, method: string, path: string, body: string): string {
  const keyMaterial = createHash("sha256").update(secret, "utf8").digest();
  const bodyHash = createHash("sha256").update(body, "utf8").digest("hex");
  const base = ["v1", ts, nonce, method.toUpperCase(), path, bodyHash].join("\n");
  return "v1=" + createHmac("sha256", keyMaterial).update(base, "utf8").digest("hex");
}

describe("signRequest", () => {
  it("matches the server's reference HMAC construction", async () => {
    const input = { secret: "s3cr3t", method: "post", path: "/v1/check?x=1", body: '{"a":1}', timestamp: "1700000000000", nonce: "0123456789abcdef" };
    const sig = await signRequest(input);
    expect(sig).toEqual({ signature: referenceSignature("s3cr3t", input.timestamp, input.nonce, "POST", input.path, input.body), timestamp: input.timestamp, nonce: input.nonce });
    expect(await sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect((await signatureBaseString({ ...input })).split("\n")).toHaveLength(6);
  });

  it("generates a fresh nonce and timestamp by default", async () => {
    const a = await signRequest({ secret: "k", method: "GET", path: "/healthz", body: "" });
    const b = await signRequest({ secret: "k", method: "GET", path: "/healthz", body: "" });
    expect(a.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(a.nonce).not.toBe(b.nonce);
    expect(Number(a.timestamp)).toBeGreaterThan(1_600_000_000_000);
  });
});

describe("SignholdClient signing", () => {
  it("attaches signature headers that verify against the body actually sent", async () => {
    const { fetch, calls } = mockFetch(jsonResponse(200, { decision: decisionJson("allow"), auditId: "a" }));
    const client = new SignholdClient({ baseUrl: "http://gw", apiKey: "k", signRequests: true, fetch });
    await client.check(intent, ctx);
    const h = calls[0].init.headers as Record<string, string>;
    expect(h["x-signhold-signature"]).toMatch(/^v1=[0-9a-f]{64}$/);
    expect(h["x-signhold-signature"]).toBe(referenceSignature("k", h["x-signhold-timestamp"], h["x-signhold-nonce"], "POST", "/v1/check", calls[0].init.body as string));
  });

  it("uses a dedicated signing secret when given, and signs GETs with path+query", async () => {
    const { fetch, calls } = mockFetch(jsonResponse(200, { items: [] }));
    const client = new SignholdClient({ baseUrl: "http://gw", apiKey: "k", signRequests: "sign-secret", fetch });
    await client.listAudit({ agentId: "a", limit: 2 });
    const h = calls[0].init.headers as Record<string, string>;
    expect(h["x-signhold-signature"]).toBe(referenceSignature("sign-secret", h["x-signhold-timestamp"], h["x-signhold-nonce"], "GET", "/v1/audit?agentId=a&limit=2", ""));
  });

  it("re-signs each retry with a fresh nonce", async () => {
    const { fetch, calls } = mockFetch(jsonResponse(503, {}), jsonResponse(200, { decision: decisionJson("allow"), auditId: "a" }));
    const client = new SignholdClient({ baseUrl: "http://gw", apiKey: "k", signRequests: true, fetch, retryBackoffMs: 1 });
    await client.check(intent, ctx);
    const n = calls.map((c) => (c.init.headers as Record<string, string>)["x-signhold-nonce"]);
    expect(n).toHaveLength(2);
    expect(n[0]).not.toBe(n[1]);
  });

  it("does not sign when disabled and rejects signing without an api key", async () => {
    const { fetch, calls } = mockFetch(jsonResponse(200, { ok: true, chains: [], policies: [] }));
    await new SignholdClient({ baseUrl: "http://gw", apiKey: "k", fetch }).health();
    expect((calls[0].init.headers as Record<string, string>)["x-signhold-signature"]).toBeUndefined();
    expect(() => new SignholdClient({ baseUrl: "http://gw", signRequests: true, fetch })).toThrow(SignholdNetworkError);
    expect(() => new SignholdClient({ baseUrl: "ftp://gw", fetch })).toThrow(/http/);
  });

  it("maps 429 and 413 to typed error codes without retrying", async () => {
    const { fetch, calls } = mockFetch(jsonResponse(429, { error: "rate_limited", message: "slow down", retryAfter: 7 }));
    const client = new SignholdClient({ baseUrl: "http://gw", fetch, retryBackoffMs: 1 });
    const err = await client.check(intent, ctx).catch((e) => e);
    expect(err).toBeInstanceOf(SignholdHttpError);
    expect(err.code).toBe("rate_limited");
    expect(err.body.retryAfter).toBe(7);
    expect(calls).toHaveLength(1);
    const { fetch: f2 } = mockFetch(jsonResponse(413, { error: "payload_too_large" }));
    const e2 = await new SignholdClient({ baseUrl: "http://gw", fetch: f2 }).check(intent, ctx).catch((e) => e);
    expect(e2.code).toBe("payload_too_large");
  });
});
