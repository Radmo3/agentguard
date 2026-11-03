import { describe, expect, it } from "vitest";
import { HttpProvider, ReputationProviderError, jsonDepth, type FetchLike, type ResponseLike } from "../src/index.js";
import { SHADY } from "./helpers.js";

function response(body: string | object, over: Partial<ResponseLike> & { contentLength?: string } = {}): ResponseLike {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return {
    ok: over.ok ?? true,
    status: over.status ?? 200,
    headers: { get: (n) => (n === "content-length" ? over.contentLength ?? null : null) },
    body: new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new TextEncoder().encode(text));
        c.close();
      },
    }),
    text: async () => text,
  };
}

function fetchSeq(responses: Array<ResponseLike | Error | (() => Promise<ResponseLike>)>): FetchLike & { calls: number } {
  let i = 0;
  const f = (async () => {
    f.calls++;
    const r = responses[Math.min(i++, responses.length - 1)]!;
    if (r instanceof Error) throw r;
    if (typeof r === "function") return r();
    return r;
  }) as FetchLike & { calls: number };
  f.calls = 0;
  return f;
}

/** GoPlus-style mapper used throughout. */
function provider(fetch: FetchLike, over: Partial<ConstructorParameters<typeof HttpProvider>[0]> = {}) {
  return new HttpProvider({
    name: "intel",
    fetch,
    retryDelayMs: 0,
    buildRequest: (chain, address, chainId) => ({ url: `https://intel.example/v1/${chain}/${chainId ?? "x"}/${address}` }),
    mapResponse: (json) => {
      const r = json as { result?: { is_malicious?: boolean; risk?: number; labels?: string[]; extra?: unknown } };
      if (!r.result) return null;
      return {
        verdict: r.result.is_malicious ? "malicious" : (r.result.risk ?? 0) >= 50 ? "suspicious" : "unknown",
        score: r.result.risk,
        tags: r.result.labels,
        evidence: { extra: r.result.extra },
      };
    },
    ...over,
  });
}

describe("HttpProvider", () => {
  it("maps a valid upstream response", async () => {
    const p = provider(fetchSeq([response({ result: { is_malicious: true, risk: 99, labels: ["Phishing", "drainer"] } })]));
    const s = await p.lookup("evm", SHADY, { chainId: 1 });
    expect(s).toMatchObject({ source: "intel", verdict: "malicious", score: 99, tags: ["phishing", "drainer"] });
  });

  it("returns unknown/no_data when the mapper has no opinion", async () => {
    const p = provider(fetchSeq([response({})]));
    expect(await p.lookup("evm", SHADY)).toMatchObject({ verdict: "unknown", tags: ["no_data"], score: 50 });
  });

  it("drops tags longer than 64 chars and caps at 20 tags, regardless of mapper", async () => {
    const labels = [...Array.from({ length: 30 }, (_, i) => `tag${i}`), "x".repeat(65), "has space", "<script>"];
    const p = provider(fetchSeq([response({ result: { risk: 10, labels } })]));
    const s = await p.lookup("evm", SHADY);
    expect(s.tags).toHaveLength(20);
    expect(s.tags.every((t) => t.length <= 64 && /^[a-z0-9][a-z0-9_.:-]*$/.test(t))).toBe(true);
  });

  it("bounds evidence from upstream", async () => {
    const extra = { long: "y".repeat(2000), nested: { a: { b: { c: { d: { e: 1 } } } } }, arr: Array.from({ length: 100 }, (_, i) => i) };
    const p = provider(fetchSeq([response({ result: { risk: 10, extra } })]));
    const s = await p.lookup("evm", SHADY);
    const ev = s.evidence?.extra as Record<string, unknown>;
    expect((ev.long as string).length).toBeLessThan(600);
    expect((ev.arr as unknown[]).length).toBe(32);
    expect(JSON.stringify(ev.nested)).toContain("[truncated]");
  });

  it("clamps out-of-range scores", async () => {
    const p = provider(fetchSeq([response({ result: { risk: 5000 } })]));
    expect((await p.lookup("evm", SHADY)).score).toBe(100);
  });

  it("rejects oversized payloads by content-length", async () => {
    const p = provider(fetchSeq([response({ result: {} }, { contentLength: "999999999" })]), { maxResponseBytes: 1024 });
    await expect(p.lookup("evm", SHADY)).rejects.toMatchObject({ code: "payload_too_large" });
  });

  it("rejects oversized payloads while streaming (no content-length)", async () => {
    const big = JSON.stringify({ result: { labels: ["a".repeat(5000)] } });
    const p = provider(fetchSeq([response(big)]), { maxResponseBytes: 1024, retries: 0 });
    await expect(p.lookup("evm", SHADY)).rejects.toMatchObject({ code: "payload_too_large" });
  });

  it("rejects invalid JSON", async () => {
    const p = provider(fetchSeq([response("{oops")]), { retries: 0 });
    await expect(p.lookup("evm", SHADY)).rejects.toMatchObject({ code: "invalid_json" });
  });

  it("rejects non-object JSON by default and custom validateUpstream failures", async () => {
    const p = provider(fetchSeq([response("42")]), { retries: 0 });
    await expect(p.lookup("evm", SHADY)).rejects.toMatchObject({ code: "invalid_schema" });
    const p2 = provider(fetchSeq([response({ result: {} })]), { retries: 0, validateUpstream: () => false });
    await expect(p2.lookup("evm", SHADY)).rejects.toMatchObject({ code: "invalid_schema" });
  });

  it("rejects JSON nested deeper than maxJsonDepth", async () => {
    let deep: unknown = { x: 1 };
    for (let i = 0; i < 20; i++) deep = { d: deep };
    const p = provider(fetchSeq([response({ result: deep })]), { retries: 0, maxJsonDepth: 8 });
    await expect(p.lookup("evm", SHADY)).rejects.toMatchObject({ code: "invalid_schema" });
    expect(jsonDepth({ a: [{ b: 1 }] })).toBe(3);
    expect(jsonDepth(1)).toBe(0);
  });

  it("rejects a mapper that returns an invalid verdict", async () => {
    const p = provider(fetchSeq([response({ result: {} })]), { retries: 0, mapResponse: () => ({ verdict: "safe" as never }) });
    await expect(p.lookup("evm", SHADY)).rejects.toMatchObject({ code: "invalid_schema" });
  });

  it("does not retry 4xx but retries 5xx and network errors", async () => {
    const f4 = fetchSeq([response("", { ok: false, status: 403 })]);
    await expect(provider(f4, { retries: 2 }).lookup("evm", SHADY)).rejects.toMatchObject({ code: "http_status" });
    expect(f4.calls).toBe(1);

    const f5 = fetchSeq([response("", { ok: false, status: 503 }), new Error("ECONNRESET"), response({ result: { risk: 1 } })]);
    const s = await provider(f5, { retries: 2 }).lookup("evm", SHADY);
    expect(s.verdict).toBe("unknown");
    expect(f5.calls).toBe(3);
  });

  it("times out slow upstreams", async () => {
    const slow = () => new Promise<ResponseLike>(() => {});
    const p = provider(fetchSeq([slow]), { timeoutMs: 15, retries: 0 });
    await expect(p.lookup("evm", SHADY)).rejects.toMatchObject({ code: "timeout" });
  });

  it("refuses non-http URLs", async () => {
    const p = provider(fetchSeq([response({})]), { retries: 0, buildRequest: () => ({ url: "file:///etc/passwd" }) });
    await expect(p.lookup("evm", SHADY)).rejects.toBeInstanceOf(ReputationProviderError);
  });

  it("honours an outer AbortSignal", async () => {
    const ac = new AbortController();
    ac.abort();
    const p = provider(fetchSeq([response({})]), { retries: 1 });
    await expect(p.lookup("evm", SHADY, { signal: ac.signal })).rejects.toMatchObject({ code: "aborted" });
  });
});
