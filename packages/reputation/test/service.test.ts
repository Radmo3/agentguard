import { describe, expect, it } from "vitest";
import { LruCache, ReputationService, aggregate } from "../src/index.js";
import { OTHER, SHADY, failingProvider, hangingProvider, mockProvider, sig } from "./helpers.js";

function clock(start = 1_700_000_000_000) {
  let t = start;
  return { now: () => new Date(t), advance: (ms: number) => (t += ms) };
}

describe("aggregate()", () => {
  const base = { chain: "evm" as const, address: SHADY, failMode: "closed" as const, errorScoreFloor: 50, fetchedAt: "x", errors: [] };

  it("any malicious wins over trusted, and score is max", () => {
    const r = aggregate({ ...base, signals: [sig("a", "trusted", { score: 0, tags: ["allowlisted"] }), sig("b", "malicious", { score: 95, tags: ["phishing"] })] });
    expect(r.verdict).toBe("malicious");
    expect(r.score).toBe(95);
    expect(r.tags.sort()).toEqual(["allowlisted", "phishing"]);
    expect(r.signals).toHaveLength(2);
  });

  it("suspicious beats trusted beats unknown", () => {
    expect(aggregate({ ...base, signals: [sig("a", "trusted"), sig("b", "suspicious")] }).verdict).toBe("suspicious");
    expect(aggregate({ ...base, signals: [sig("a", "unknown", { score: 50 }), sig("b", "trusted")] }).verdict).toBe("trusted");
    expect(aggregate({ ...base, signals: [sig("a", "unknown")] }).verdict).toBe("unknown");
  });

  it("keeps per-source evidence", () => {
    const r = aggregate({ ...base, signals: [sig("a", "unknown", { evidence: { foo: 1 } }), sig("b", "trusted", { evidence: { bar: 2 } })] });
    expect(r.signals.find((s) => s.source === "a")?.evidence).toEqual({ foo: 1 });
    expect(r.signals.find((s) => s.source === "b")?.evidence).toEqual({ bar: 2 });
  });

  it("fail-closed: error downgrades trusted to unknown with floor score and provider_error tag", () => {
    const r = aggregate({ ...base, signals: [sig("a", "trusted", { score: 0 })], errors: [{ source: "b", kind: "error", message: "boom" }] });
    expect(r.verdict).toBe("unknown");
    expect(r.score).toBeGreaterThanOrEqual(50);
    expect(r.tags).toContain("provider_error");
    expect(r.tags).toContain("provider_failed");
  });

  it("fail-closed: error does not mask a surviving malicious signal", () => {
    const r = aggregate({ ...base, signals: [sig("a", "malicious", { score: 100 })], errors: [{ source: "b", kind: "timeout", message: "t" }] });
    expect(r.verdict).toBe("malicious");
    expect(r.score).toBe(100);
    expect(r.tags).toContain("provider_timeout");
  });

  it("fail-open: error keeps trusted verdict and score but records tag", () => {
    const r = aggregate({ ...base, failMode: "open", signals: [sig("a", "trusted", { score: 0 })], errors: [{ source: "b", kind: "error", message: "boom" }] });
    expect(r.verdict).toBe("trusted");
    expect(r.score).toBe(0);
    expect(r.tags).toContain("provider_error");
  });

  it("all providers failed => unknown with floor, even in fail-open", () => {
    const r = aggregate({ ...base, failMode: "open", signals: [], errors: [{ source: "b", kind: "error", message: "boom" }] });
    expect(r.verdict).toBe("unknown");
    expect(r.score).toBe(50);
    expect(r.tags).toContain("all_providers_failed");
  });

  it("respects a higher errorScoreFloor", () => {
    const r = aggregate({ ...base, errorScoreFloor: 80, signals: [], errors: [{ source: "b", kind: "error", message: "boom" }] });
    expect(r.score).toBe(80);
  });
});

describe("ReputationService", () => {
  it("defaults to fail-closed and lifts score on provider error", async () => {
    const svc = new ReputationService({ providers: [mockProvider("a", sig("a", "trusted", { score: 0 })), failingProvider("b")] });
    expect(svc.failMode).toBe("closed");
    const r = await svc.lookup("evm", SHADY);
    expect(r.verdict).toBe("unknown");
    expect(r.score).toBeGreaterThanOrEqual(50);
    expect(r.tags).toContain("provider_error");
    expect(r.errors).toEqual([{ source: "b", kind: "error", message: "boom" }]);
  });

  it("times out hanging providers (fail-closed)", async () => {
    const svc = new ReputationService({ providers: [hangingProvider("slow"), mockProvider("fast", sig("fast", "trusted"))], providerTimeoutMs: 20 });
    const r = await svc.lookup("evm", SHADY);
    expect(r.verdict).toBe("unknown");
    expect(r.errors[0]).toMatchObject({ source: "slow", kind: "timeout" });
    expect(r.tags).toContain("provider_timeout");
    expect(r.score).toBeGreaterThanOrEqual(50);
  });

  it("passes an AbortSignal that fires on timeout", async () => {
    let aborted = false;
    const p = {
      name: "p",
      lookup: (_c: "evm" | "solana", _a: string, opts?: { signal?: AbortSignal }) =>
        new Promise<never>((_, reject) => opts?.signal?.addEventListener("abort", () => { aborted = true; reject(new Error("aborted")); })),
    };
    const svc = new ReputationService({ providers: [p], providerTimeoutMs: 10 });
    await svc.lookup("evm", SHADY);
    expect(aborted).toBe(true);
  });

  it("does not throw when a provider returns garbage", async () => {
    const p = { name: "bad", lookup: async () => ({ verdict: "nonsense", score: "9000", tags: "x" }) as never };
    const svc = new ReputationService({ providers: [p] });
    const r = await svc.lookup("evm", SHADY);
    expect(r.verdict).toBe("unknown");
    expect(r.signals[0]?.tags).toEqual([]);
    expect(r.signals[0]?.score).toBe(0);
  });

  it("caches conclusive results until TTL, case-normalized on EVM", async () => {
    const c = clock();
    const p = mockProvider("a", sig("a", "malicious"));
    const svc = new ReputationService({ providers: [p], now: c.now, cache: { ttlMs: 1000 } });
    const r1 = await svc.lookup("evm", SHADY);
    const r2 = await svc.lookup("evm", SHADY.toUpperCase().replace("0X", "0x"));
    expect(r1.cached).toBe(false);
    expect(r2.cached).toBe(true);
    expect(p.calls).toHaveLength(1);
    c.advance(1001);
    await svc.lookup("evm", SHADY);
    expect(p.calls).toHaveLength(2);
  });

  it("negative-caches unknown results with the shorter TTL", async () => {
    const c = clock();
    const p = mockProvider("a", sig("a", "unknown"));
    const svc = new ReputationService({ providers: [p], now: c.now, cache: { ttlMs: 10_000, negativeTtlMs: 100 } });
    await svc.lookup("evm", SHADY);
    await svc.lookup("evm", SHADY);
    expect(p.calls).toHaveLength(1);
    c.advance(101);
    await svc.lookup("evm", SHADY);
    expect(p.calls).toHaveLength(2);
  });

  it("caches error results only for errorTtlMs (0 disables)", async () => {
    const c = clock();
    const p = failingProvider("a");
    const svc = new ReputationService({ providers: [p], now: c.now, cache: { errorTtlMs: 0 } });
    await svc.lookup("evm", SHADY);
    await svc.lookup("evm", SHADY);
    expect(p.calls).toHaveLength(2);
  });

  it("scopes cache by chainId", async () => {
    const p = mockProvider("a", sig("a", "trusted"));
    const svc = new ReputationService({ providers: [p] });
    await svc.lookup("evm", SHADY, { chainId: 1 });
    await svc.lookup("evm", SHADY, { chainId: 8453 });
    expect(p.calls).toHaveLength(2);
  });

  it("dedupes concurrent in-flight lookups", async () => {
    const p = mockProvider("a", sig("a", "trusted"));
    const svc = new ReputationService({ providers: [p] });
    await Promise.all([svc.lookup("evm", SHADY), svc.lookup("evm", SHADY), svc.lookup("evm", SHADY.toLowerCase())]);
    expect(p.calls).toHaveLength(1);
  });

  it("bounds the cache (LRU eviction)", async () => {
    const p = mockProvider("a", sig("a", "trusted"));
    const svc = new ReputationService({ providers: [p], cache: { maxEntries: 2 } });
    await svc.lookup("evm", "0x01");
    await svc.lookup("evm", "0x02");
    await svc.lookup("evm", "0x01"); // touch -> 0x02 is now LRU
    await svc.lookup("evm", "0x03"); // evicts 0x02
    expect(svc.cacheSize).toBe(2);
    expect(svc.peek("evm", "0x01")).toBeDefined();
    expect(svc.peek("evm", "0x02")).toBeUndefined();
    expect(svc.peek("evm", "0x03")).toBeDefined();
  });

  it("peek() is sync and returns undefined for misses", async () => {
    const svc = new ReputationService({ providers: [mockProvider("a", sig("a", "trusted"))] });
    expect(svc.peek("evm", OTHER)).toBeUndefined();
    await svc.lookup("evm", OTHER);
    expect(svc.peek("evm", OTHER)?.verdict).toBe("trusted");
  });

  it("prefetch warms intent.to, contractsTouched and approval spenders", async () => {
    const p = mockProvider("a", sig("a", "trusted"));
    const svc = new ReputationService({ providers: [p] });
    const { intent, simulation } = await import("./helpers.js");
    await svc.prefetch(
      intent({ to: SHADY }),
      simulation({ contractsTouched: [OTHER, SHADY], approvals: [{ token: "0xt", spender: "0xSpender", previous: 0n, next: 1n, unlimited: false }] }),
    );
    expect(p.calls.map((c) => c.address).sort()).toEqual([OTHER, SHADY, "0xspender"].map((a) => a.toLowerCase()).sort());
    expect(svc.peek("evm", "0xSPENDER", 1)).toBeDefined();
  });

  it("rejects duplicate provider names", () => {
    expect(() => new ReputationService({ providers: [mockProvider("a", sig("a", "trusted")), mockProvider("a", sig("a", "trusted"))] })).toThrow(/duplicate/);
  });

  it("no providers => unknown with no_providers tag", async () => {
    const svc = new ReputationService({ providers: [] });
    const r = await svc.lookup("solana", "11111111111111111111111111111111");
    expect(r.verdict).toBe("unknown");
    expect(r.tags).toContain("no_providers");
    expect(r.score).toBe(50);
  });
});

describe("LruCache", () => {
  it("evicts least-recently-used and honors TTL", () => {
    let t = 0;
    const c = new LruCache<number>(2, () => t);
    c.set("a", 1, 100);
    c.set("b", 2, 100);
    c.get("a");
    c.set("c", 3, 100);
    expect(c.keys()).toEqual(["a", "c"]);
    t = 100;
    expect(c.get("a")).toBeUndefined();
    expect(c.size).toBe(1);
  });

  it("rejects non-positive sizes", () => {
    expect(() => new LruCache(0)).toThrow();
  });
});
