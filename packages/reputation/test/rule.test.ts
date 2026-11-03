import type { PolicyRule } from "@agentguard/core";
import { describe, expect, it } from "vitest";
import { ReputationService, StaticListProvider, createReputationRule, type ReputationProvider } from "../src/index.js";
import { OTHER, ROUTER, SHADY, failingProvider, intent, mockProvider, sig, simulation } from "./helpers.js";

const rule: PolicyRule = { id: "rep", kind: "custom", params: { fn: "reputation" } };

function service(extra: ReputationProvider[] = []) {
  return new ReputationService({
    providers: [
      new StaticListProvider({ deny: [{ chain: "evm", address: SHADY, tags: ["drainer"] }] }),
      ...extra,
    ],
  });
}

describe("createReputationRule", () => {
  it("blocks on malicious", async () => {
    const svc = service();
    const fn = createReputationRule(svc);
    const i = intent({ to: SHADY });
    const s = simulation();
    await svc.prefetch(i, s);
    const f = fn({ intent: i, simulation: s, rule });
    expect(f?.verdict).toBe("block");
    expect(f?.ruleId).toBe("rep");
    expect(f?.kind).toBe("custom");
    expect(f?.message).toMatch(/malicious/);
    expect((f?.evidence as { blocked: unknown[] }).blocked).toHaveLength(1);
  });

  it("allows (null) for trusted seed contracts", async () => {
    const svc = service();
    const fn = createReputationRule(svc);
    const i = intent({ to: ROUTER });
    const s = simulation({ contractsTouched: [ROUTER] });
    await svc.prefetch(i, s);
    expect(fn({ intent: i, simulation: s, rule })).toBeNull();
  });

  it("escalates on unknown with score >= minScoreToEscalate (default 60) only", async () => {
    // Static alone gives unknown/50 => below threshold => no finding.
    const svc = service();
    const fn = createReputationRule(svc);
    const i = intent({ to: OTHER });
    const s = simulation();
    await svc.prefetch(i, s);
    expect(fn({ intent: i, simulation: s, rule })).toBeNull();

    // Lower threshold => escalate.
    const fn2 = createReputationRule(svc, { minScoreToEscalate: 50 });
    const f = fn2({ intent: i, simulation: s, rule });
    expect(f?.verdict).toBe("escalate");
    expect(f?.message).toMatch(/elevated or unknown risk/);
  });

  it("escalates on provider failure even when the lifted score (50) is below minScoreToEscalate (60)", async () => {
    const svc = service([failingProvider("intel")]);
    const fn = createReputationRule(svc);
    const i = intent({ to: ROUTER });
    const s = simulation();
    await svc.prefetch(i, s);
    const f = fn({ intent: i, simulation: s, rule });
    expect(f?.verdict).toBe("escalate");
    expect(f?.message).toMatch(/failing closed/);
    expect((f?.evidence as { providerError?: boolean }).providerError).toBe(true);
    // Opt-out restores the pure score threshold.
    const lenient = createReputationRule(svc, { escalateOnProviderError: false });
    expect(lenient({ intent: i, simulation: s, rule })).toBeNull();
  });

  it("escalates on unknown when a provider failed (fail-closed lifts score to >= 50) with threshold 50", async () => {
    const svc = service([failingProvider("intel")]);
    const fn = createReputationRule(svc, { minScoreToEscalate: 50 });
    const i = intent({ to: ROUTER });
    const s = simulation();
    await svc.prefetch(i, s);
    const f = fn({ intent: i, simulation: s, rule });
    expect(f?.verdict).toBe("escalate");
    const ev = f?.evidence as { escalated: Array<{ tags: string[] }> };
    expect(ev.escalated[0]?.tags).toContain("provider_error");
  });

  it("escalates on suspicious signals from any provider", async () => {
    const svc = service([mockProvider("heur", sig("heur", "suspicious", { score: 70, tags: ["age_lt_1d"] }))]);
    const fn = createReputationRule(svc);
    const i = intent({ to: OTHER });
    const s = simulation();
    await svc.prefetch(i, s);
    const f = fn({ intent: i, simulation: s, rule });
    expect(f?.verdict).toBe("escalate");
    expect(f?.message).toContain("age_lt_1d");
  });

  it("checks contractsTouched and approval spenders, not just intent.to", async () => {
    const svc = service();
    const fn = createReputationRule(svc);
    const i = intent({ to: ROUTER });
    const s = simulation({ contractsTouched: [ROUTER, SHADY] });
    await svc.prefetch(i, s);
    expect(fn({ intent: i, simulation: s, rule })?.verdict).toBe("block");

    const s2 = simulation({ approvals: [{ token: ROUTER, spender: SHADY, previous: 0n, next: 1n, unlimited: false }] });
    await svc.prefetch(i, s2);
    expect(fn({ intent: i, simulation: s2, rule })?.verdict).toBe("block");
  });

  it("escalates with not_prefetched when the cache was not warmed (fail-closed)", () => {
    const svc = service();
    const fn = createReputationRule(svc);
    const f = fn({ intent: intent({ to: OTHER }), simulation: simulation(), rule });
    expect(f?.verdict).toBe("escalate");
    expect(f?.message).toMatch(/no reputation data/);
    expect((f?.evidence as { tags: string[] }).tags).toEqual(["not_prefetched"]);
    expect((f?.evidence as { missing: string[] }).missing).toEqual([OTHER.toLowerCase()]);
  });

  it("onCacheMiss: ignore returns null for misses", () => {
    const fn = createReputationRule(service(), { onCacheMiss: "ignore" });
    expect(fn({ intent: intent({ to: OTHER }), simulation: simulation(), rule })).toBeNull();
  });

  it("block wins over escalate in a mixed set", async () => {
    const svc = service([mockProvider("heur", (_c, a) => sig("heur", a === OTHER.toLowerCase() ? "suspicious" : "unknown", { score: a === OTHER.toLowerCase() ? 75 : 0 }))]);
    const fn = createReputationRule(svc);
    const i = intent({ to: SHADY });
    const s = simulation({ contractsTouched: [OTHER] });
    await svc.prefetch(i, s);
    const f = fn({ intent: i, simulation: s, rule });
    expect(f?.verdict).toBe("block");
    const ev = f?.evidence as { blocked: unknown[]; escalated: unknown[]; checked: number };
    expect(ev.blocked).toHaveLength(1);
    expect(ev.escalated).toHaveLength(1);
    expect(ev.checked).toBe(2);
  });

  it("custom blockOn/escalateOn sets", async () => {
    const svc = service([mockProvider("heur", sig("heur", "suspicious", { score: 90 }))]);
    const fn = createReputationRule(svc, { blockOn: ["malicious", "suspicious"], escalateOn: [] });
    const i = intent({ to: OTHER });
    const s = simulation();
    await svc.prefetch(i, s);
    expect(fn({ intent: i, simulation: s, rule })?.verdict).toBe("block");
  });
});
