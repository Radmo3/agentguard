import { describe, expect, it } from "vitest";
import { PolicyError } from "@signhold/core";
import {
  PolicyEngine,
  aggregateVerdict,
  computeRiskScore,
  conservativeDefaultPolicy,
  loadPolicy,
  safeLoadPolicy,
} from "../src/index.js";
import { ROUTER, SHADY, USDC, context, intent, policy, rule, simulation } from "./fixtures.js";

const engine = new PolicyEngine({ now: () => new Date("2026-01-01T00:00:00Z") });

describe("aggregation", () => {
  it("block beats escalate beats allow", async () => {
    const d = await engine.evaluate({
      intent: intent(),
      simulation: simulation({ newContracts: [SHADY] }),
      context: context(),
      policy: policy([
        rule("no_new_contracts", undefined, { id: "a", onViolation: "escalate" }),
        rule("max_tx_usd", { maxUsd: 1 }, { id: "b", onViolation: "block" }),
        rule("require_simulation_ok", undefined, { id: "c" }),
      ]),
    });
    expect(d.verdict).toBe("block");
    expect(d.findings.map((f) => f.ruleId)).toEqual(["a", "b"]);
    expect(d.explanation).toContain("blocked");
    expect(d.explanation).toContain("Blocking rule: b (max_tx_usd)");
    expect(d.explanation).toContain("Escalating rule: a (no_new_contracts)");
    expect(d.evaluatedAt).toBe("2026-01-01T00:00:00.000Z");
    expect(d.policyId).toBe("test-policy");
    expect(d.policyVersion).toBe(1);
    expect(d.intentId).toBe("intent-1");
    expect(d.simulation).toBeDefined();
  });

  it("escalates when only escalate findings", () => {
    expect(aggregateVerdict([{ ruleId: "x", kind: "custom", verdict: "escalate", message: "" }])).toBe("escalate");
    expect(aggregateVerdict([])).toBe("allow");
  });

  it("allows with empty policy and explains no rules fired", async () => {
    const d = await engine.evaluate({ intent: intent(), simulation: simulation(), context: context(), policy: policy([]) });
    expect(d.verdict).toBe("allow");
    expect(d.riskScore).toBe(0);
    expect(d.explanation).toContain("No policy rules fired");
  });
});

describe("riskScore", () => {
  it("is 0 for clean sim with no findings", () => {
    expect(computeRiskScore([], simulation())).toBe(0);
  });
  it("follows the documented formula and clamps to 100", () => {
    const f = (v: "block" | "escalate") => ({ ruleId: "r", kind: "custom" as const, verdict: v, message: "" });
    expect(computeRiskScore([f("escalate")], simulation())).toBe(20);
    expect(computeRiskScore([f("block")], simulation())).toBe(40);
    expect(computeRiskScore([], simulation({ ok: false }))).toBe(25);
    expect(computeRiskScore([], simulation({ warnings: ["a", "b", "c", "d"] }))).toBe(30);
    expect(
      computeRiskScore([], simulation({ approvals: [{ token: USDC, spender: ROUTER, previous: 0n, next: 1n, unlimited: true }] })),
    ).toBe(15);
    expect(computeRiskScore([], simulation({ newContracts: [SHADY, SHADY, SHADY] }))).toBe(20);
    expect(computeRiskScore([f("block"), f("block"), f("block")], simulation({ ok: false }))).toBe(100);
  });
});

describe("never throws", () => {
  it("returns engine_error escalate on garbage input", async () => {
    for (const bad of [undefined, null, {}, { intent: null }, { intent: intent(), simulation: null }, { intent: intent(), simulation: simulation(), policy: { id: "p", version: 1, rules: "x" } }]) {
      const d = await engine.evaluate(bad as any);
      expect(d.verdict).toBe("escalate");
      expect(d.findings[0].ruleId).toBe("engine_error");
      expect(d.findings[0].kind).toBe("custom");
      expect(d.riskScore).toBeGreaterThanOrEqual(50);
      expect(typeof d.explanation).toBe("string");
      expect(typeof d.evaluatedAt).toBe("string");
    }
  });

  it("isolates a bad rule and still evaluates the others", async () => {
    const d = await engine.evaluate({
      intent: intent(),
      simulation: simulation(),
      context: context(),
      policy: policy([
        rule("max_tx_usd", { maxUsd: "not a number" }, { id: "broken" }),
        { id: "weird", kind: "not_a_kind" as any },
        rule("max_tx_usd", { maxUsd: 1 }, { id: "fires" }),
      ]),
    });
    expect(d.verdict).toBe("block");
    const ids = d.findings.map((f) => f.ruleId);
    expect(ids).toEqual(["engine_error", "engine_error", "fires"]);
    expect(d.findings[0].evidence?.ruleId).toBe("broken");
  });

  it("survives a throwing clock", async () => {
    const e = new PolicyEngine({ now: () => { throw new Error("no clock"); } });
    const d = await e.evaluate({ intent: intent(), simulation: simulation(), context: context(), policy: policy([]) });
    expect(d.verdict).toBe("allow");
    expect(d.evaluatedAt).toMatch(/^\d{4}-/);
  });
});

describe("conservativeDefaultPolicy + loadPolicy", () => {
  it("default policy validates and allows a benign swap", async () => {
    expect(() => loadPolicy(conservativeDefaultPolicy)).not.toThrow();
    const d = await engine.evaluate({ intent: intent(), simulation: simulation(), context: context(), policy: conservativeDefaultPolicy });
    expect(d.verdict).toBe("allow");
  });
  it("default policy blocks an unlimited approval to a new contract from a reverted sim", async () => {
    const d = await engine.evaluate({
      intent: intent({ to: SHADY, value: 10n ** 18n }),
      simulation: simulation({
        ok: false,
        newContracts: [SHADY],
        approvals: [{ token: USDC, spender: SHADY, previous: 0n, next: 1n, unlimited: true }],
      }),
      context: context(),
      policy: conservativeDefaultPolicy,
    });
    expect(d.verdict).toBe("block");
    expect(d.findings.map((f) => f.ruleId)).toEqual(
      expect.arrayContaining(["sim-must-succeed", "no-unlimited-approvals", "max-native-0.05", "new-contracts"]),
    );
  });
  it("loadPolicy accepts JSON strings and rejects bad params / duplicate ids / unknown kinds", () => {
    const p = loadPolicy(JSON.stringify({ id: "p", version: 2, rules: [{ id: "a", kind: "max_tx_usd", params: { maxUsd: 5 } }] }));
    expect(p.version).toBe(2);
    expect(() => loadPolicy({ id: "p", version: 1, rules: [{ id: "a", kind: "max_tx_usd" }] })).toThrow(PolicyError);
    expect(() => loadPolicy({ id: "p", version: 1, rules: [{ id: "a", kind: "custom", params: {} }] })).toThrow(/params.fn/);
    expect(() => loadPolicy({ id: "p", version: 1, rules: [{ id: "a", kind: "nope" }] })).toThrow(PolicyError);
    expect(() =>
      loadPolicy({ id: "p", version: 1, rules: [{ id: "a", kind: "denylist" }, { id: "a", kind: "denylist" }] }),
    ).toThrow(/duplicate/);
    expect(() => loadPolicy({ id: "p", version: 1, rules: [{ id: "a", kind: "max_native_value", params: { maxWei: "1.5" } }] })).toThrow(PolicyError);
    expect(() => loadPolicy("{not json")).toThrow(/valid JSON/);
    expect(safeLoadPolicy("{not json").ok).toBe(false);
  });
});
