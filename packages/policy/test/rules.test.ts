import { describe, expect, it } from "vitest";
import { UINT256_MAX } from "@signhold/core";
import { PolicyEngine } from "../src/index.js";
import { AGENT, ROUTER, SHADY, USDC, context, intent, policy, rule, simulation } from "./fixtures.js";

const engine = new PolicyEngine({
  customRules: {
    alwaysFire: ({ rule }) => ({ ruleId: rule.id, kind: "custom", verdict: "escalate", message: "custom fired" }),
    neverFire: () => null,
    throws: () => {
      throw new Error("boom");
    },
  },
});

async function run(r: Parameters<typeof policy>[0][number], over: { intent?: any; simulation?: any; context?: any } = {}) {
  return engine.evaluate({
    intent: intent(over.intent),
    simulation: simulation(over.simulation),
    context: context(over.context),
    policy: policy([r]),
  });
}

describe("max_tx_usd", () => {
  it("allows when outflow is under the limit", async () => {
    const d = await run(rule("max_tx_usd", { maxUsd: 150 }));
    expect(d.verdict).toBe("allow");
    expect(d.findings).toHaveLength(0);
  });
  it("blocks when summed negative USD deltas exceed the limit", async () => {
    const d = await run(rule("max_tx_usd", { maxUsd: 50 }));
    expect(d.verdict).toBe("block");
    expect(d.findings[0].evidence?.spentUsd).toBe(100);
  });
  it("sums multiple outflows and ignores inflows", async () => {
    const d = await run(rule("max_tx_usd", { maxUsd: 120 }), {
      simulation: {
        deltas: [
          { asset: "a", decimals: 18, amount: -1n, usdValue: -70 },
          { asset: "b", decimals: 18, amount: -1n, usdValue: -60 },
          { asset: "c", decimals: 18, amount: 1n, usdValue: 500 },
        ],
      },
    });
    expect(d.verdict).toBe("block");
    expect(d.findings[0].evidence?.spentUsd).toBe(130);
  });
});

describe("max_window_usd", () => {
  it("adds this tx to spentUsdInWindow", async () => {
    const ok = await run(rule("max_window_usd", { maxUsd: 500 }), { context: { spentUsdInWindow: 350 } });
    expect(ok.verdict).toBe("allow");
    const bad = await run(rule("max_window_usd", { maxUsd: 500 }), { context: { spentUsdInWindow: 450 } });
    expect(bad.verdict).toBe("block");
    expect(bad.findings[0].evidence?.totalUsd).toBe(550);
  });
  it("respects onViolation escalate", async () => {
    const d = await run(rule("max_window_usd", { maxUsd: 10 }, { onViolation: "escalate" }));
    expect(d.verdict).toBe("escalate");
  });
});

describe("allowlist_only", () => {
  it("allows when to and all contractsTouched are allowlisted, case-insensitively on EVM", async () => {
    const d = await run(rule("allowlist_only"), {
      context: { allowlist: [ROUTER.toUpperCase(), USDC.toLowerCase()] },
    });
    expect(d.verdict).toBe("allow");
  });
  it("blocks when a touched contract is missing from the allowlist", async () => {
    const d = await run(rule("allowlist_only"), { context: { allowlist: [ROUTER] } });
    expect(d.verdict).toBe("block");
    expect(d.findings[0].evidence?.offenders).toEqual([USDC]);
  });
  it("blocks when intent.to is not allowlisted", async () => {
    const d = await run(rule("allowlist_only"), {
      intent: { to: SHADY },
      context: { allowlist: [ROUTER, USDC] },
    });
    expect(d.verdict).toBe("block");
  });
  it("merges rule params.addresses with context allowlist", async () => {
    const d = await run(rule("allowlist_only", { addresses: [USDC] }), { context: { allowlist: [ROUTER] } });
    expect(d.verdict).toBe("allow");
  });
  it("is case-sensitive on Solana", async () => {
    const prog = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const d = await run(rule("allowlist_only"), {
      intent: { chain: "solana", to: prog },
      simulation: { contractsTouched: [prog] },
      context: { allowlist: [prog.toLowerCase()] },
    });
    expect(d.verdict).toBe("block");
  });
});

describe("denylist", () => {
  it("blocks on denylisted to / contract / approval spender", async () => {
    const d1 = await run(rule("denylist"), { intent: { to: SHADY }, context: { denylist: [SHADY.toLowerCase()] } });
    expect(d1.verdict).toBe("block");
    const d2 = await run(rule("denylist"), {
      simulation: { approvals: [{ token: USDC, spender: SHADY, previous: 0n, next: 1n, unlimited: false }] },
      context: { denylist: [SHADY] },
    });
    expect(d2.verdict).toBe("block");
  });
  it("allows when nothing matches", async () => {
    const d = await run(rule("denylist"), { context: { denylist: [SHADY] } });
    expect(d.verdict).toBe("allow");
  });
});

describe("no_unlimited_approvals", () => {
  it("blocks unlimited approvals (flag or max value)", async () => {
    const d = await run(rule("no_unlimited_approvals"), {
      simulation: { approvals: [{ token: USDC, spender: ROUTER, previous: 0n, next: UINT256_MAX, unlimited: false }] },
    });
    expect(d.verdict).toBe("block");
  });
  it("allows bounded approvals", async () => {
    const d = await run(rule("no_unlimited_approvals"), {
      simulation: { approvals: [{ token: USDC, spender: ROUTER, previous: 0n, next: 1000n, unlimited: false }] },
    });
    expect(d.verdict).toBe("allow");
  });
});

describe("max_slippage_bps", () => {
  it("fires when actual positive delta USD is below expectedOutUsd by more than maxBps", async () => {
    const d = await run(rule("max_slippage_bps", { maxBps: 50, expectedOutUsd: 100 })); // actual 99 => 100bps
    expect(d.verdict).toBe("block");
    expect(d.findings[0].evidence?.slippageBps).toBeCloseTo(100);
  });
  it("allows within tolerance and when no expectation given", async () => {
    expect((await run(rule("max_slippage_bps", { maxBps: 200, expectedOutUsd: 100 }))).verdict).toBe("allow");
    expect((await run(rule("max_slippage_bps", { maxBps: 1 }))).verdict).toBe("allow");
  });
  it("falls back to intent.metadata.expectedOutUsd", async () => {
    const d = await run(rule("max_slippage_bps", { maxBps: 10 }), { intent: { metadata: { expectedOutUsd: 100 } } });
    expect(d.verdict).toBe("block");
  });
});

describe("no_new_contracts", () => {
  it("fires when simulation lists new contracts", async () => {
    const d = await run(rule("no_new_contracts", undefined, { onViolation: "escalate" }), {
      simulation: { newContracts: [SHADY] },
    });
    expect(d.verdict).toBe("escalate");
  });
  it("allows otherwise", async () => {
    expect((await run(rule("no_new_contracts"))).verdict).toBe("allow");
  });
});

describe("require_simulation_ok", () => {
  it("blocks when simulation reverted", async () => {
    const d = await run(rule("require_simulation_ok"), { simulation: { ok: false, revertReason: "INSUFFICIENT_OUTPUT" } });
    expect(d.verdict).toBe("block");
    expect(d.findings[0].message).toContain("INSUFFICIENT_OUTPUT");
  });
  it("allows when ok", async () => {
    expect((await run(rule("require_simulation_ok"))).verdict).toBe("allow");
  });
});

describe("max_native_value", () => {
  it("compares intent.value against maxWei bigint-as-string", async () => {
    const limit = "1000000000000000000"; // 1 ETH
    expect((await run(rule("max_native_value", { maxWei: limit }), { intent: { value: 10n ** 18n } })).verdict).toBe("allow");
    const d = await run(rule("max_native_value", { maxWei: limit }), { intent: { value: 10n ** 18n + 1n } });
    expect(d.verdict).toBe("block");
    expect(d.findings[0].evidence?.value).toBe((10n ** 18n + 1n).toString());
  });
  it("treats missing value as zero", async () => {
    expect((await run(rule("max_native_value", { maxWei: "0" }), { intent: { value: undefined } })).verdict).toBe("allow");
  });
});

describe("custom", () => {
  it("looks up params.fn in the registry", async () => {
    const fired = await run(rule("custom", { fn: "alwaysFire" }));
    expect(fired.verdict).toBe("escalate");
    expect(fired.findings[0].message).toBe("custom fired");
    const quiet = await run(rule("custom", { fn: "neverFire" }));
    expect(quiet.verdict).toBe("allow");
  });
  it("escalates with engine_error when fn is unknown or throws", async () => {
    for (const r of [rule("custom", { fn: "nope" }), rule("custom", { fn: "throws" }), rule("custom")]) {
      const d = await run(r);
      expect(d.verdict).toBe("escalate");
      expect(d.findings[0].ruleId).toBe("engine_error");
    }
  });
  it("supports registerCustomRule", async () => {
    const e = new PolicyEngine().registerCustomRule("later", ({ rule }) => ({
      ruleId: rule.id,
      kind: "custom",
      verdict: "block",
      message: "late",
    }));
    const d = await e.evaluate({ intent: intent(), simulation: simulation(), context: context(), policy: policy([rule("custom", { fn: "later" })]) });
    expect(d.verdict).toBe("block");
  });
});
