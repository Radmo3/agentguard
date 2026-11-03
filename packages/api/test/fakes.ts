import type { ChainAdapter, Decision, PolicySet, SimulationResult, TransactionIntent } from "@agentguard/core";
import type { EvaluateInput, PolicyEngineLike } from "../src/types.js";

export const testPolicy: PolicySet = { id: "test-policy", version: 3, rules: [] };

export function okSimulation(): SimulationResult {
  return {
    ok: true,
    deltas: [{ asset: "native", decimals: 18, amount: -1_000_000_000_000_000_000n, usdValue: -2500 }],
    approvals: [{ token: "0xtoken", spender: "0xspender", previous: 0n, next: (1n << 256n) - 1n, unlimited: true }],
    contractsTouched: ["0xabc"],
    newContracts: [],
    gasEstimate: 21_000n,
    warnings: [],
  };
}

export class FakeAdapter implements ChainAdapter {
  calls: TransactionIntent[] = [];
  constructor(
    public readonly chain: "evm" | "solana",
    private readonly impl: (i: TransactionIntent) => Promise<SimulationResult> = async () => okSimulation(),
  ) {}
  simulate(intent: TransactionIntent): Promise<SimulationResult> {
    this.calls.push(intent);
    return this.impl(intent);
  }
}

export class FakeEngine implements PolicyEngineLike {
  inputs: EvaluateInput[] = [];
  constructor(private readonly verdict: Decision["verdict"] | ((i: EvaluateInput) => Promise<Decision>) = "allow") {}
  async evaluate(input: EvaluateInput): Promise<Decision> {
    this.inputs.push(input);
    if (typeof this.verdict === "function") return this.verdict(input);
    return {
      intentId: input.intent.id,
      verdict: this.verdict,
      findings: this.verdict === "allow" ? [] : [{ ruleId: "r1", kind: "max_tx_usd", verdict: this.verdict, message: "too big" }],
      riskScore: this.verdict === "allow" ? 5 : 80,
      explanation: `fake ${this.verdict}`,
      simulation: input.simulation,
      policyId: input.policy?.id ?? "none",
      policyVersion: input.policy?.version ?? 0,
      evaluatedAt: new Date().toISOString(),
    };
  }
}

export function requestBody(overrides: Record<string, unknown> = {}) {
  return {
    intent: {
      id: "intent-1",
      chain: "evm",
      chainId: 1,
      from: "0xfrom",
      to: "0xto",
      value: "1000000000000000000",
      data: "0xdeadbeef",
      description: "swap",
    },
    context: { agentId: "agent-A", spentUsdInWindow: 10 },
    ...overrides,
  };
}
