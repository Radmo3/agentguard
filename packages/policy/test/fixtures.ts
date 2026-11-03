import type { AgentContext, PolicyRule, PolicySet, SimulationResult, TransactionIntent } from "@agentguard/core";

export const AGENT = "0xAgent000000000000000000000000000000000001";
export const ROUTER = "0xRouter00000000000000000000000000000000002";
export const USDC = "0xUsdc000000000000000000000000000000000003";
export const SHADY = "0xShady000000000000000000000000000000000004";

export function intent(over: Partial<TransactionIntent> = {}): TransactionIntent {
  return {
    id: "intent-1",
    chain: "evm",
    chainId: 1,
    from: AGENT,
    to: ROUTER,
    value: 0n,
    data: "0xdeadbeef",
    description: "swap 100 USDC for ETH",
    ...over,
  };
}

export function simulation(over: Partial<SimulationResult> = {}): SimulationResult {
  return {
    ok: true,
    deltas: [
      { asset: USDC, symbol: "USDC", decimals: 6, amount: -100_000_000n, usdValue: -100 },
      { asset: "native", symbol: "ETH", decimals: 18, amount: 40_000_000_000_000_000n, usdValue: 99 },
    ],
    approvals: [],
    contractsTouched: [ROUTER, USDC],
    newContracts: [],
    warnings: [],
    ...over,
  };
}

export function context(over: Partial<AgentContext> = {}): AgentContext {
  return { agentId: "agent-1", spentUsdInWindow: 0, windowSeconds: 3600, ...over };
}

export function policy(rules: PolicyRule[], over: Partial<PolicySet> = {}): PolicySet {
  return { id: "test-policy", version: 1, rules, ...over };
}

export function rule(kind: PolicyRule["kind"], params?: Record<string, unknown>, over: Partial<PolicyRule> = {}): PolicyRule {
  return { id: `r-${kind}`, kind, params, ...over };
}
