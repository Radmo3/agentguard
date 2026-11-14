import type { Chain, SimulationResult, TransactionIntent } from "@signhold/core";
import type { ReputationProvider, ReputationSignal, ReputationVerdict } from "../src/index.js";

export const AGENT = "0x1111111111111111111111111111111111111111";
export const ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"; // Uniswap V2 router (seed)
export const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
export const SHADY = "0xdead00000000000000000000000000000000beef";
export const OTHER = "0xcafe00000000000000000000000000000000cafe";

export function sig(source: string, verdict: ReputationVerdict, over: Partial<ReputationSignal> = {}): ReputationSignal {
  return { source, verdict, score: over.score ?? defaultScore(verdict), tags: over.tags ?? [], evidence: over.evidence, fetchedAt: "2026-01-01T00:00:00.000Z" };
}

function defaultScore(v: ReputationVerdict) {
  return v === "malicious" ? 100 : v === "suspicious" ? 70 : v === "unknown" ? 50 : 0;
}

export interface MockProvider extends ReputationProvider {
  calls: Array<{ chain: Chain; address: string }>;
}

/** Provider that returns a fixed signal (or per-address map) and records calls. */
export function mockProvider(
  name: string,
  respond: ReputationSignal | ((chain: Chain, address: string) => ReputationSignal | Promise<ReputationSignal>),
): MockProvider {
  const calls: MockProvider["calls"] = [];
  return {
    name,
    calls,
    async lookup(chain, address) {
      calls.push({ chain, address });
      return typeof respond === "function" ? respond(chain, address) : { ...respond, source: name };
    },
  };
}

export function failingProvider(name: string, err: Error = new Error("boom")): MockProvider {
  const calls: MockProvider["calls"] = [];
  return {
    name,
    calls,
    async lookup(chain, address) {
      calls.push({ chain, address });
      throw err;
    },
  };
}

export function hangingProvider(name: string): MockProvider {
  const calls: MockProvider["calls"] = [];
  return {
    name,
    calls,
    lookup(chain, address) {
      calls.push({ chain, address });
      return new Promise(() => {});
    },
  };
}

export function intent(over: Partial<TransactionIntent> = {}): TransactionIntent {
  return { id: "intent-1", chain: "evm", chainId: 1, from: AGENT, to: ROUTER, value: 0n, data: "0x", ...over };
}

export function simulation(over: Partial<SimulationResult> = {}): SimulationResult {
  return { ok: true, deltas: [], approvals: [], contractsTouched: [], newContracts: [], warnings: [], ...over };
}
