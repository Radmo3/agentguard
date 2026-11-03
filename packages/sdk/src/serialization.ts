import type {
  AgentContext,
  ApprovalChange,
  AssetDelta,
  CheckResponse,
  Decision,
  SimulationResult,
  TransactionIntent,
} from "@agentguard/core";
import { bigintReplacer } from "@agentguard/core";

/** Serialise a request payload: bigints -> decimal strings, Dates -> ISO. */
export function serializeRequest(value: unknown): string {
  return JSON.stringify(value, (k, v) => bigintReplacer(k, v));
}

function toBig(v: unknown): bigint | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "bigint") return v;
  if (typeof v === "string" || typeof v === "number") return BigInt(v);
  throw new TypeError(`cannot revive bigint from ${typeof v}`);
}

export function reviveSimulation(raw: Record<string, unknown>): SimulationResult {
  const deltas = ((raw.deltas as Record<string, unknown>[] | undefined) ?? []).map(
    (d) => ({ ...d, amount: toBig(d.amount) ?? 0n }) as unknown as AssetDelta,
  );
  const approvals = ((raw.approvals as Record<string, unknown>[] | undefined) ?? []).map(
    (a) =>
      ({ ...a, previous: toBig(a.previous) ?? 0n, next: toBig(a.next) ?? 0n }) as unknown as ApprovalChange,
  );
  return { ...(raw as unknown as SimulationResult), deltas, approvals, gasEstimate: toBig(raw.gasEstimate) };
}

export function reviveDecision(raw: Record<string, unknown>): Decision {
  const sim = raw.simulation as Record<string, unknown> | undefined;
  return { ...(raw as unknown as Decision), simulation: sim ? reviveSimulation(sim) : undefined };
}

export function reviveCheckResponse(raw: Record<string, unknown>): CheckResponse {
  return { decision: reviveDecision(raw.decision as Record<string, unknown>), auditId: raw.auditId as string };
}

export function reviveIntent(raw: Record<string, unknown>): TransactionIntent {
  return { ...(raw as unknown as TransactionIntent), value: toBig(raw.value) };
}

export function reviveContext(raw: Record<string, unknown>): AgentContext {
  return {
    ...(raw as unknown as AgentContext),
    now: typeof raw.now === "string" ? new Date(raw.now) : (raw.now as Date | undefined),
  };
}
