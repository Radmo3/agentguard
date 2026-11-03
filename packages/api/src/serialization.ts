import { z } from "zod";
import type {
  AgentContext,
  ApprovalChange,
  AssetDelta,
  AuditRecord,
  CheckRequest,
  Decision,
  SimulationResult,
  TransactionIntent,
} from "@agentguard/core";
import { bigintReplacer } from "@agentguard/core";

/** Decimal string (optionally negative) -> bigint. Accepts bigint/number inputs too for in-process use. */
const bigintString = z
  .union([z.string().regex(/^-?\d+$/, "expected decimal integer string"), z.bigint(), z.number().int()])
  .transform((v) => (typeof v === "bigint" ? v : BigInt(v)));

export const transactionIntentSchema = z.object({
  id: z.string().min(1),
  chain: z.enum(["evm", "solana"]),
  chainId: z.union([z.number(), z.string()]).optional(),
  from: z.string().min(1),
  to: z.string().optional(),
  value: bigintString.optional(),
  data: z
    .string()
    .regex(/^0x[0-9a-fA-F]*$/, "expected 0x-prefixed hex")
    .optional()
    .transform((v) => v as `0x${string}` | undefined),
  raw: z.string().optional(),
  description: z.string().max(4096).optional(),
  metadata: z.record(z.unknown()).optional(),
});

export const agentContextSchema = z.object({
  agentId: z.string().min(1),
  tenantId: z.string().optional(),
  spentUsdInWindow: z.number().optional(),
  windowSeconds: z.number().optional(),
  allowlist: z.array(z.string()).optional(),
  denylist: z.array(z.string()).optional(),
  now: z
    .union([z.string().datetime({ offset: true }), z.date()])
    .optional()
    .transform((v) => (typeof v === "string" ? new Date(v) : v)),
});

export const checkRequestSchema = z.object({
  intent: transactionIntentSchema,
  context: agentContextSchema,
  policyId: z.string().optional(),
});

export function parseCheckRequest(body: unknown): CheckRequest {
  const parsed = checkRequestSchema.parse(body);
  // zod's inferred type is structurally identical to CheckRequest; cast keeps the core type canonical.
  return parsed as CheckRequest;
}

/** Serialise anything containing bigints to JSON (bigints as decimal strings). */
export function stringifyWithBigints(value: unknown): string {
  return JSON.stringify(value, bigintReplacer);
}

// ---- Revivers: turn decimal strings back into bigints on known fields ----

function toBig(v: unknown): bigint | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "bigint") return v;
  if (typeof v === "string" || typeof v === "number") return BigInt(v);
  throw new TypeError(`cannot revive bigint from ${typeof v}`);
}

export function reviveIntent(raw: Record<string, unknown>): TransactionIntent {
  return { ...(raw as unknown as TransactionIntent), value: toBig(raw.value) };
}

export function reviveSimulation(raw: Record<string, unknown>): SimulationResult {
  const deltas = ((raw.deltas as Record<string, unknown>[] | undefined) ?? []).map(
    (d) => ({ ...d, amount: toBig(d.amount) ?? 0n }) as unknown as AssetDelta,
  );
  const approvals = ((raw.approvals as Record<string, unknown>[] | undefined) ?? []).map(
    (a) =>
      ({ ...a, previous: toBig(a.previous) ?? 0n, next: toBig(a.next) ?? 0n }) as unknown as ApprovalChange,
  );
  return {
    ...(raw as unknown as SimulationResult),
    deltas,
    approvals,
    gasEstimate: toBig(raw.gasEstimate),
  };
}

export function reviveDecision(raw: Record<string, unknown>): Decision {
  const sim = raw.simulation as Record<string, unknown> | undefined;
  return {
    ...(raw as unknown as Decision),
    simulation: sim ? reviveSimulation(sim) : undefined,
  };
}

export function reviveContext(raw: Record<string, unknown>): AgentContext {
  return {
    ...(raw as unknown as AgentContext),
    now: typeof raw.now === "string" ? new Date(raw.now) : (raw.now as Date | undefined),
  };
}

export function reviveAuditRecord(raw: Record<string, unknown>): AuditRecord {
  return {
    id: raw.id as string,
    recordedAt: raw.recordedAt as string,
    intent: reviveIntent(raw.intent as Record<string, unknown>),
    decision: reviveDecision(raw.decision as Record<string, unknown>),
    context: reviveContext(raw.context as Record<string, unknown>),
  };
}
