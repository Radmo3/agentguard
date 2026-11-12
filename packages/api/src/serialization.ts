import { z } from "zod";
import type {
  AgentContext,
  ApprovalChange,
  ApprovalSubmission,
  AssetDelta,
  AuditRecord,
  CheckRequest,
  Decision,
  SimulationResult,
  TransactionIntent,
} from "@agentguard/core";
import { bigintReplacer } from "@agentguard/core";

// ---- Limits (bytes/characters) ----
export const LIMITS = {
  description: 2 * 1024,
  /** Serialized (JSON) size of `intent.metadata`. */
  metadataSerialized: 8 * 1024,
  /** Hex characters of EVM calldata after the 0x prefix. */
  calldataHex: 128 * 1024,
  /** Base64 characters of a Solana serialized transaction. */
  rawBase64: 16 * 1024,
  id: 128,
  listEntries: 1000,
  chainIdString: 64,
  /** Free-text reason on an approval submission. */
  approvalReason: 512,
} as const;

/** Decimal string (optionally negative) -> bigint. Accepts bigint/number inputs too for in-process use. */
const bigintString = z
  .union([
    z.string().max(80).regex(/^-?\d+$/, "expected decimal integer string"),
    z.bigint(),
    z.number().int().finite(),
  ])
  .transform((v) => (typeof v === "bigint" ? v : BigInt(v)));

/** Native value: a non-negative integer that fits in 256 bits. Negative or oversized values have no on-chain meaning. */
const nativeValue = bigintString.refine((v) => v >= 0n && v < 1n << 256n, "value must be a non-negative integer below 2^256");

const uuid = z.string().uuid("intent id must be a UUID");
const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const SOLANA_ADDRESS_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export const evmAddressSchema = z.string().regex(EVM_ADDRESS_RE, "expected 0x-prefixed 20-byte hex address");
export const solanaAddressSchema = z.string().regex(SOLANA_ADDRESS_RE, "expected base58 Solana address (32-44 chars)");

export function isEvmAddress(s: string): boolean {
  return EVM_ADDRESS_RE.test(s);
}
export function isSolanaAddress(s: string): boolean {
  return SOLANA_ADDRESS_RE.test(s);
}

const addressList = (schema: z.ZodType<string>) => z.array(schema).max(LIMITS.listEntries);

const finiteNumber = z.number().finite();

const metadataSchema = z
  .record(z.string().max(256), z.unknown())
  .superRefine((v, ctx) => {
    let size: number;
    try {
      size = Buffer.byteLength(JSON.stringify(v, bigintReplacer), "utf8");
    } catch {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "metadata is not serializable" });
      return;
    }
    if (size > LIMITS.metadataSerialized) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: `metadata exceeds ${LIMITS.metadataSerialized} bytes serialized` });
    }
  });

const intentBase = {
  id: uuid,
  description: z.string().max(LIMITS.description).optional(),
  metadata: metadataSchema.optional(),
  value: nativeValue.optional(),
};

export const evmIntentSchema = z
  .object({
    ...intentBase,
    chain: z.literal("evm"),
    chainId: z.union([z.number().int().positive().finite(), z.string().regex(/^\d{1,20}$/)]).optional(),
    from: evmAddressSchema,
    to: evmAddressSchema.optional(),
    data: z
      .string()
      .max(2 + LIMITS.calldataHex)
      .regex(/^0x([0-9a-fA-F]{2})*$/, "expected 0x-prefixed even-length hex")
      .optional()
      .transform((v) => v as `0x${string}` | undefined),
    raw: z.undefined().optional(),
  })
  .strict();

export const solanaIntentSchema = z
  .object({
    ...intentBase,
    chain: z.literal("solana"),
    chainId: z.string().max(LIMITS.chainIdString).regex(/^[a-z0-9-]+$/, "expected Solana cluster name").optional(),
    from: solanaAddressSchema,
    to: solanaAddressSchema.optional(),
    raw: z
      .string()
      .max(LIMITS.rawBase64)
      .regex(/^[A-Za-z0-9+/]+={0,2}$/, "expected base64")
      .optional(),
    data: z.undefined().optional(),
  })
  .strict();

export const transactionIntentSchema = z.discriminatedUnion("chain", [evmIntentSchema, solanaIntentSchema]);

export const agentContextSchema = z
  .object({
    agentId: z.string().min(1).max(LIMITS.id),
    tenantId: z.string().min(1).max(LIMITS.id).optional(),
    spentUsdInWindow: finiteNumber.nonnegative().optional(),
    windowSeconds: finiteNumber.nonnegative().optional(),
    allowlist: addressList(z.string().min(1).max(64)).optional(),
    denylist: addressList(z.string().min(1).max(64)).optional(),
    now: z
      .union([z.string().datetime({ offset: true }), z.date()])
      .optional()
      .transform((v) => (typeof v === "string" ? new Date(v) : v)),
  })
  .strict();

export const checkRequestSchema = z
  .object({
    intent: transactionIntentSchema,
    context: agentContextSchema,
    policyId: z.string().min(1).max(LIMITS.id).optional(),
  })
  .strict();

export function parseCheckRequest(body: unknown): CheckRequest {
  const parsed = checkRequestSchema.parse(body);
  // zod's inferred type is structurally identical to CheckRequest; cast keeps the core type canonical.
  return parsed as unknown as CheckRequest;
}

/** Body of `POST /v1/approvals`. Strict: unknown keys rejected, every field bounded. */
export const approvalSubmissionSchema = z
  .object({
    auditId: uuid,
    keyId: z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/, "expected approver key id"),
    // 64-byte Ed25519 signature, base64 => exactly 88 characters with one '=' of padding.
    signature: z.string().length(88).regex(/^[A-Za-z0-9+/]{86}==$/, "expected base64 Ed25519 signature"),
    approvedAt: z.string().datetime({ offset: true }),
    reason: z.string().max(LIMITS.approvalReason).optional(),
  })
  .strict();

export function parseApprovalSubmission(body: unknown): ApprovalSubmission {
  return approvalSubmissionSchema.parse(body) as ApprovalSubmission;
}

/** Strip control characters and cap length: approver-supplied text is data, shown to humans only. */
export function sanitizeReason(s: string | undefined): string | undefined {
  if (s === undefined) return undefined;
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u001f\u007f]/g, "").slice(0, LIMITS.approvalReason);
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
  const out = { ...(raw as unknown as TransactionIntent) };
  const v = toBig(raw.value);
  if (v === undefined) delete (out as { value?: bigint }).value;
  else out.value = v;
  return out;
}

export function reviveSimulation(raw: Record<string, unknown>): SimulationResult {
  const deltas = ((raw.deltas as Record<string, unknown>[] | undefined) ?? []).map(
    (d) => ({ ...d, amount: toBig(d.amount) ?? 0n }) as unknown as AssetDelta,
  );
  const approvals = ((raw.approvals as Record<string, unknown>[] | undefined) ?? []).map(
    (a) =>
      ({ ...a, previous: toBig(a.previous) ?? 0n, next: toBig(a.next) ?? 0n }) as unknown as ApprovalChange,
  );
  const out: SimulationResult = { ...(raw as unknown as SimulationResult), deltas, approvals };
  const gas = toBig(raw.gasEstimate);
  if (gas === undefined) delete out.gasEstimate;
  else out.gasEstimate = gas;
  return out;
}

export function reviveDecision(raw: Record<string, unknown>): Decision {
  const sim = raw.simulation as Record<string, unknown> | undefined;
  const out: Decision = { ...(raw as unknown as Decision) };
  if (sim) out.simulation = reviveSimulation(sim);
  else delete out.simulation;
  return out;
}

export function reviveContext(raw: Record<string, unknown>): AgentContext {
  const out: AgentContext = { ...(raw as unknown as AgentContext) };
  if (typeof raw.now === "string") out.now = new Date(raw.now);
  else if (raw.now === undefined) delete out.now;
  return out;
}

export function reviveAuditRecord(raw: Record<string, unknown>): AuditRecord {
  const rec: AuditRecord = {
    id: raw.id as string,
    recordedAt: raw.recordedAt as string,
    intent: reviveIntent(raw.intent as Record<string, unknown>),
    decision: reviveDecision(raw.decision as Record<string, unknown>),
    context: reviveContext(raw.context as Record<string, unknown>),
  };
  if (raw.type !== undefined) rec.type = raw.type as AuditRecord["type"];
  if (raw.principal) rec.principal = raw.principal as AuditRecord["principal"];
  if (raw.integrity) rec.integrity = raw.integrity as AuditRecord["integrity"];
  if (raw.approvalRequest) rec.approvalRequest = raw.approvalRequest as AuditRecord["approvalRequest"];
  if (raw.approval) rec.approval = raw.approval as AuditRecord["approval"];
  return rec;
}
