import { z } from "zod";
import type { PolicySet } from "@agentguard/core";
import { PolicyError } from "@agentguard/core";

export const ruleKindSchema = z.enum([
  "max_tx_usd",
  "max_window_usd",
  "allowlist_only",
  "denylist",
  "no_unlimited_approvals",
  "max_slippage_bps",
  "no_new_contracts",
  "require_simulation_ok",
  "max_native_value",
  "custom",
]);

const finiteNumber = z.union([z.number().finite(), z.string().regex(/^\d+(\.\d+)?$/)]);
const bigintString = z.union([z.string().regex(/^\d+$/, "expected integer string"), z.number().int().nonnegative()]);

/** Per-kind parameter validation; unknown extra keys are allowed. */
const paramsByKind: Record<z.infer<typeof ruleKindSchema>, z.ZodTypeAny> = {
  max_tx_usd: z.object({ maxUsd: finiteNumber }).passthrough(),
  max_window_usd: z.object({ maxUsd: finiteNumber }).passthrough(),
  allowlist_only: z.object({ addresses: z.array(z.string()).optional() }).passthrough().optional(),
  denylist: z.object({ addresses: z.array(z.string()).optional() }).passthrough().optional(),
  no_unlimited_approvals: z.object({}).passthrough().optional(),
  max_slippage_bps: z.object({ maxBps: finiteNumber, expectedOutUsd: finiteNumber.optional() }).passthrough(),
  no_new_contracts: z.object({}).passthrough().optional(),
  require_simulation_ok: z.object({}).passthrough().optional(),
  max_native_value: z.object({ maxWei: bigintString, decimals: z.number().int().nonnegative().optional() }).passthrough(),
  custom: z.object({ fn: z.string().min(1) }).passthrough(),
};

export const policyRuleSchema = z
  .object({
    id: z.string().min(1),
    kind: ruleKindSchema,
    onViolation: z.enum(["block", "escalate"]).optional(),
    params: z.record(z.unknown()).optional(),
    description: z.string().optional(),
  })
  .superRefine((rule, ctx) => {
    const res = paramsByKind[rule.kind].safeParse(rule.params);
    if (!res.success) {
      for (const issue of res.error.issues) {
        ctx.addIssue({ ...issue, path: ["params", ...issue.path] });
      }
    }
  });

export const policySetSchema = z
  .object({
    id: z.string().min(1),
    version: z.number().int().nonnegative(),
    rules: z.array(policyRuleSchema),
  })
  .superRefine((set, ctx) => {
    const seen = new Set<string>();
    set.rules.forEach((r, i) => {
      if (seen.has(r.id)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["rules", i, "id"], message: `duplicate rule id "${r.id}"` });
      seen.add(r.id);
    });
  });

/**
 * Validate a policy supplied as a JSON string or an already-parsed object.
 * Throws `PolicyError` (code "policy_error") on invalid input.
 */
export function loadPolicy(json: unknown): PolicySet {
  let value: unknown = json;
  if (typeof json === "string") {
    try {
      value = JSON.parse(json);
    } catch (err) {
      throw new PolicyError(`policy is not valid JSON: ${(err as Error).message}`, err);
    }
  }
  const res = policySetSchema.safeParse(value);
  if (!res.success) {
    const msg = res.error.issues.map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`).join("; ");
    throw new PolicyError(`invalid policy: ${msg}`, res.error);
  }
  return res.data as PolicySet;
}

/** Non-throwing variant. */
export function safeLoadPolicy(json: unknown): { ok: true; policy: PolicySet } | { ok: false; error: PolicyError } {
  try {
    return { ok: true, policy: loadPolicy(json) };
  } catch (err) {
    return { ok: false, error: err instanceof PolicyError ? err : new PolicyError(String(err), err) };
  }
}
