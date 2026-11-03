import type {
  AgentContext,
  PolicyRule,
  PolicySet,
  RuleFinding,
  RuleKind,
  SimulationResult,
  TransactionIntent,
  Verdict,
} from "@agentguard/core";
import { toDecimal, isUnlimitedApproval } from "@agentguard/core";

/** Everything a rule may look at. */
export interface EvaluateInput {
  intent: TransactionIntent;
  simulation: SimulationResult;
  context: AgentContext;
  policy: PolicySet;
}

/** Input handed to rule implementations (built-in and custom). */
export interface RuleInput extends EvaluateInput {
  rule: PolicyRule;
}

/** Signature of a custom rule looked up by `params.fn` in the registry. */
export type CustomRuleFn = (input: RuleInput) => RuleFinding | null;

export type CustomRuleRegistry = Record<string, CustomRuleFn>;

export type BuiltinRuleFn = (input: RuleInput, custom: CustomRuleRegistry) => RuleFinding | null;

// ---------- helpers ----------

export function violationVerdict(rule: PolicyRule): Exclude<Verdict, "allow"> {
  return rule.onViolation ?? "block";
}

export function finding(
  rule: PolicyRule,
  message: string,
  evidence?: Record<string, unknown>,
): RuleFinding {
  return { ruleId: rule.id, kind: rule.kind, verdict: violationVerdict(rule), message, evidence };
}

/** Addresses are case-insensitive on EVM, case-sensitive (base58) on Solana. */
export function normalizeAddress(addr: string, chain: TransactionIntent["chain"]): string {
  const t = addr.trim();
  return chain === "evm" ? t.toLowerCase() : t;
}

function num(v: unknown, name: string): number {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) return Number(v);
  throw new Error(`rule param "${name}" must be a finite number, got ${JSON.stringify(v)}`);
}

function optNum(v: unknown): number | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) return Number(v);
  return undefined;
}

function toBigInt(v: unknown, name: string): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isInteger(v)) return BigInt(v);
  if (typeof v === "string" && /^-?\d+$/.test(v.trim())) return BigInt(v.trim());
  throw new Error(`rule param "${name}" must be an integer bigint-as-string, got ${JSON.stringify(v)}`);
}

function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

/** Sum of USD outflows (negative deltas) as a positive number. */
export function spentUsd(sim: SimulationResult): number {
  return sim.deltas.reduce((acc, d) => {
    const usd = d.usdValue;
    return typeof usd === "number" && usd < 0 ? acc + -usd : acc;
  }, 0);
}

/** Sum of USD inflows (positive deltas). */
export function receivedUsd(sim: SimulationResult): number {
  return sim.deltas.reduce((acc, d) => {
    const usd = d.usdValue;
    return typeof usd === "number" && usd > 0 ? acc + usd : acc;
  }, 0);
}

function fmtUsd(n: number): string {
  return `$${n.toLocaleString("en-US", { maximumFractionDigits: 2 })}`;
}

// ---------- built-in rules ----------

const maxTxUsd: BuiltinRuleFn = ({ rule, simulation }) => {
  const max = num(rule.params?.maxUsd, "maxUsd");
  const spent = spentUsd(simulation);
  if (spent > max) {
    return finding(rule, `Transaction spends ${fmtUsd(spent)}, exceeding the per-transaction limit of ${fmtUsd(max)}.`, {
      spentUsd: spent,
      maxUsd: max,
    });
  }
  return null;
};

const maxWindowUsd: BuiltinRuleFn = ({ rule, simulation, context }) => {
  const max = num(rule.params?.maxUsd, "maxUsd");
  const prior = context.spentUsdInWindow ?? 0;
  const thisTx = spentUsd(simulation);
  const total = prior + thisTx;
  if (total > max) {
    return finding(
      rule,
      `Rolling-window spend would reach ${fmtUsd(total)} (${fmtUsd(prior)} already spent + ${fmtUsd(thisTx)} this transaction), exceeding the window limit of ${fmtUsd(max)}.`,
      { spentUsdInWindow: prior, thisTxUsd: thisTx, totalUsd: total, maxUsd: max, windowSeconds: context.windowSeconds },
    );
  }
  return null;
};

const allowlistOnly: BuiltinRuleFn = ({ rule, intent, simulation, context }) => {
  const chain = intent.chain;
  const list = new Set(
    [...(context.allowlist ?? []), ...strList(rule.params?.addresses)].map((a) => normalizeAddress(a, chain)),
  );
  const targets = new Set<string>();
  if (intent.to) targets.add(intent.to);
  for (const c of simulation.contractsTouched) targets.add(c);
  const offenders = [...targets].filter((t) => !list.has(normalizeAddress(t, chain)));
  if (offenders.length > 0) {
    return finding(
      rule,
      `Transaction touches ${offenders.length} address(es) not on the allowlist: ${offenders.join(", ")}.`,
      { offenders, allowlistSize: list.size },
    );
  }
  return null;
};

const denylist: BuiltinRuleFn = ({ rule, intent, simulation, context }) => {
  const chain = intent.chain;
  const list = new Set(
    [...(context.denylist ?? []), ...strList(rule.params?.addresses)].map((a) => normalizeAddress(a, chain)),
  );
  if (list.size === 0) return null;
  const targets = new Set<string>();
  if (intent.to) targets.add(intent.to);
  for (const c of simulation.contractsTouched) targets.add(c);
  for (const a of simulation.approvals) targets.add(a.spender);
  const hits = [...targets].filter((t) => list.has(normalizeAddress(t, chain)));
  if (hits.length > 0) {
    return finding(rule, `Transaction interacts with denylisted address(es): ${hits.join(", ")}.`, { hits });
  }
  return null;
};

const noUnlimitedApprovals: BuiltinRuleFn = ({ rule, simulation }) => {
  const unlimited = simulation.approvals.filter((a) => a.unlimited || isUnlimitedApproval(a.next));
  if (unlimited.length > 0) {
    return finding(
      rule,
      `Transaction grants unlimited token approval(s): ${unlimited.map((a) => `${a.token} -> ${a.spender}`).join(", ")}.`,
      { approvals: unlimited.map((a) => ({ token: a.token, spender: a.spender, next: a.next.toString() })) },
    );
  }
  return null;
};

const maxSlippageBps: BuiltinRuleFn = ({ rule, simulation, intent }) => {
  const maxBps = num(rule.params?.maxBps, "maxBps");
  const expected = optNum(rule.params?.expectedOutUsd) ?? optNum(intent.metadata?.expectedOutUsd);
  if (expected === undefined || expected <= 0) return null; // nothing to compare against
  const actual = receivedUsd(simulation);
  const slippageBps = ((expected - actual) / expected) * 10_000;
  if (slippageBps > maxBps) {
    return finding(
      rule,
      `Expected to receive ${fmtUsd(expected)} but simulation shows ${fmtUsd(actual)} (${slippageBps.toFixed(0)} bps slippage), above the limit of ${maxBps} bps.`,
      { expectedOutUsd: expected, actualOutUsd: actual, slippageBps, maxBps },
    );
  }
  return null;
};

const noNewContracts: BuiltinRuleFn = ({ rule, simulation }) => {
  if (simulation.newContracts.length > 0) {
    return finding(
      rule,
      `Transaction interacts with ${simulation.newContracts.length} contract(s) with no prior history: ${simulation.newContracts.join(", ")}.`,
      { newContracts: simulation.newContracts },
    );
  }
  return null;
};

const requireSimulationOk: BuiltinRuleFn = ({ rule, simulation }) => {
  if (!simulation.ok) {
    return finding(
      rule,
      `Simulation did not succeed${simulation.revertReason ? ` (revert: ${simulation.revertReason})` : ""}.`,
      { revertReason: simulation.revertReason },
    );
  }
  return null;
};

const maxNativeValue: BuiltinRuleFn = ({ rule, intent }) => {
  const maxWei = toBigInt(rule.params?.maxWei, "maxWei");
  const value = intent.value ?? 0n;
  if (value > maxWei) {
    const decimals = optNum(rule.params?.decimals) ?? (intent.chain === "solana" ? 9 : 18);
    return finding(
      rule,
      `Native value ${toDecimal(value, decimals)} exceeds the maximum of ${toDecimal(maxWei, decimals)} (${value.toString()} > ${maxWei.toString()} base units).`,
      { value: value.toString(), maxWei: maxWei.toString() },
    );
  }
  return null;
};

const custom: BuiltinRuleFn = (input, registry) => {
  const name = input.rule.params?.fn;
  if (typeof name !== "string" || name === "") {
    throw new Error(`custom rule "${input.rule.id}" is missing params.fn`);
  }
  const fn = registry[name];
  if (!fn) throw new Error(`custom rule "${input.rule.id}" references unknown function "${name}"`);
  const result = fn(input);
  if (result === null || result === undefined) return null;
  // Guarantee the finding is well-formed regardless of what the custom fn returned.
  return {
    ruleId: result.ruleId || input.rule.id,
    kind: result.kind || "custom",
    verdict: result.verdict === "escalate" || result.verdict === "block" ? result.verdict : violationVerdict(input.rule),
    message: result.message || `Custom rule "${name}" fired.`,
    evidence: result.evidence,
  };
};

export const builtinRules: Record<RuleKind, BuiltinRuleFn> = {
  max_tx_usd: maxTxUsd,
  max_window_usd: maxWindowUsd,
  allowlist_only: allowlistOnly,
  denylist,
  no_unlimited_approvals: noUnlimitedApprovals,
  max_slippage_bps: maxSlippageBps,
  no_new_contracts: noNewContracts,
  require_simulation_ok: requireSimulationOk,
  max_native_value: maxNativeValue,
  custom,
};
