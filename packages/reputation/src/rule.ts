import type { PolicyRule, RuleFinding, SimulationResult, TransactionIntent, Verdict } from "@agentguard/core";
import type { ReputationService } from "./service.js";
import type { AggregatedReputation, ReputationVerdict } from "./types.js";

/**
 * Structural subset of the policy engine's `RuleInput`. Declared locally (not imported
 * from @agentguard/policy) so this package has no dependency on the engine; a
 * `ReputationRuleFn` is assignable to the engine's `CustomRuleFn`.
 */
export interface ReputationRuleInput {
  intent: TransactionIntent;
  simulation: SimulationResult;
  rule: PolicyRule;
}

export type ReputationRuleFn = (input: ReputationRuleInput) => RuleFinding | null;

export interface ReputationRuleOptions {
  /** Verdicts that produce a `block` finding (default ["malicious"]). */
  blockOn?: ReputationVerdict[];
  /** Verdicts that produce an `escalate` finding (default ["suspicious", "unknown"]). */
  escalateOn?: ReputationVerdict[];
  /**
   * For verdicts in `escalateOn`, only escalate when the aggregated risk score is at
   * least this value (default 60). Does not apply to `blockOn`.
   */
  minScoreToEscalate?: number;
  /**
   * What to do when an address is NOT in the cache (prefetch was skipped or expired).
   * "escalate" (default, fail-closed) or "ignore".
   */
  onCacheMiss?: "escalate" | "ignore";
  /** Also check `simulation.approvals[].spender` (default true). */
  includeApprovalSpenders?: boolean;
  /**
   * Escalate whenever a lookup carries `provider_error` / `all_providers_failed` tags,
   * regardless of score (default true). Without this, a total provider outage in
   * fail-closed mode yields score 50 < the default `minScoreToEscalate` of 60 and the
   * transaction would be ALLOWED: an outage must never look like a clean bill of health.
   * Verdicts of `malicious` still block and `trusted` from a surviving provider still passes.
   */
  escalateOnProviderError?: boolean;
}

const ERROR_TAGS = new Set(["provider_error", "all_providers_failed", "no_providers", "not_prefetched"]);

export interface ReputationRuleEvidence extends Record<string, unknown> {
  blocked: AddressVerdict[];
  escalated: AddressVerdict[];
  missing: string[];
  checked: number;
}

export interface AddressVerdict {
  address: string;
  verdict: ReputationVerdict;
  score: number;
  tags: string[];
  sources: string[];
}

/**
 * Build a synchronous custom rule for the policy engine's `CustomRuleRegistry`.
 *
 * IMPORTANT — two-phase usage. The engine's custom-rule signature is synchronous, so
 * this rule only READS the service cache. The integration layer must warm it first:
 *
 *   const reputation = new ReputationService({ providers: [...] });
 *   const registry = { reputation: createReputationRule(reputation) };
 *   // per request:
 *   const simulation = await adapter.simulate(intent);
 *   await reputation.prefetch(intent, simulation);          // <-- REQUIRED, awaited
 *   const decision = await engine.evaluate({ intent, simulation, context, policy });
 *
 * and the policy must include `{ id: "rep", kind: "custom", params: { fn: "reputation" } }`.
 * Addresses missing from the cache (prefetch skipped, or TTL expired between prefetch
 * and evaluate) escalate with tag `not_prefetched` unless `onCacheMiss: "ignore"`.
 */
export function createReputationRule(service: ReputationService, options: ReputationRuleOptions = {}): ReputationRuleFn {
  const blockOn = new Set<ReputationVerdict>(options.blockOn ?? ["malicious"]);
  const escalateOn = new Set<ReputationVerdict>(options.escalateOn ?? ["suspicious", "unknown"]);
  const minScore = clamp(options.minScoreToEscalate ?? 60);
  const onMiss = options.onCacheMiss ?? "escalate";
  const includeSpenders = options.includeApprovalSpenders ?? true;
  const escalateOnError = options.escalateOnProviderError ?? true;

  return function reputationRule({ intent, simulation, rule }: ReputationRuleInput): RuleFinding | null {
    const targets = collectTargets(intent, simulation, includeSpenders);
    const blocked: AddressVerdict[] = [];
    const escalated: AddressVerdict[] = [];
    const missing: string[] = [];

    for (const address of targets) {
      const rep = service.peek(intent.chain, address, intent.chainId);
      if (!rep) {
        missing.push(address);
        continue;
      }
      const av = summarize(rep);
      const errored = escalateOnError && rep.verdict !== "trusted" && rep.tags.some((t) => ERROR_TAGS.has(t));
      if (blockOn.has(rep.verdict)) blocked.push(av);
      else if ((escalateOn.has(rep.verdict) && rep.score >= minScore) || errored) escalated.push(av);
    }

    const evidence: ReputationRuleEvidence = { blocked, escalated, missing, checked: targets.length };
    const parts: string[] = [];
    let verdict: Exclude<Verdict, "allow"> | null = null;

    if (blocked.length > 0) {
      verdict = "block";
      parts.push(`Reputation check flagged ${blocked.length} address(es) as ${describe(blocked)}.`);
    }
    if (escalated.length > 0) {
      verdict ??= "escalate";
      const outages = escalated.filter((a) => a.tags.some((t) => ERROR_TAGS.has(t)));
      if (outages.length > 0) {
        parts.push(`Reputation data unavailable for ${outages.length} address(es) (provider error or timeout); failing closed.`);
        evidence.providerError = true;
      }
      parts.push(`${escalated.length} address(es) have elevated or unknown risk: ${describe(escalated)}.`);
    }
    if (missing.length > 0 && onMiss === "escalate") {
      verdict ??= "escalate";
      parts.push(`${missing.length} address(es) had no reputation data (prefetch missing or expired): ${missing.join(", ")}.`);
      evidence.tags = ["not_prefetched"];
    }
    if (!verdict) return null;
    return { ruleId: rule.id, kind: rule.kind ?? "custom", verdict, message: parts.join(" "), evidence };
  };
}

function collectTargets(intent: TransactionIntent, simulation: SimulationResult | undefined, spenders: boolean): string[] {
  const set = new Set<string>();
  const norm = (a: string) => (intent.chain === "evm" ? a.trim().toLowerCase() : a.trim());
  if (intent.to) set.add(norm(intent.to));
  for (const c of simulation?.contractsTouched ?? []) if (typeof c === "string" && c) set.add(norm(c));
  for (const r of simulation?.recipients ?? []) if (typeof r === "string" && r) set.add(norm(r));
  if (spenders) for (const a of simulation?.approvals ?? []) if (a?.spender) set.add(norm(a.spender));
  return [...set];
}

function summarize(rep: AggregatedReputation): AddressVerdict {
  return {
    address: rep.address,
    verdict: rep.verdict,
    score: rep.score,
    tags: rep.tags.slice(0, 20),
    sources: rep.signals.map((s) => s.source),
  };
}

function describe(list: AddressVerdict[]): string {
  return list
    .slice(0, 5)
    .map((a) => `${a.address} (${a.verdict}, score ${a.score}${a.tags.length ? `, ${a.tags.slice(0, 4).join("/")}` : ""})`)
    .join("; ");
}

function clamp(n: number): number {
  return Math.max(0, Math.min(100, Number.isFinite(n) ? n : 60));
}
