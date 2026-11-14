import type { Decision, RuleFinding, SimulationResult, Verdict } from "@signhold/core";
import { isUnlimitedApproval, nowIso } from "@signhold/core";
import { builtinRules, type CustomRuleFn, type CustomRuleRegistry, type EvaluateInput } from "./rules.js";

export interface PolicyEngineOptions {
  /** Functions available to rules of kind "custom" via `params.fn`. */
  customRules?: CustomRuleRegistry;
  /** Clock override, mainly for tests. */
  now?: () => Date;
}

export const ENGINE_ERROR_RULE_ID = "engine_error";

/**
 * Risk score formula (clamped to 0..100):
 *   + 40 for every finding with verdict "block"
 *   + 20 for every finding with verdict "escalate"
 *   + 25 if the simulation did not succeed (ok === false)
 *   + 10 per simulation warning            (capped at 30)
 *   + 15 per unlimited approval granted    (capped at 30)
 *   + 10 per never-seen-before contract    (capped at 20)
 * A transaction that fires no rules and has a clean simulation scores 0.
 */
export function computeRiskScore(findings: RuleFinding[], simulation?: SimulationResult): number {
  let score = 0;
  for (const f of findings) score += f.verdict === "block" ? 40 : 20;
  if (simulation) {
    if (!simulation.ok) score += 25;
    score += Math.min(30, 10 * simulation.warnings.length);
    const unlimited = simulation.approvals.filter((a) => a.unlimited || isUnlimitedApproval(a.next)).length;
    score += Math.min(30, 15 * unlimited);
    score += Math.min(20, 10 * simulation.newContracts.length);
  }
  return Math.max(0, Math.min(100, Math.round(score)));
}

/** block > escalate > allow. */
export function aggregateVerdict(findings: RuleFinding[]): Verdict {
  if (findings.some((f) => f.verdict === "block")) return "block";
  if (findings.some((f) => f.verdict === "escalate")) return "escalate";
  return "allow";
}

export function buildExplanation(
  verdict: Verdict,
  findings: RuleFinding[],
  input: Partial<EvaluateInput>,
  riskScore: number,
): string {
  const intent = input.intent;
  const sim = input.simulation;
  const who = intent ? `Transaction ${safeText(intent.id, 128)} from ${safeText(intent.from, 64)}${intent.to ? ` to ${safeText(intent.to, 64)}` : ""} on ${intent.chain}` : "Transaction";
  // The description is attacker-controlled text (prompt injection, T2 in the threat
  // model). It is quoted verbatim-but-escaped and length-capped so it can never
  // close the quote, inject newlines, or impersonate a finding in the explanation.
  const purpose = intent?.description ? ` (agent's stated purpose: ${JSON.stringify(safeText(intent.description, 200))})` : "";
  const head = `${who}${purpose} was ${verdict === "allow" ? "allowed" : verdict === "block" ? "blocked" : "escalated for human review"} with risk score ${riskScore}/100.`;

  const parts: string[] = [head];
  if (findings.length === 0) {
    parts.push("No policy rules fired.");
  } else {
    const blocks = findings.filter((f) => f.verdict === "block");
    const escalates = findings.filter((f) => f.verdict === "escalate");
    const describe = (f: RuleFinding) => `${f.ruleId} (${f.kind}): ${f.message}`;
    if (blocks.length) parts.push(`Blocking rule${blocks.length > 1 ? "s" : ""}: ${blocks.map(describe).join(" ")}`);
    if (escalates.length) parts.push(`Escalating rule${escalates.length > 1 ? "s" : ""}: ${escalates.map(describe).join(" ")}`);
  }
  if (sim) {
    const notes: string[] = [];
    if (!sim.ok) notes.push(`simulation failed${sim.revertReason ? ` (${sim.revertReason})` : ""}`);
    if (sim.warnings.length) notes.push(`simulation warnings: ${sim.warnings.join("; ")}`);
    if (sim.newContracts.length) notes.push(`${sim.newContracts.length} new contract(s) touched`);
    const unlimited = sim.approvals.filter((a) => a.unlimited || isUnlimitedApproval(a.next)).length;
    if (unlimited) notes.push(`${unlimited} unlimited approval(s)`);
    if (notes.length) parts.push(`Simulation notes: ${notes.join("; ")}.`);
  }
  return parts.join(" ");
}

export class PolicyEngine {
  private readonly custom: CustomRuleRegistry;
  private readonly now: () => Date;

  constructor(opts: PolicyEngineOptions = {}) {
    this.custom = { ...(opts.customRules ?? {}) };
    this.now = opts.now ?? (() => new Date());
  }

  /** Register (or replace) a custom rule function by name. */
  registerCustomRule(name: string, fn: CustomRuleFn): this {
    this.custom[name] = fn;
    return this;
  }

  /**
   * Evaluate an intent against a policy. Never throws: any internal failure yields
   * verdict "escalate" with a finding of ruleId "engine_error".
   */
  async evaluate(input: EvaluateInput): Promise<Decision> {
    let evaluatedAt: string;
    try {
      evaluatedAt = nowIso(this.now());
    } catch {
      evaluatedAt = new Date().toISOString();
    }

    try {
      const { intent, simulation, context, policy } = input;
      if (!intent || typeof intent !== "object") throw new Error("missing intent");
      if (!simulation || typeof simulation !== "object") throw new Error("missing simulation");
      if (!policy || !Array.isArray(policy.rules)) throw new Error("missing or malformed policy");
      const ctx = context ?? { agentId: "unknown" };

      const findings: RuleFinding[] = [];
      for (const rule of policy.rules) {
        try {
          const impl = builtinRules[rule.kind];
          if (!impl) throw new Error(`unknown rule kind "${String(rule.kind)}"`);
          const f = impl({ intent, simulation, context: ctx, policy, rule }, this.custom);
          if (f) findings.push(f);
        } catch (err) {
          findings.push(engineErrorFinding(err, { ruleId: rule?.id, kind: rule?.kind }));
        }
      }

      const verdict = aggregateVerdict(findings);
      const riskScore = computeRiskScore(findings, simulation);
      return {
        intentId: intent.id,
        verdict,
        findings,
        riskScore,
        explanation: buildExplanation(verdict, findings, input, riskScore),
        simulation,
        policyId: policy.id,
        policyVersion: policy.version,
        evaluatedAt,
      };
    } catch (err) {
      const findings = [engineErrorFinding(err)];
      const simulation = safeGet(() => input?.simulation);
      const riskScore = Math.max(50, computeRiskScore(findings, isSim(simulation) ? simulation : undefined));
      let explanation: string;
      try {
        explanation = buildExplanation("escalate", findings, input ?? {}, riskScore);
      } catch {
        explanation = `Transaction was escalated for human review because the policy engine failed: ${findings[0].message}`;
      }
      return {
        intentId: safeGet(() => String(input.intent.id)) ?? "unknown",
        verdict: "escalate",
        findings,
        riskScore,
        explanation,
        simulation: isSim(simulation) ? simulation : undefined,
        policyId: safeGet(() => String(input.policy.id)) ?? "unknown",
        policyVersion: safeGet(() => Number(input.policy.version)) ?? 0,
        evaluatedAt,
      };
    }
  }
}

/** Strip control characters (including newlines) and cap length; used on every untrusted string in explanations. */
export function safeText(v: unknown, max: number): string {
  const s = String(v ?? "").replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ");
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

function engineErrorFinding(err: unknown, evidence?: Record<string, unknown>): RuleFinding {
  const message = err instanceof Error ? err.message : String(err);
  return {
    ruleId: ENGINE_ERROR_RULE_ID,
    kind: "custom",
    verdict: "escalate",
    message: `Policy engine error: ${message}`,
    evidence: { ...evidence, error: message },
  };
}

function safeGet<T>(fn: () => T): T | undefined {
  try {
    const v = fn();
    return v === undefined || v === null || (typeof v === "number" && Number.isNaN(v)) ? undefined : v;
  } catch {
    return undefined;
  }
}

function isSim(v: unknown): v is SimulationResult {
  return (
    typeof v === "object" &&
    v !== null &&
    Array.isArray((v as SimulationResult).deltas) &&
    Array.isArray((v as SimulationResult).approvals) &&
    Array.isArray((v as SimulationResult).warnings) &&
    Array.isArray((v as SimulationResult).newContracts)
  );
}
