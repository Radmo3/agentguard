/**
 * Minimal stand-in for a behavioral anomaly package. The real `@signhold/behavior`
 * is a separately licensed package that is not part of this repository; the API only
 * ever sees the structural interfaces in `src/types.ts` (`BehaviorIntegration`,
 * `BehaviorStoreLike`, `BehaviorModuleLike`), so the tests exercise the wiring and the
 * fail-closed behaviour of the server with this stub instead of the real analyzer.
 *
 * The stub learns the same *shape* of baseline the real package does (counterparties
 * seen and the largest outflow, from ALLOWED decisions only) and exposes a synchronous
 * custom rule that reads the warmed profile via `store.peek`:
 *
 *   - no profile / empty baseline         -> null (cold start: other rules decide)
 *   - novel counterparty, outflow >= 5x   -> block    (anomalyScore 90)
 *   - novel counterparty                  -> escalate (anomalyScore 60)
 *   - otherwise                           -> null
 */
import type { AgentContext, Decision, PolicyRule, PolicySet, RuleFinding, SimulationResult, TransactionIntent } from "@signhold/core";
import type { BehaviorIntegration, BehaviorIntegrationOptions, BehaviorStoreLike } from "../src/types.js";

export interface StubProfile {
  agentId: string;
  /** Allowed transactions folded in. */
  observedCount: number;
  counterparties: Record<string, number>;
  maxUsd: number;
  verdictHistory: Array<{ intentId: string; verdict: Decision["verdict"]; usd: number; at: string }>;
}

export class StubProfileStore implements BehaviorStoreLike {
  private readonly profiles = new Map<string, StubProfile>();
  async get(agentId: string): Promise<StubProfile | undefined> {
    return this.profiles.get(agentId);
  }
  peek(agentId: string): StubProfile | undefined {
    return this.profiles.get(agentId);
  }
  async put(profile: StubProfile): Promise<void> {
    this.profiles.set(profile.agentId, profile);
  }
}

export interface StubRuleInput {
  intent: TransactionIntent;
  simulation: SimulationResult;
  context: AgentContext;
  policy?: PolicySet;
  rule?: PolicyRule;
}

const norm = (a: string) => a.toLowerCase();

function counterpartiesOf(intent: TransactionIntent, simulation: SimulationResult): string[] {
  const out = new Set<string>();
  if (intent.to) out.add(norm(intent.to));
  for (const c of simulation.contractsTouched ?? []) out.add(norm(c));
  for (const r of simulation.recipients ?? []) out.add(norm(r));
  return [...out];
}

export function outflowUsd(simulation: SimulationResult): number {
  let usd = 0;
  for (const d of simulation.deltas ?? []) if (typeof d.usdValue === "number" && d.usdValue < 0) usd += -d.usdValue;
  return usd;
}

export function createStubBehaviorRule(store: StubProfileStore, opts: { blockAt?: number; escalateAt?: number } = {}) {
  const blockAt = opts.blockAt ?? 85;
  const escalateAt = opts.escalateAt ?? 50;
  return (input: StubRuleInput): RuleFinding | null => {
    const ruleId = input.rule?.id ?? "behavior";
    const profile = input.context?.agentId ? store.peek(input.context.agentId) : undefined;
    if (!profile || profile.observedCount === 0) return null;
    const novel = counterpartiesOf(input.intent, input.simulation).filter((c) => !(c in profile.counterparties));
    if (novel.length === 0) return null;
    const usd = outflowUsd(input.simulation);
    const anomalyScore = usd >= 5 * Math.max(profile.maxUsd, 1) ? 90 : 60;
    const verdict = anomalyScore >= blockAt ? "block" : anomalyScore >= escalateAt ? "escalate" : null;
    if (!verdict) return null;
    return {
      ruleId,
      kind: "custom",
      verdict,
      message: `Transaction is out of character for this agent (anomaly ${anomalyScore}/100; top signals: novel_counterparty). Funds flow to never-paid address(es): ${novel.join(", ")}.`,
      evidence: { anomalyScore, observedCount: profile.observedCount, novel, usd },
    };
  };
}

/** Fold a decision into the stub baseline. Only `allow` teaches; everything extends the verdict history. */
export async function stubPersist(
  store: StubProfileStore,
  agentId: string,
  intent: TransactionIntent,
  simulation: SimulationResult,
  decision: Decision,
  opts: { at?: Date } = {},
): Promise<StubProfile> {
  const existing = await store.get(agentId);
  const p: StubProfile = existing
    ? { ...existing, counterparties: { ...existing.counterparties }, verdictHistory: [...existing.verdictHistory] }
    : { agentId, observedCount: 0, counterparties: {}, maxUsd: 0, verdictHistory: [] };
  const usd = outflowUsd(simulation);
  if (decision.verdict === "allow") {
    p.observedCount += 1;
    for (const c of counterpartiesOf(intent, simulation)) p.counterparties[c] = (p.counterparties[c] ?? 0) + 1;
    p.maxUsd = Math.max(p.maxUsd, usd);
  }
  p.verdictHistory.push({ intentId: String(intent.id), verdict: decision.verdict, usd, at: (opts.at ?? new Date()).toISOString() });
  await store.put(p);
  return p;
}

/** Same shape as the factory export the real package provides (`BehaviorModuleLike`). */
export function createBehaviorIntegration(_options: BehaviorIntegrationOptions = {}): BehaviorIntegration & { rule: (input: StubRuleInput) => RuleFinding | null; store: StubProfileStore } {
  const store = new StubProfileStore();
  return {
    store,
    rule: createStubBehaviorRule(store),
    persist: (agentId, intent, simulation, decision, o) => stubPersist(store, agentId, intent, simulation, decision, o),
  };
}
