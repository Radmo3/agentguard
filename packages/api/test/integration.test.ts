/**
 * Wiring of the behavior integration (`ServerOptions.behavior`, duck-typed; the real
 * `@agentguard/behavior` package is separately licensed and not part of this repo, so
 * an in-test stub with the same structural shape is used) and @agentguard/reputation
 * into the request pipeline (simulate -> reputation.prefetch -> behavior.store.get ->
 * evaluate -> audit -> behavior.persist), and the fail-closed invariants of that wiring.
 */
import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { Decision } from "@agentguard/core";
import { PolicyEngine, conservativeDefaultPolicy } from "@agentguard/policy";
import { ReputationService, StaticListProvider, createReputationRule, type ReputationProvider } from "@agentguard/reputation";
import { InMemoryAuditStore } from "../src/audit.js";
import { BEHAVIOR_RULE, REPUTATION_RULE, withCustomRules, buildReputationUrl } from "../src/bootstrap.js";
import { createServer } from "../src/server.js";
import type { ServerOptions } from "../src/types.js";
import { FakeAdapter, FakeEngine, intentId, okSimulation, requestBody } from "./fakes.js";
import { StubProfileStore, createStubBehaviorRule, stubPersist as persistOutcome } from "./behavior-stub.js";

const SHADY = "0xdead00000000000000000000000000000000beef";

function cleanSimulation() {
  return { ...okSimulation(), approvals: [], deltas: [{ asset: "0xtoken", decimals: 6, amount: -5_000_000n, usdValue: -5 }] };
}

function stack(opts: { providers?: ReputationProvider[]; store?: StubProfileStore } = {}) {
  const store = opts.store ?? new StubProfileStore();
  const reputation = new ReputationService({
    providers: opts.providers ?? [new StaticListProvider({ deny: [{ chain: "evm", address: SHADY }] })],
    providerTimeoutMs: 100,
  });
  const engine = new PolicyEngine({
    customRules: { behavior: createStubBehaviorRule(store), reputation: createReputationRule(reputation) },
  });
  const policy = withCustomRules(conservativeDefaultPolicy, [BEHAVIOR_RULE, REPUTATION_RULE]);
  return { store, reputation, engine, policy };
}

async function build(over: Partial<ServerOptions> = {}, s = stack()) {
  const app = await createServer({
    engine: s.engine,
    adapters: { evm: new FakeAdapter("evm", async () => cleanSimulation()) },
    policies: new Map([[s.policy.id, s.policy]]),
    audit: new InMemoryAuditStore(),
    behavior: { store: s.store, persist: (a, i, sim, d, o) => persistOutcome(s.store, a, i, sim, d, o) },
    reputation: s.reputation,
    logger: false,
    rateLimit: false,
    env: "test",
    ...over,
  });
  return { app, ...s };
}

async function check(app: FastifyInstance, n: number, over: Record<string, unknown> = {}) {
  const body = requestBody();
  (body.intent as Record<string, unknown>).id = intentId(n);
  (body.intent as Record<string, unknown>).value = "0";
  Object.assign(body.intent, over);
  const res = await app.inject({ method: "POST", url: "/v1/check", payload: body });
  return { res, decision: res.json().decision as Decision };
}

describe("behavior + reputation wiring", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("default policy extension adds both custom rules exactly once and keeps the policy loadable", async () => {
    const p = withCustomRules(conservativeDefaultPolicy, [BEHAVIOR_RULE, REPUTATION_RULE, BEHAVIOR_RULE]);
    expect(p.rules.filter((r) => r.kind === "custom").map((r) => r.id)).toEqual(["behavior", "reputation"]);
    expect(conservativeDefaultPolicy.rules.some((r) => r.kind === "custom")).toBe(false); // original untouched
    const { loadPolicy } = await import("@agentguard/policy");
    expect(() => loadPolicy(p)).not.toThrow();
  });

  it("runs prefetch and store.get before evaluate, and persistOutcome after audit", async () => {
    const order: string[] = [];
    const s = stack();
    const store = s.store;
    const origGet = store.get.bind(store);
    store.get = async (id) => { order.push("store.get"); return origGet(id); };
    const origPrefetch = s.reputation.prefetch.bind(s.reputation);
    s.reputation.prefetch = async (i, sim) => { order.push("prefetch"); return origPrefetch(i, sim); };
    const origEval = s.engine.evaluate.bind(s.engine);
    s.engine.evaluate = async (input) => { order.push("evaluate"); return origEval(input); };
    const audit = new InMemoryAuditStore();
    const origRecord = audit.record.bind(audit);
    audit.record = async (r) => { order.push("audit"); return origRecord(r); };
    ({ app } = await build({
      audit,
      behavior: { store, persist: async (a, i, sim, d, o) => { order.push("persist"); return persistOutcome(store, a, i, sim, d, o); } },
    }, s));
    const { res, decision } = await check(app, 1);
    expect(res.statusCode).toBe(200);
    expect(decision.verdict).toBe("allow");
    // persistOutcome re-reads the store internally, so compare the first occurrence of each step.
    const first = (k: string) => order.indexOf(k);
    expect(order.slice(0, 5)).toEqual(["prefetch", "store.get", "evaluate", "audit", "persist"]);
    expect(first("prefetch")).toBeLessThan(first("evaluate"));
    expect(first("audit")).toBeLessThan(first("persist"));
    expect(store.peek("agent-A")?.observedCount).toBe(1);
  });

  it("blocks a denylisted counterparty via the reputation rule under the default policy", async () => {
    ({ app } = await build());
    const { decision } = await check(app, 2, { to: SHADY });
    expect(decision.verdict).toBe("block");
    expect(decision.findings.map((f) => f.ruleId)).toContain("reputation");
  });

  it("escalates (never allows) when the reputation provider is down", async () => {
    const down: ReputationProvider = { name: "intel", async lookup() { throw new Error("upstream 503"); } };
    ({ app } = await build({}, stack({ providers: [down] })));
    const { decision } = await check(app, 3);
    expect(decision.verdict).toBe("escalate");
    const rep = decision.findings.find((f) => f.ruleId === "reputation");
    expect(rep?.verdict).toBe("escalate");
    expect(JSON.stringify(rep?.evidence)).toContain("provider_error");
  });

  it("escalates when the reputation provider hangs past its timeout", async () => {
    const hang: ReputationProvider = { name: "slow", lookup: () => new Promise(() => {}) };
    ({ app } = await build({}, stack({ providers: [hang] })));
    const { decision } = await check(app, 4);
    expect(decision.verdict).toBe("escalate");
  });

  it("escalates with reputation_error when prefetch itself throws (service contract violated)", async () => {
    const s = stack();
    s.reputation.prefetch = async () => { throw new Error("prefetch exploded"); };
    ({ app } = await build({}, s));
    const { decision } = await check(app, 5);
    expect(decision.verdict).toBe("escalate");
    expect(decision.findings[0]).toMatchObject({ ruleId: "reputation_error", verdict: "escalate" });
    expect(decision.riskScore).toBeGreaterThanOrEqual(50);
  });

  it("escalates with behavior_error when the profile store cannot be read", async () => {
    const s = stack();
    s.store.get = async () => { throw new Error("db down"); };
    ({ app } = await build({}, s));
    const { decision } = await check(app, 6);
    expect(decision.verdict).toBe("escalate");
    expect(decision.findings.map((f) => f.ruleId)).toContain("behavior_error");
  });

  it("a pre-evaluate failure never downgrades a block", async () => {
    const s = stack();
    s.store.get = async () => { throw new Error("db down"); };
    ({ app } = await build({}, s));
    const { decision } = await check(app, 7, { to: SHADY });
    expect(decision.verdict).toBe("block");
  });

  it("persistOutcome failure does not change the verdict or the audit record", async () => {
    const s = stack();
    const audit = new InMemoryAuditStore();
    ({ app } = await build({ audit, behavior: { store: s.store, persist: async () => { throw new Error("disk full"); } } }, s));
    const { res, decision } = await check(app, 8);
    expect(res.statusCode).toBe(200);
    expect(decision.verdict).toBe("allow");
    expect((await audit.get(res.json().auditId))?.decision.verdict).toBe("allow");
    expect(s.store.peek("agent-A")).toBeUndefined();
  });

  it("persistOutcome rejecting with a non-Error is swallowed too", async () => {
    const s = stack();
    ({ app } = await build({ behavior: { store: s.store, persist: () => Promise.reject("nope") } }, s));
    const { res } = await check(app, 9);
    expect(res.statusCode).toBe(200);
  });

  it("learns the baseline only from allowed decisions (blocked tx does not teach)", async () => {
    const built = await build();
    app = built.app;
    await check(app, 10, { to: SHADY });
    expect(built.store.peek("agent-A")?.observedCount).toBe(0);
    expect(built.store.peek("agent-A")?.verdictHistory[0]?.verdict).toBe("block");
  });

  it("the server works without behavior/reputation injected (rules absent from policy)", async () => {
    app = await createServer({
      engine: new FakeEngine(),
      adapters: { evm: new FakeAdapter("evm") },
      policies: new Map([[conservativeDefaultPolicy.id, conservativeDefaultPolicy]]),
      audit: new InMemoryAuditStore(),
      logger: false,
      rateLimit: false,
      env: "test",
    });
    const { res, decision } = await check(app, 11);
    expect(res.statusCode).toBe(200);
    expect(decision.verdict).toBe("allow");
  });

  it("a policy that references the custom rules while the engine lacks them escalates (engine_error), never allows", async () => {
    const s = stack();
    const engine = new PolicyEngine(); // no custom rules registered
    ({ app } = await build({ engine }, s));
    const { decision } = await check(app, 12);
    expect(decision.verdict).toBe("escalate");
    expect(decision.findings.map((f) => f.ruleId)).toContain("engine_error");
  });

  it("buildReputationUrl percent-encodes substitutions", () => {
    expect(buildReputationUrl("https://x.test/{chain}/{chainId}/{address}", "evm", "0xAb/../?x", 1)).toBe("https://x.test/evm/1/0xAb%2F..%2F%3Fx");
    expect(buildReputationUrl("https://x.test/{address}", "solana", "abc")).toBe("https://x.test/abc");
  });
});
