import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { AuditRecord, Decision } from "@signhold/core";
import { InMemoryAuditStore } from "../src/audit.js";
import { AdapterUnavailableError, CircuitBreakerAdapter } from "../src/breaker.js";
import { createServer } from "../src/server.js";
import type { AuditStore, ServerOptions } from "../src/types.js";
import { FakeAdapter, FakeEngine, okSimulation, requestBody, testPolicy } from "./fakes.js";

async function build(opts: Partial<ServerOptions> = {}) {
  const app = await createServer({
    engine: new FakeEngine(),
    adapters: { evm: new FakeAdapter("evm") },
    policies: new Map([[testPolicy.id, testPolicy]]),
    audit: new InMemoryAuditStore(),
    logger: false,
    rateLimit: false,
    env: "test",
    ...opts,
  });
  return app;
}

/**
 * Exhaustive matrix: every component that can fail (adapter, engine, breaker,
 * malformed outputs, audit store) in every failure mode (throw, reject with
 * non-Error, return garbage, hang past timeout). None may produce `allow`.
 */
describe("fail closed: no code path returns allow on exception", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  const throwers: Array<[string, () => never]> = [
    ["Error", () => { throw new Error("boom"); }],
    ["string", () => { throw "boom"; }],
    ["null", () => { throw null; }],
    ["object with verdict allow", () => { throw { verdict: "allow" }; }],
  ];

  for (const [name, thrower] of throwers) {
    it(`adapter throwing ${name} => escalate (simulation_error)`, async () => {
      app = await build({ adapters: { evm: new FakeAdapter("evm", async () => thrower()) } });
      const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
      expect(res.statusCode).toBe(200);
      expect(res.json().decision.verdict).toBe("escalate");
      expect(res.json().decision.findings[0].ruleId).toBe("simulation_error");
      expect(res.json().decision.riskScore).toBe(100);
    });

    it(`engine throwing ${name} => escalate (engine_error)`, async () => {
      app = await build({ engine: new FakeEngine(async () => thrower()) });
      const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
      expect(res.json().decision.verdict).toBe("escalate");
      expect(res.json().decision.findings[0].ruleId).toBe("engine_error");
    });
  }

  it("adapter throwing synchronously (not a rejected promise) => escalate", async () => {
    const evm = { chain: "evm" as const, simulate: () => { throw new Error("sync"); } };
    app = await build({ adapters: { evm } });
    expect((await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() })).json().decision.verdict).toBe("escalate");
  });

  const garbage: Array<[string, unknown]> = [
    ["undefined", undefined],
    ["null", null],
    ["string", "allow"],
    ["object missing deltas", { ok: true }],
  ];
  for (const [name, value] of garbage) {
    it(`adapter returning ${name} => escalate`, async () => {
      app = await build({ adapters: { evm: new FakeAdapter("evm", async () => value as never) } });
      const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
      expect(res.json().decision.verdict).toBe("escalate");
    });
  }

  const badDecisions: Array<[string, (d: Decision) => unknown]> = [
    ["undefined", () => undefined],
    ["null", () => null],
    ["verdict typo", (d) => ({ ...d, verdict: "allowed" })],
    ["wrong intentId", (d) => ({ ...d, intentId: "ffffffff-ffff-4fff-8fff-ffffffffffff" })],
    ["NaN riskScore", (d) => ({ ...d, riskScore: Number.NaN })],
    ["riskScore > 100", (d) => ({ ...d, riskScore: 101 })],
    ["findings not array", (d) => ({ ...d, findings: null })],
  ];
  for (const [name, mutate] of badDecisions) {
    it(`engine returning malformed decision (${name}) => escalate (invalid_decision)`, async () => {
      const inner = new FakeEngine("allow");
      const engine = { evaluate: async (i: Parameters<FakeEngine["evaluate"]>[0]) => mutate(await inner.evaluate(i)) as Decision };
      app = await build({ engine });
      const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
      expect(res.statusCode).toBe(200);
      expect(res.json().decision.verdict).toBe("escalate");
      expect(res.json().decision.findings[0].ruleId).toBe("invalid_decision");
    });
  }

  it("adapter hanging past the call timeout => escalate", async () => {
    const evm = new FakeAdapter("evm", () => new Promise(() => undefined));
    app = await build({ adapters: { evm }, circuitBreaker: { callTimeoutMs: 20 } });
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
    expect(res.json().decision.verdict).toBe("escalate");
    expect(res.json().decision.findings[0].message).toMatch(/AdapterTimeoutError/);
  });

  it("audit store failing => 503, never a verdict the agent could act on", async () => {
    const audit: AuditStore = {
      record: async () => { throw new Error("disk full"); },
      get: async () => undefined,
      list: async () => ({ items: [] }),
      range: async () => [],
      headIntegrity: async () => undefined,
    };
    app = await build({ audit });
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
    expect(res.statusCode).toBe(503);
    expect(res.json().error).toBe("audit_unavailable");
    expect(JSON.stringify(res.json())).not.toContain("allow");
    expect(JSON.stringify(res.json())).not.toContain("disk full");
  });

  it("error findings never leak stack traces or nested data", async () => {
    const err = Object.assign(new Error("rpc down"), { stack: "SECRET_STACK", config: { apiKey: "SECRET_KEY" } });
    app = await build({ adapters: { evm: new FakeAdapter("evm", async () => { throw err; }) } });
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
    const text = JSON.stringify(res.json());
    expect(text).not.toContain("SECRET_STACK");
    expect(text).not.toContain("SECRET_KEY");
    expect(text).toContain("rpc down");
  });

  it("escalated fail-closed decisions are still audited", async () => {
    const audit = new InMemoryAuditStore();
    app = await build({ audit, adapters: { evm: new FakeAdapter("evm", async () => { throw new Error("x"); }) } });
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
    const rec = (await audit.get(res.json().auditId)) as AuditRecord;
    expect(rec.decision.verdict).toBe("escalate");
    expect(rec.integrity?.seq).toBe(0);
  });
});

describe("circuit breaker", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("opens after N consecutive failures, rejects fast, then half-opens after the reset timeout", async () => {
    let t = 0;
    let fail = true;
    let calls = 0;
    const inner = new FakeAdapter("evm", async () => {
      calls++;
      if (fail) throw new Error("rpc");
      return okSimulation();
    });
    const states: string[] = [];
    const cb = new CircuitBreakerAdapter(inner, { failureThreshold: 3, resetTimeoutMs: 1000, callTimeoutMs: 0, now: () => t, onStateChange: (s) => states.push(s) });
    const intent = { id: "x", chain: "evm" as const, from: "0x" };
    for (let i = 0; i < 3; i++) await expect(cb.simulate(intent)).rejects.toThrow("rpc");
    expect(cb.currentState).toBe("open");
    await expect(cb.simulate(intent)).rejects.toBeInstanceOf(AdapterUnavailableError);
    expect(calls).toBe(3); // no call reached the adapter while open
    t = 1000;
    fail = false;
    expect(await cb.simulate(intent)).toEqual(okSimulation()); // trial call succeeds
    expect(cb.currentState).toBe("closed");
    expect(states).toEqual(["open", "half_open", "closed"]);

    // A failed trial re-opens immediately.
    fail = true;
    for (let i = 0; i < 3; i++) await expect(cb.simulate(intent)).rejects.toThrow("rpc");
    t = 2000;
    await expect(cb.simulate(intent)).rejects.toThrow("rpc");
    expect(cb.currentState).toBe("open");
  });

  it("server escalates with reason adapter_unavailable while the circuit is open", async () => {
    const evm = new FakeAdapter("evm", async () => { throw new Error("rpc"); });
    app = await build({ adapters: { evm }, circuitBreaker: { failureThreshold: 2, resetTimeoutMs: 60_000 } });
    const verdicts: string[] = [];
    const reasons: string[] = [];
    for (let i = 0; i < 4; i++) {
      const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
      verdicts.push(res.json().decision.verdict);
      reasons.push(res.json().decision.findings[0].ruleId);
    }
    expect(verdicts).toEqual(["escalate", "escalate", "escalate", "escalate"]);
    expect(reasons).toEqual(["simulation_error", "simulation_error", "adapter_unavailable", "adapter_unavailable"]);
    expect(evm.calls).toHaveLength(2);
  });
});
