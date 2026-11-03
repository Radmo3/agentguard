import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { createServer } from "../src/server.js";
import { InMemoryAuditStore } from "../src/audit.js";
import { FROM, INTENT_ID, FakeAdapter, FakeEngine, intentId, requestBody, testPolicy } from "./fakes.js";

async function build(opts: Partial<Parameters<typeof createServer>[0]> = {}) {
  const engine = new FakeEngine();
  const evm = new FakeAdapter("evm");
  const audit = new InMemoryAuditStore();
  const app = await createServer({
    engine,
    adapters: { evm },
    policies: new Map([[testPolicy.id, testPolicy]]),
    audit,
    logger: false,
    rateLimit: false,
    ...opts,
  });
  return { app, engine, evm, audit };
}

describe("POST /v1/check", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("simulates, evaluates, records audit and returns bigints as strings", async () => {
    const built = await build();
    app = built.app;
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.decision.verdict).toBe("allow");
    expect(body.decision.policyId).toBe("test-policy");
    expect(body.decision.simulation.deltas[0].amount).toBe("-1000000000000000000");
    expect(body.decision.simulation.gasEstimate).toBe("21000");
    expect(typeof body.auditId).toBe("string");

    // bigint was revived before reaching the adapter / engine
    expect(built.evm.calls[0].value).toBe(1_000_000_000_000_000_000n);
    expect(built.engine.inputs[0].policy).toEqual(testPolicy);
    expect(built.engine.inputs[0].context.agentId).toBe("agent-A");

    const rec = await built.audit.get(body.auditId);
    expect(rec?.intent.id).toBe(INTENT_ID);
    expect(rec?.decision.verdict).toBe("allow");
  });

  it("rejects malformed bodies with 400 and zod issues", async () => {
    ({ app } = await build());
    const res = await app.inject({
      method: "POST",
      url: "/v1/check",
      payload: requestBody({ intent: { id: INTENT_ID, chain: "evm", from: FROM, value: "not-a-number" } }),
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("bad_request");
    expect(res.json().issues.length).toBeGreaterThan(0);
  });

  it("returns 400 for chains without an adapter", async () => {
    ({ app } = await build());
    const body = requestBody({
      intent: { id: INTENT_ID, chain: "solana", from: "7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDpvcMwJeK", raw: "AAAA" },
    });
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: body });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("unsupported_chain");
  });

  it("returns 404 for unknown policyId", async () => {
    ({ app } = await build());
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody({ policyId: "nope" }) });
    expect(res.statusCode).toBe(404);
  });

  it("fails closed with escalate when the adapter throws", async () => {
    const evm = new FakeAdapter("evm", async () => {
      throw new Error("rpc down");
    });
    ({ app } = await build({ adapters: { evm } }));
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
    expect(res.statusCode).toBe(200);
    const d = res.json().decision;
    expect(d.verdict).toBe("escalate");
    expect(d.findings[0].ruleId).toBe("simulation_error");
    expect(d.simulation.ok).toBe(false);
  });

  it("fails closed with escalate when the engine throws", async () => {
    const engine = new FakeEngine(async () => {
      throw new Error("boom");
    });
    ({ app } = await build({ engine }));
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
    expect(res.statusCode).toBe(200);
    expect(res.json().decision.verdict).toBe("escalate");
    expect(res.json().decision.findings[0].ruleId).toBe("engine_error");
  });

  it("passes block verdicts through", async () => {
    ({ app } = await build({ engine: new FakeEngine("block") }));
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
    expect(res.json().decision.verdict).toBe("block");
    expect(res.json().decision.findings[0].message).toBe("too big");
  });
});

describe("audit routes", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("GET /v1/audit/:id returns the record and 404 for unknown", async () => {
    ({ app } = await build());
    const created = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
    const id = created.json().auditId;
    const res = await app.inject({ method: "GET", url: `/v1/audit/${id}` });
    expect(res.statusCode).toBe(200);
    expect(res.json().id).toBe(id);
    expect(res.json().intent.value).toBe("1000000000000000000");
    expect((await app.inject({ method: "GET", url: "/v1/audit/missing" })).statusCode).toBe(404);
  });

  it("GET /v1/audit?agentId= filters and paginates newest first", async () => {
    ({ app } = await build());
    for (let i = 0; i < 5; i++) {
      const body = requestBody({ context: { agentId: i % 2 === 0 ? "even" : "odd" } });
      (body.intent as Record<string, unknown>).id = intentId(i);
      await app.inject({ method: "POST", url: "/v1/check", payload: body });
    }
    const p1 = await app.inject({ method: "GET", url: "/v1/audit?agentId=even&limit=2" });
    expect(p1.statusCode).toBe(200);
    expect(p1.json().items.map((r: { intent: { id: string } }) => r.intent.id)).toEqual([intentId(4), intentId(2)]);
    expect(p1.json().nextCursor).toBe("2");
    const p2 = await app.inject({ method: "GET", url: `/v1/audit?agentId=even&limit=2&cursor=${p1.json().nextCursor}` });
    expect(p2.json().items.map((r: { intent: { id: string } }) => r.intent.id)).toEqual([intentId(0)]);
    expect(p2.json().nextCursor).toBeUndefined();

    const all = await app.inject({ method: "GET", url: "/v1/audit" });
    expect(all.json().items).toHaveLength(5);
  });
});

describe("auth + health", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("GET /healthz works without auth", async () => {
    ({ app } = await build({ apiKeys: ["secret"] }));
    const res = await app.inject({ method: "GET", url: "/healthz" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ ok: true, chains: ["evm"], policies: ["test-policy"] });
  });

  it("requires x-api-key when keys are configured", async () => {
    ({ app } = await build({ apiKeys: ["secret", "other"] }));
    expect((await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() })).statusCode).toBe(401);
    expect((await app.inject({ method: "POST", url: "/v1/check", payload: requestBody(), headers: { "x-api-key": "wrong" } })).statusCode).toBe(401);
    expect((await app.inject({ method: "POST", url: "/v1/check", payload: requestBody(), headers: { "x-api-key": "other" } })).statusCode).toBe(200);
  });

  it("skips auth when no keys configured", async () => {
    ({ app } = await build({ apiKeys: [], env: "development" }));
    expect((await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() })).statusCode).toBe(200);
  });
});

describe("logging", () => {
  let app: FastifyInstance;
  beforeEach(() => void 0);
  afterEach(async () => app?.close());

  it("never logs raw calldata at info level", async () => {
    const lines: string[] = [];
    const stream = { write: (s: string) => void lines.push(s) };
    ({ app } = await build({ logger: { level: "info", stream } }));
    await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
    expect(lines.length).toBeGreaterThan(0);
    expect(lines.join("")).not.toContain("0xdeadbeef");
    expect(lines.join("")).toContain("check decided");
  });
});
