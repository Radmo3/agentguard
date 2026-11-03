import { randomUUID } from "node:crypto";
import Fastify, { LogController, type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import type { AuditRecord, CheckResponse, Decision, SimulationResult } from "@agentguard/core";
import { nowIso } from "@agentguard/core";
import { parseCheckRequest, stringifyWithBigints } from "./serialization.js";
import type { ServerOptions } from "./types.js";

const auditListQuerySchema = z.object({
  agentId: z.string().min(1).optional(),
  limit: z.coerce.number().int().min(1).max(500).default(50),
  cursor: z.string().optional(),
});

function emptySimulation(reason: string): SimulationResult {
  return {
    ok: false,
    revertReason: reason,
    deltas: [],
    approvals: [],
    contractsTouched: [],
    newContracts: [],
    warnings: [],
  };
}

function failClosedDecision(
  intentId: string,
  policy: { id: string; version: number } | undefined,
  ruleId: "engine_error" | "simulation_error",
  message: string,
  simulation?: SimulationResult,
): Decision {
  return {
    intentId,
    verdict: "escalate",
    findings: [{ ruleId, kind: "custom", verdict: "escalate", message }],
    riskScore: 100,
    explanation: `Escalated because AgentGuard could not complete the check: ${message}`,
    simulation,
    policyId: policy?.id ?? "unknown",
    policyVersion: policy?.version ?? 0,
    evaluatedAt: nowIso(),
  };
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export async function createServer(opts: ServerOptions): Promise<FastifyInstance> {
  const app = Fastify({
    logger: opts.logger ?? true,
    // We emit our own structured request logs below so calldata never reaches info-level logs.
    logController: new LogController({ disableRequestLogging: true }),
    genReqId: () => randomUUID(),
  });

  // Every JSON reply goes through the bigint-aware serializer.
  app.setReplySerializer((payload) => stringifyWithBigints(payload));

  const apiKeys = new Set((opts.apiKeys ?? []).map((k) => k.trim()).filter(Boolean));
  if (apiKeys.size === 0) {
    app.log.warn("AGENTGUARD_API_KEYS is not set: API key authentication is DISABLED");
  }

  if (opts.rateLimit) {
    const rateLimit = (await import("@fastify/rate-limit")).default;
    await app.register(rateLimit, { max: opts.rateLimit.max, timeWindow: opts.rateLimit.timeWindowMs });
  }

  // ---- Auth ----
  app.addHook("onRequest", async (req: FastifyRequest, reply: FastifyReply) => {
    if (apiKeys.size === 0 || req.url === "/healthz") return;
    const header = req.headers["x-api-key"];
    const key = Array.isArray(header) ? header[0] : header;
    if (!key || !apiKeys.has(key)) {
      return reply.code(401).send({ error: "unauthorized", message: "missing or invalid x-api-key" });
    }
  });

  // ---- Structured request logging (no bodies) ----
  app.addHook("onResponse", async (req, reply) => {
    req.log.info(
      {
        method: req.method,
        path: req.routeOptions?.url ?? req.url,
        statusCode: reply.statusCode,
        durationMs: Math.round(reply.elapsedTime),
      },
      "request completed",
    );
  });

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof ZodError) {
      return reply.code(400).send({ error: "bad_request", message: "invalid request body", issues: err.issues });
    }
    const e = err as { statusCode?: number; message?: string };
    const status = e.statusCode ?? 500;
    if (status >= 500) req.log.error({ err }, "unhandled error");
    return reply.code(status).send({
      error: status >= 500 ? "internal_error" : "bad_request",
      message: status >= 500 ? "internal server error" : (e.message ?? "bad request"),
    });
  });

  // ---- Routes ----
  app.get("/healthz", async () => ({
    ok: true,
    chains: Object.keys(opts.adapters),
    policies: [...opts.policies.keys()],
  }));

  app.post("/v1/check", async (req, reply) => {
    const body = parseCheckRequest(req.body);
    const { intent, context } = body;

    const policyId = body.policyId ?? opts.defaultPolicyId ?? opts.policies.keys().next().value;
    const policy = policyId !== undefined ? opts.policies.get(policyId) : undefined;
    if (body.policyId !== undefined && !policy) {
      return reply.code(404).send({ error: "policy_not_found", message: `unknown policy '${body.policyId}'` });
    }
    if (!policy) {
      return reply.code(503).send({ error: "no_policy", message: "server has no policy configured" });
    }

    const adapter = opts.adapters[intent.chain];
    if (!adapter) {
      return reply.code(400).send({ error: "unsupported_chain", message: `no adapter for chain '${intent.chain}'` });
    }

    req.log.info(
      { intentId: intent.id, chain: intent.chain, chainId: intent.chainId, from: intent.from, to: intent.to, agentId: context.agentId, policyId },
      "check received",
    );
    // Raw calldata / serialized tx is only visible at debug level.
    req.log.debug({ intentId: intent.id, data: intent.data, raw: intent.raw }, "check payload");

    let decision: Decision;
    let simulation: SimulationResult | undefined;
    try {
      simulation = await adapter.simulate(intent);
    } catch (err) {
      req.log.error({ err, intentId: intent.id }, "adapter threw during simulate");
      decision = failClosedDecision(intent.id, policy, "simulation_error", errorMessage(err), emptySimulation(errorMessage(err)));
    }

    if (simulation) {
      try {
        decision = await opts.engine.evaluate({ intent, simulation, context, policy });
      } catch (err) {
        // Engines must not throw (ARCHITECTURE.md); guard anyway and fail closed.
        req.log.error({ err, intentId: intent.id }, "engine threw during evaluate");
        decision = failClosedDecision(intent.id, policy, "engine_error", errorMessage(err), simulation);
      }
    }

    const record: AuditRecord = {
      id: randomUUID(),
      intent,
      decision: decision!,
      context,
      recordedAt: nowIso(),
    };
    await opts.audit.record(record);

    req.log.info(
      { intentId: intent.id, auditId: record.id, verdict: record.decision.verdict, riskScore: record.decision.riskScore, findings: record.decision.findings.length },
      "check decided",
    );

    const response: CheckResponse = { decision: record.decision, auditId: record.id };
    return response;
  });

  app.get<{ Params: { id: string } }>("/v1/audit/:id", async (req, reply) => {
    const rec = await opts.audit.get(req.params.id);
    if (!rec) return reply.code(404).send({ error: "not_found", message: "audit record not found" });
    return rec;
  });

  app.get("/v1/audit", async (req) => {
    const q = auditListQuerySchema.parse(req.query);
    return opts.audit.list(q);
  });

  return app;
}
