import { randomUUID } from "node:crypto";
import Fastify, { LogController, type FastifyBaseLogger, type FastifyInstance, type FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import type { ApprovalStatusResponse, AuditPrincipal, AuditRecord, ChainAdapter, CheckResponse, Decision, SimulationResult } from "@signhold/core";
import { computeApprovalChallenge, nowIso } from "@signhold/core";
import { ApproverRegistry, DEFAULT_APPROVAL_CLOCK_SKEW_MS, PendingApprovalStore, verifyApprovalSubmission, type ApprovalRejectionReason } from "./approvals.js";
import { ApiKeyring, NonceCache, type SignatureInput } from "./auth.js";
import { AdapterUnavailableError, CircuitBreakerAdapter } from "./breaker.js";
import { verifyChain } from "./integrity.js";
import { createRedactingLogger } from "./logger.js";
import { parseApprovalSubmission, parseCheckRequest, sanitizeReason, stringifyWithBigints } from "./serialization.js";
import type { ServerOptions } from "./types.js";

declare module "fastify" {
  interface FastifyRequest {
    principal: AuditPrincipal;
    rawBody?: string;
  }
}

const DEFAULTS = {
  bodyLimit: 64 * 1024,
  rateLimit: { max: 120, timeWindowMs: 60_000 },
  signingWindowMs: 5 * 60_000,
  shutdownGraceMs: 10_000,
} as const;

const auditListQuerySchema = z
  .object({
    agentId: z.string().min(1).max(128).optional(),
    limit: z.coerce.number().int().min(1).max(500).default(50),
    cursor: z.string().max(32).regex(/^\d+$/).optional(),
  })
  .strict();

const auditVerifyQuerySchema = z
  .object({
    from: z.coerce.number().int().min(0).default(0),
    to: z.coerce.number().int().min(0).optional(),
    requireSignatures: z
      .enum(["true", "false"])
      .optional()
      .transform((v) => v === "true"),
  })
  .strict();

const auditIdParamSchema = z.string().uuid();

const VERDICTS = new Set(["allow", "block", "escalate"]);

function emptySimulation(reason: string): SimulationResult {
  return { ok: false, revertReason: reason, deltas: [], approvals: [], contractsTouched: [], newContracts: [], warnings: [] };
}

type FailReason = "engine_error" | "simulation_error" | "adapter_unavailable" | "invalid_decision" | "reputation_error" | "behavior_error";

function failClosedDecision(
  intentId: string,
  policy: { id: string; version: number } | undefined,
  ruleId: FailReason,
  message: string,
  simulation?: SimulationResult,
): Decision {
  return {
    intentId,
    verdict: "escalate",
    findings: [{ ruleId, kind: "custom", verdict: "escalate", message }],
    riskScore: 100,
    explanation: `Escalated because Signhold could not complete the check: ${message}`,
    simulation,
    policyId: policy?.id ?? "unknown",
    policyVersion: policy?.version ?? 0,
    evaluatedAt: nowIso(),
  };
}

/** Short, non-sensitive description of an error for findings. Never includes stack or nested data. */
function safeReason(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`.slice(0, 200);
  return typeof err === "string" ? err.slice(0, 200) : "non-error thrown";
}

/** Reject engine output that is not a well-formed Decision; anything odd escalates. */
function validateDecision(d: unknown, intentId: string): d is Decision {
  if (!d || typeof d !== "object") return false;
  const x = d as Partial<Decision>;
  return (
    typeof x.verdict === "string" &&
    VERDICTS.has(x.verdict) &&
    typeof x.riskScore === "number" &&
    Number.isFinite(x.riskScore) &&
    x.riskScore >= 0 &&
    x.riskScore <= 100 &&
    Array.isArray(x.findings) &&
    typeof x.explanation === "string" &&
    x.intentId === intentId
  );
}

function headerValue(req: FastifyRequest, name: string): string | undefined {
  const h = req.headers[name];
  return Array.isArray(h) ? h[0] : h;
}

export async function createServer(opts: ServerOptions): Promise<FastifyInstance> {
  const env = opts.env ?? process.env.NODE_ENV ?? "development";
  const isProd = env === "production";

  const keyring = new ApiKeyring(opts.apiKeys ?? []);
  if (keyring.size === 0 && isProd) {
    throw new Error("refusing to start in production without API keys (set SIGNHOLD_API_KEYS)");
  }

  const loggerOpt = opts.logger ?? true;
  const logger =
    loggerOpt === false
      ? undefined
      : createRedactingLogger(loggerOpt === true ? { level: "info" } : { level: loggerOpt.level ?? "info", stream: loggerOpt.stream, redactKeys: loggerOpt.redactKeys });

  const trustProxy = opts.trustProxy ?? false;
  const app = Fastify({
    loggerInstance: logger as FastifyBaseLogger | undefined,
    // We emit our own structured request logs below so bodies/calldata never reach info-level logs.
    logController: new LogController({ disableRequestLogging: true, requestIdLogLabel: "requestId" }),
    genReqId: () => randomUUID(),
    bodyLimit: opts.bodyLimit ?? DEFAULTS.bodyLimit,
    trustProxy: typeof trustProxy === "number" ? String(trustProxy) : trustProxy,
    forceCloseConnections: "idle",
    requestIdHeader: false, // never trust a client-supplied request id
  });

  if (keyring.size === 0) app.log.warn("SIGNHOLD_API_KEYS is not set: API key authentication is DISABLED");

  // ---- Human approval of escalations (I-HITL) ----
  // Approver keys are the only thing that can turn `escalate` into an approval, and
  // the server itself must not hold one: refuse any approver key that is also an audit
  // signing/verification key.
  const serverHeldKeyIds = new Set<string>(opts.auditPublicKeys?.keys() ?? []);
  const auditSignerKeyId = (opts.audit as { signerKeyId?: string }).signerKeyId;
  if (auditSignerKeyId) serverHeldKeyIds.add(auditSignerKeyId);
  const approvers = new ApproverRegistry(opts.approvers ?? [], { forbiddenKeyIds: serverHeldKeyIds });
  const pendingApprovals = new PendingApprovalStore({ ttlMs: opts.approvals?.ttlMs, maxPending: opts.approvals?.maxPending, now: opts.approvals?.now });
  const approvalsNow = opts.approvals?.now ?? Date.now;
  const approvalClockSkewMs = opts.approvals?.clockSkewMs ?? DEFAULT_APPROVAL_CLOCK_SKEW_MS;
  if (approvers.size > 0) app.log.info({ approverKeyIds: approvers.ids, ttlMs: pendingApprovals.ttlMs }, "human approval enabled: escalations carry a challenge for registered approver keys");
  else app.log.warn("SIGNHOLD_APPROVER_KEYS is not set: escalated transactions cannot be approved through the API");

  // ---- Adapters wrapped in circuit breakers ----
  const adapters: Partial<Record<string, ChainAdapter>> = {};
  for (const [chain, adapter] of Object.entries(opts.adapters)) {
    if (!adapter) continue;
    adapters[chain] =
      opts.circuitBreaker === false
        ? adapter
        : new CircuitBreakerAdapter(adapter, {
            ...opts.circuitBreaker,
            onStateChange: (state, c) => {
              app.log.warn({ chain: c, state }, "adapter circuit state changed");
              if (opts.circuitBreaker) opts.circuitBreaker.onStateChange?.(state, c);
            },
          });
  }

  // ---- Strict JSON body parsing; raw body retained for signature verification ----
  app.removeAllContentTypeParsers();
  app.addContentTypeParser("application/json", { parseAs: "string" }, (req, body, done) => {
    const text = body as string;
    req.rawBody = text;
    if (text.length === 0) return done(Object.assign(new Error("empty JSON body"), { statusCode: 400, code: "FST_ERR_CTP_EMPTY_JSON_BODY" }), undefined);
    try {
      done(null, JSON.parse(text));
    } catch {
      done(Object.assign(new Error("invalid JSON body"), { statusCode: 400, code: "FST_ERR_CTP_INVALID_JSON_BODY" }), undefined);
    }
  });

  // Every JSON reply goes through the bigint-aware serializer.
  app.setReplySerializer((payload) => stringifyWithBigints(payload));

  // ---- In-flight tracking for graceful shutdown ----
  let inFlight = 0;
  let closing = false;
  app.addHook("onRequest", async (req, reply) => {
    req.principal = { requestId: req.id as string, signed: false };
    reply.header("x-request-id", req.id as string);
    if (closing) {
      reply.header("connection", "close");
      return reply.code(503).send({ error: "shutting_down", message: "server is shutting down", requestId: req.id });
    }
    inFlight++;
  });
  app.addHook("onResponse", async () => {
    inFlight = Math.max(0, inFlight - 1);
  });
  app.addHook("preClose", async () => {
    closing = true;
    const grace = opts.shutdownGraceMs ?? DEFAULTS.shutdownGraceMs;
    const deadline = Date.now() + grace;
    while (inFlight > 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 10));
    if (inFlight > 0) app.log.warn({ inFlight }, "shutdown grace period elapsed with requests still in flight");
  });

  // ---- Identify API key early (no rejection yet) so rate limiting can key on it ----
  app.addHook("onRequest", async (req) => {
    if (keyring.size === 0) return;
    const id = keyring.identify(headerValue(req, "x-api-key"));
    if (id) req.principal.apiKeyId = id;
  });

  // ---- Rate limiting (on by default, per key; per IP when unauthenticated) ----
  if (opts.rateLimit !== false) {
    const rl = opts.rateLimit ?? DEFAULTS.rateLimit;
    const rateLimit = (await import("@fastify/rate-limit")).default;
    await app.register(rateLimit, {
      max: rl.max,
      timeWindow: rl.timeWindowMs,
      keyGenerator: (req) => (req.principal?.apiKeyId ? `key:${req.principal.apiKeyId}` : `ip:${req.ip}`),
      errorResponseBuilder: (req, ctx) => ({
        statusCode: 429,
        error: "rate_limited",
        message: `rate limit exceeded, retry in ${ctx.after}`,
        retryAfter: Math.ceil(ctx.ttl / 1000),
        requestId: req.id,
      }),
    });
  }

  // ---- Auth enforcement (preParsing: after the route-level rate-limit hook, before any body is read) ----
  app.addHook("preParsing", async (req, reply) => {
    if (keyring.size === 0 || req.url === "/healthz") return;
    if (!req.principal.apiKeyId) {
      return reply.code(401).send({ error: "unauthorized", message: "missing or invalid x-api-key", requestId: req.id });
    }
  });

  // ---- HMAC request signing ----
  const signingWindow = opts.signing?.windowMs ?? DEFAULTS.signingWindowMs;
  const nonces = new NonceCache(signingWindow, opts.signing?.nonceCacheSize);
  app.addHook("preValidation", async (req, reply) => {
    if (keyring.size === 0 || req.url === "/healthz") return;
    const sig = headerValue(req, "x-signhold-signature");
    const ts = headerValue(req, "x-signhold-timestamp");
    const nonce = headerValue(req, "x-signhold-nonce");
    const reject = (message: string) => reply.code(401).send({ error: "invalid_signature", message, requestId: req.id });
    if (!sig && !ts && !nonce) {
      if (opts.signing?.required) return reject("request signature required");
      return;
    }
    if (!sig || !ts || !nonce) return reject("x-signhold-signature, x-signhold-timestamp and x-signhold-nonce are all required");
    if (!/^\d{1,16}$/.test(ts)) return reject("invalid timestamp");
    if (!/^[A-Za-z0-9_-]{8,128}$/.test(nonce)) return reject("invalid nonce");
    const skew = Math.abs(Date.now() - Number(ts));
    if (skew > signingWindow) return reject("timestamp outside the accepted window");
    const keyId = req.principal.apiKeyId!;
    const input: SignatureInput = { timestamp: ts, nonce, method: req.method, path: req.url, body: req.rawBody ?? "" };
    if (!keyring.verifySignature(keyId, sig, input)) return reject("signature mismatch");
    if (!nonces.consume(`${keyId}:${nonce}`)) return reject("nonce already used");
    req.principal.signed = true;
  });

  // ---- Security headers / CORS ----
  const corsOrigins = opts.cors ? new Set(opts.cors.origins) : undefined;
  app.addHook("onSend", async (req, reply) => {
    reply.removeHeader("x-powered-by");
    reply.header("x-content-type-options", "nosniff");
    reply.header("x-frame-options", "DENY");
    reply.header("cache-control", "no-store");
    reply.header("referrer-policy", "no-referrer");
    reply.header("content-security-policy", "default-src 'none'; frame-ancestors 'none'");
    if (corsOrigins) {
      const origin = headerValue(req, "origin");
      if (origin && corsOrigins.has(origin)) {
        reply.header("access-control-allow-origin", origin);
        reply.header("vary", "origin");
        reply.header("access-control-allow-methods", "GET, POST, OPTIONS");
        reply.header("access-control-allow-headers", "content-type, x-api-key, x-signhold-signature, x-signhold-timestamp, x-signhold-nonce");
        reply.header("access-control-max-age", "600");
      }
    }
  });
  if (corsOrigins) {
    app.options("/*", async (_req, reply) => reply.code(204).send());
  }

  // ---- Structured request logging (no bodies) ----
  app.addHook("onResponse", async (req, reply) => {
    req.log.info(
      {
        method: req.method,
        path: req.routeOptions?.url ?? req.url.split("?")[0],
        statusCode: reply.statusCode,
        durationMs: Math.round(reply.elapsedTime),
        apiKeyId: req.principal?.apiKeyId,
        signed: req.principal?.signed ?? false,
      },
      "request completed",
    );
  });

  // ---- Errors: never leak internals; always JSON with a correlation id ----
  app.setNotFoundHandler((req, reply) => {
    void reply.code(404).send({ error: "not_found", message: "route not found", requestId: req.id });
  });
  app.setErrorHandler((err, req, reply) => {
    const requestId = req.id;
    if (err instanceof ZodError) {
      const issues = err.issues.slice(0, 50).map((i) => ({ path: i.path.join("."), code: i.code, message: i.message }));
      return reply.code(400).send({ error: "bad_request", message: "invalid request body", issues, requestId });
    }
    const e = err as { statusCode?: number; code?: string; message?: string };
    const status = e.statusCode ?? 500;
    if (status >= 500) {
      req.log.error({ err, requestId }, "unhandled error");
      return reply.code(500).send({ error: "internal_error", message: "internal server error", requestId });
    }
    const map: Record<number, string> = { 400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 413: "payload_too_large", 415: "unsupported_media_type", 429: "rate_limited" };
    const code = e.code ?? "";
    const message =
      code === "FST_ERR_CTP_BODY_TOO_LARGE"
        ? "request body too large"
        : code === "FST_ERR_CTP_INVALID_MEDIA_TYPE"
          ? "content-type must be application/json"
          : code.startsWith("FST_ERR_CTP")
            ? "invalid JSON body"
            : status === 429
              ? (e.message ?? "rate limit exceeded")
              : (map[status] ?? "request rejected");
    const body: Record<string, unknown> = { error: map[status] ?? "bad_request", message, requestId };
    if (status === 429 && typeof (e as { retryAfter?: number }).retryAfter === "number") body.retryAfter = (e as { retryAfter: number }).retryAfter;
    return reply.code(status).send(body);
  });

  // ---- Routes ----
  app.get("/healthz", async () => ({
    ok: true,
    chains: Object.keys(adapters),
    policies: [...opts.policies.keys()],
  }));

  app.post("/v1/check", async (req, reply) => {
    const body = parseCheckRequest(req.body);
    const { intent, context } = body;

    const policyId = body.policyId ?? opts.defaultPolicyId ?? opts.policies.keys().next().value;
    const policy = policyId !== undefined ? opts.policies.get(policyId) : undefined;
    if (body.policyId !== undefined && !policy) {
      return reply.code(404).send({ error: "policy_not_found", message: "unknown policy", requestId: req.id });
    }
    if (!policy) {
      return reply.code(503).send({ error: "no_policy", message: "server has no policy configured", requestId: req.id });
    }

    const adapter = adapters[intent.chain];
    if (!adapter) {
      return reply.code(400).send({ error: "unsupported_chain", message: `no adapter for chain '${intent.chain}'`, requestId: req.id });
    }

    req.log.info(
      { intentId: intent.id, chain: intent.chain, chainId: intent.chainId, from: intent.from, to: intent.to, agentId: context.agentId, policyId, apiKeyId: req.principal.apiKeyId },
      "check received",
    );
    // Raw calldata / serialized tx is only visible at debug level (and redacted above it regardless).
    req.log.debug({ intentId: intent.id, data: intent.data, raw: intent.raw }, "check payload");

    // Fail closed: every exception below ends in `escalate`; no path returns `allow` on error.
    let decision: Decision | undefined;
    let simulation: SimulationResult | undefined;
    try {
      simulation = await adapter.simulate(intent);
      if (!simulation || typeof simulation !== "object" || typeof simulation.ok !== "boolean" || !Array.isArray(simulation.deltas)) {
        throw new TypeError("adapter returned a malformed SimulationResult");
      }
    } catch (err) {
      const reason = safeReason(err);
      if (err instanceof AdapterUnavailableError) {
        req.log.warn({ intentId: intent.id, chain: intent.chain, state: err.state }, "adapter circuit open; escalating");
        decision = failClosedDecision(intent.id, policy, "adapter_unavailable", reason, emptySimulation(reason));
      } else {
        req.log.error({ err, intentId: intent.id }, "adapter threw during simulate");
        decision = failClosedDecision(intent.id, policy, "simulation_error", reason, emptySimulation(reason));
      }
    }

    // Warm the synchronous caches the custom rules read (reputation + behavior). The
    // engine evaluates rules synchronously, so both MUST complete before evaluate().
    // Any failure here is a fail-closed condition: evaluate still runs (so blocking
    // rules keep blocking) but the verdict can never be `allow`.
    const preFailures: Array<{ ruleId: FailReason; message: string }> = [];
    if (!decision && simulation && opts.reputation) {
      try {
        await opts.reputation.prefetch(intent, simulation);
      } catch (err) {
        req.log.error({ err, intentId: intent.id }, "reputation prefetch failed; escalating");
        preFailures.push({ ruleId: "reputation_error", message: `reputation lookup failed: ${safeReason(err)}` });
      }
    }
    if (!decision && simulation && opts.behavior) {
      try {
        await opts.behavior.store.get(context.agentId);
      } catch (err) {
        req.log.error({ err, intentId: intent.id }, "behavior profile load failed; escalating");
        preFailures.push({ ruleId: "behavior_error", message: `behavior profile unavailable: ${safeReason(err)}` });
      }
    }

    if (!decision && simulation) {
      try {
        const out: unknown = await opts.engine.evaluate({ intent, simulation, context, policy });
        if (!validateDecision(out, intent.id)) {
          req.log.error({ intentId: intent.id }, "engine returned a malformed decision");
          decision = failClosedDecision(intent.id, policy, "invalid_decision", "engine returned a malformed decision", simulation);
        } else {
          decision = out;
        }
      } catch (err) {
        // Engines must not throw (ARCHITECTURE.md); guard anyway and fail closed.
        req.log.error({ err, intentId: intent.id }, "engine threw during evaluate");
        decision = failClosedDecision(intent.id, policy, "engine_error", safeReason(err), simulation);
      }
    }
    if (!decision) decision = failClosedDecision(intent.id, policy, "engine_error", "no decision produced", simulation);

    if (preFailures.length > 0 && decision.verdict !== "block") {
      // Keep the engine's findings (so operators see what else fired) but force escalate.
      decision = {
        ...decision,
        verdict: "escalate",
        riskScore: Math.max(decision.riskScore, 50),
        findings: [...preFailures.map((f) => ({ ruleId: f.ruleId, kind: "custom" as const, verdict: "escalate" as const, message: f.message })), ...decision.findings],
        explanation: `Escalated because Signhold could not complete the check: ${preFailures.map((f) => f.message).join("; ")}. ${decision.explanation}`,
      };
    }

    const principal: AuditPrincipal = { ...req.principal };
    const record: AuditRecord = { id: randomUUID(), type: "check", intent, decision, context, recordedAt: nowIso(), principal };

    // Escalations get a challenge bound to this very record (auditId, intent, decision,
    // policy, agent, issue time). It is sealed into the chain *before* the agent sees it,
    // so the agent cannot later claim a different transaction was what the human approved.
    if (decision.verdict === "escalate" && approvers.size > 0) {
      const issuedAtMs = approvalsNow();
      const issuedAt = new Date(issuedAtMs).toISOString();
      const expiresAt = new Date(issuedAtMs + pendingApprovals.ttlMs).toISOString();
      const challenge = computeApprovalChallenge({
        auditId: record.id,
        intent,
        decision,
        policyId: decision.policyId,
        policyVersion: decision.policyVersion,
        agentId: context.agentId,
        issuedAt,
      });
      record.approvalRequest = { challenge, issuedAt, expiresAt };
    }

    let sealed: AuditRecord;
    try {
      sealed = await opts.audit.record(record);
    } catch (err) {
      // The audit trail is part of the product guarantee: no record, no verdict.
      req.log.error({ err, intentId: intent.id }, "audit store failed to record");
      return reply.code(503).send({ error: "audit_unavailable", message: "decision could not be recorded; transaction must not proceed", requestId: req.id });
    }
    if (sealed.approvalRequest) {
      // Only a sealed record can be approved: the pending entry is created after the audit write.
      pendingApprovals.issue({ auditId: sealed.id, challenge: sealed.approvalRequest.challenge, issuedAt: sealed.approvalRequest.issuedAt, expiresAt: sealed.approvalRequest.expiresAt, agentId: context.agentId });
    }

    // Fold the outcome into the agent's behavioral baseline. Awaited so tests and
    // callers observe a consistent profile, but a failure here must never change
    // the (already audited) verdict: log and continue.
    const simForProfile = simulation ?? sealed.decision.simulation;
    if (opts.behavior && simForProfile) {
      try {
        // `context.now` is the clock the analyzer scored with; keep the baseline on the same clock.
        await opts.behavior.persist(context.agentId, intent, simForProfile, sealed.decision, { at: context.now instanceof Date ? context.now : undefined });
      } catch (err) {
        req.log.error({ err, intentId: intent.id, agentId: context.agentId }, "behavior profile update failed; verdict unaffected");
      }
    }

    req.log.info(
      { intentId: intent.id, auditId: sealed.id, auditSeq: sealed.integrity?.seq, verdict: sealed.decision.verdict, riskScore: sealed.decision.riskScore, findings: sealed.decision.findings.length, apiKeyId: principal.apiKeyId },
      "check decided",
    );

    const response: CheckResponse = { decision: sealed.decision, auditId: sealed.id };
    if (sealed.approvalRequest) response.approval = { challenge: sealed.approvalRequest.challenge, expiresAt: sealed.approvalRequest.expiresAt };
    return response;
  });

  // ---- Human approval (I-HITL): the only path from `escalate` to an approval ----
  // The caller is whoever holds a registered approver private key, which the agent
  // process never does. Every failure is a generic 403 (no oracle); the reason goes
  // to the log and to an `approval_rejected` audit record.
  const approvalRejectedBody = (requestId: string) => ({ error: "approval_rejected", message: "approval could not be verified", requestId });

  app.post("/v1/approvals", async (req, reply) => {
    const body = parseApprovalSubmission(req.body);
    const now = approvalsNow();
    const pending = pendingApprovals.get(body.auditId);
    const record = await opts.audit.get(body.auditId);
    const reasons: ApprovalRejectionReason[] = verifyApprovalSubmission(body, { pending, record, registry: approvers, now, clockSkewMs: approvalClockSkewMs });

    // Claim is synchronous and single-use: two concurrent valid submissions cannot both win.
    const claimed = reasons.length === 0 ? pendingApprovals.claim(body.auditId, { keyId: body.keyId, approvedAt: body.approvedAt }) : undefined;
    if (reasons.length === 0 && !claimed) reasons.push("already_used");

    const reason = sanitizeReason(body.reason);
    const principal: AuditPrincipal = { ...req.principal, approverKeyId: body.keyId };

    if (reasons.length > 0 || !claimed || !record) {
      req.log.warn({ auditId: body.auditId, keyId: body.keyId, reasons, apiKeyId: req.principal.apiKeyId }, "approval rejected");
      // Fail closed: a challenge that saw an invalid attempt is burned. A fresh check is required.
      if (pending && pendingApprovals.status(body.auditId).status === "pending") pendingApprovals.reject(body.auditId);
      if (record) {
        const rejected: AuditRecord = {
          id: randomUUID(),
          type: "approval_rejected",
          intent: record.intent,
          decision: record.decision,
          context: record.context,
          recordedAt: nowIso(),
          principal,
          approval: {
            checkAuditId: record.id,
            challenge: pending?.challenge ?? record.approvalRequest?.challenge ?? "",
            outcome: "rejected",
            approverKeyId: body.keyId,
            reason,
            rejectionReason: reasons.join(","),
          },
        };
        try {
          await opts.audit.record(rejected);
        } catch (err) {
          req.log.error({ err, auditId: body.auditId }, "audit store failed to record approval rejection");
          return reply.code(503).send({ error: "audit_unavailable", message: "approval could not be recorded", requestId: req.id });
        }
      }
      return reply.code(403).send(approvalRejectedBody(req.id));
    }

    const approvalRecord: AuditRecord = {
      id: randomUUID(),
      type: "approval",
      intent: record.intent,
      decision: record.decision,
      context: record.context,
      recordedAt: nowIso(),
      principal,
      approval: {
        checkAuditId: record.id,
        challenge: claimed.challenge,
        outcome: "approved",
        approvalId: claimed.approvalId,
        approverKeyId: body.keyId,
        approvedAt: body.approvedAt,
        reason,
      },
    };
    let sealed: AuditRecord;
    try {
      sealed = await opts.audit.record(approvalRecord);
    } catch (err) {
      // No record, no approval: the claim is burned rather than reopened.
      pendingApprovals.invalidate(body.auditId);
      req.log.error({ err, auditId: body.auditId }, "audit store failed to record approval");
      return reply.code(503).send({ error: "audit_unavailable", message: "approval could not be recorded; transaction must not proceed", requestId: req.id });
    }
    req.log.info({ auditId: body.auditId, approvalId: claimed.approvalId, approvalAuditId: sealed.id, approverKeyId: body.keyId, apiKeyId: req.principal.apiKeyId }, "approval verified");
    return { verdict: "allow" as const, approvalId: claimed.approvalId, auditId: body.auditId, approvalAuditId: sealed.id };
  });

  // Read-only: the agent polls this; nothing here changes state.
  app.get<{ Params: { auditId: string } }>("/v1/approvals/:auditId", async (req, reply) => {
    const id = auditIdParamSchema.safeParse(req.params.auditId);
    if (!id.success) return reply.code(404).send({ error: "not_found", message: "approval not found", requestId: req.id });
    const { status, entry } = pendingApprovals.status(id.data);
    const out: ApprovalStatusResponse = { auditId: id.data, status };
    if (entry) {
      out.expiresAt = entry.expiresAt;
      if (status === "approved") {
        out.approvedBy = entry.approvedBy;
        out.approvalId = entry.approvalId;
        out.approvedAt = entry.approvedAt;
      }
    }
    return out;
  });

  app.get("/v1/audit/verify", async (req, reply) => {
    const q = auditVerifyQuerySchema.parse(req.query);
    const head = await opts.audit.headIntegrity();
    const to = q.to ?? head?.seq ?? -1;
    if (q.to !== undefined && q.to < q.from) {
      return reply.code(400).send({ error: "bad_request", message: "`to` must be >= `from`", requestId: req.id });
    }
    const records = await opts.audit.range(q.from, to);
    const result = verifyChain(records, { publicKeys: opts.auditPublicKeys, requireSignatures: q.requireSignatures });
    return { ...result, from: q.from, to, headSeq: head?.seq, headHash: head?.hash };
  });

  app.get<{ Params: { id: string } }>("/v1/audit/:id", async (req, reply) => {
    const id = auditIdParamSchema.safeParse(req.params.id);
    if (!id.success) return reply.code(404).send({ error: "not_found", message: "audit record not found", requestId: req.id });
    const rec = await opts.audit.get(id.data);
    if (!rec) return reply.code(404).send({ error: "not_found", message: "audit record not found", requestId: req.id });
    return rec;
  });

  app.get("/v1/audit", async (req) => {
    const q = auditListQuerySchema.parse(req.query);
    return opts.audit.list(q);
  });

  return app;
}
