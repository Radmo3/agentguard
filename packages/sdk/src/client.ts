import type { AgentContext, ApprovalStatus, ApprovalStatusResponse, AuditRecord, CheckRequest, CheckResponse, TransactionIntent } from "@agentguard/core";
import { AgentGuardHttpError, AgentGuardNetworkError, AgentGuardProtocolError, AgentGuardTimeoutError, ApprovalDeniedError, ApprovalTimeoutError } from "./errors.js";
import { reviveCheckResponse, reviveContext, reviveDecision, reviveIntent, serializeRequest } from "./serialization.js";
import { signRequest, type RequestSigner } from "./signing.js";

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface AgentGuardClientOptions {
  baseUrl: string;
  apiKey?: string;
  /**
   * Enable HMAC request signing (`x-agentguard-signature`). `true` signs with
   * `apiKey`; a string uses a dedicated signing secret configured server-side
   * for this key. Requires `apiKey`.
   */
  signRequests?: boolean | string;
  /** Injectable signer (tests). Defaults to the built-in WebCrypto HMAC-SHA256 signer. */
  signer?: RequestSigner;
  /** Per-attempt timeout. Default 10_000ms. */
  timeoutMs?: number;
  /** Retries on 5xx / network errors. Default 2 (3 attempts total). */
  retries?: number;
  /** Base backoff; doubles per retry. Default 200ms. */
  retryBackoffMs?: number;
  /** Injectable fetch for tests. Defaults to global fetch. */
  fetch?: FetchLike;
  /** Default context fields merged under the per-call context. */
  defaultContext?: Partial<AgentContext>;
  /** Default policy id attached to every check unless overridden. */
  policyId?: string;
}

export interface CheckOptions {
  policyId?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface AuditPage {
  items: AuditRecord[];
  nextCursor?: string;
}

export interface WaitForApprovalOptions {
  /** Give up after this long. Default 15 minutes (the server's default approval TTL). */
  timeoutMs?: number;
  /** Poll interval. Default 2 s. */
  intervalMs?: number;
  signal?: AbortSignal;
  /** Called after every poll (observability only; the return value is ignored). */
  onPoll?: (status: ApprovalStatusResponse) => void;
}

export interface ApprovalGranted {
  auditId: string;
  status: "approved";
  approvedBy: string;
  approvalId: string;
  approvedAt?: string;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export class AgentGuardClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly backoffMs: number;
  private readonly signingSecret: string | undefined;

  constructor(private readonly opts: AgentGuardClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    if (!/^https?:\/\//i.test(this.baseUrl)) throw new AgentGuardNetworkError("baseUrl must be an http(s) URL");
    if (opts.signRequests) {
      if (!opts.apiKey) throw new AgentGuardNetworkError("signRequests requires apiKey");
      this.signingSecret = typeof opts.signRequests === "string" ? opts.signRequests : opts.apiKey;
    }
    const f = opts.fetch ?? (globalThis.fetch as FetchLike | undefined);
    if (!f) throw new AgentGuardNetworkError("no fetch implementation available; pass `fetch` in options");
    this.fetchImpl = f;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.retries = opts.retries ?? 2;
    this.backoffMs = opts.retryBackoffMs ?? 200;
  }

  async check(intent: TransactionIntent, context: AgentContext, opts: CheckOptions = {}): Promise<CheckResponse> {
    const body: CheckRequest = {
      intent,
      context: { ...this.opts.defaultContext, ...context },
      policyId: opts.policyId ?? this.opts.policyId,
    };
    const raw = await this.request("POST", "/v1/check", { body, timeoutMs: opts.timeoutMs, signal: opts.signal });
    return reviveCheckResponse(assertCheckResponse(raw));
  }

  async getAudit(id: string, opts: Pick<CheckOptions, "timeoutMs" | "signal"> = {}): Promise<AuditRecord> {
    const raw = (await this.request("GET", `/v1/audit/${encodeURIComponent(id)}`, opts)) as Record<string, unknown>;
    return reviveAudit(raw);
  }

  async listAudit(
    query: { agentId?: string; limit?: number; cursor?: string } = {},
    opts: Pick<CheckOptions, "timeoutMs" | "signal"> = {},
  ): Promise<AuditPage> {
    const qs = new URLSearchParams();
    if (query.agentId) qs.set("agentId", query.agentId);
    if (query.limit) qs.set("limit", String(query.limit));
    if (query.cursor) qs.set("cursor", query.cursor);
    const suffix = qs.size ? `?${qs}` : "";
    const raw = (await this.request("GET", `/v1/audit${suffix}`, opts)) as { items: Record<string, unknown>[]; nextCursor?: string };
    return { items: raw.items.map(reviveAudit), nextCursor: raw.nextCursor };
  }

  /**
   * Read the server-side approval status of an escalated check. Read-only: the
   * agent can observe whether a human approved, never cause it.
   */
  async getApprovalStatus(auditId: string, opts: Pick<CheckOptions, "timeoutMs" | "signal"> = {}): Promise<ApprovalStatusResponse> {
    const raw = await this.request("GET", `/v1/approvals/${encodeURIComponent(auditId)}`, opts);
    return assertApprovalStatus(raw, auditId);
  }

  /**
   * Poll `GET /v1/approvals/:auditId` until the server reports `approved`.
   * Resolves only on a literal `approved`; `expired` / `rejected` / `unknown` throw
   * `ApprovalDeniedError`, the deadline throws `ApprovalTimeoutError`, and any
   * malformed status throws `AgentGuardProtocolError`. Nothing in this method can
   * produce an approval: it only reads state the approver device created.
   */
  async waitForApproval(auditId: string, opts: WaitForApprovalOptions = {}): Promise<ApprovalGranted> {
    const timeoutMs = opts.timeoutMs ?? 15 * 60_000;
    const intervalMs = Math.max(50, opts.intervalMs ?? 2_000);
    const deadline = Date.now() + timeoutMs;
    let last: ApprovalStatus | undefined;
    for (;;) {
      if (opts.signal?.aborted) throw new AgentGuardNetworkError("waitForApproval aborted", opts.signal.reason);
      const st = await this.getApprovalStatus(auditId, { signal: opts.signal });
      opts.onPoll?.(st);
      last = st.status;
      if (st.status === "approved") {
        if (typeof st.approvedBy !== "string" || !st.approvedBy || typeof st.approvalId !== "string" || !st.approvalId) {
          throw new AgentGuardProtocolError("malformed approval status: approved without approvedBy/approvalId");
        }
        return { auditId, status: "approved", approvedBy: st.approvedBy, approvalId: st.approvalId, approvedAt: st.approvedAt };
      }
      if (st.status !== "pending") throw new ApprovalDeniedError(auditId, st.status);
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new ApprovalTimeoutError(auditId, timeoutMs, last);
      await sleep(Math.min(intervalMs, remaining));
    }
  }

  async health(): Promise<{ ok: boolean; chains: string[]; policies: string[] }> {
    return (await this.request("GET", "/healthz", {})) as { ok: boolean; chains: string[]; policies: string[] };
  }

  private async request(
    method: "GET" | "POST",
    path: string,
    { body, timeoutMs, signal }: { body?: unknown; timeoutMs?: number; signal?: AbortSignal },
  ): Promise<unknown> {
    const baseHeaders: Record<string, string> = { accept: "application/json" };
    if (body !== undefined) baseHeaders["content-type"] = "application/json";
    if (this.opts.apiKey) baseHeaders["x-api-key"] = this.opts.apiKey;
    const payload = body === undefined ? undefined : serializeRequest(body);
    const perAttemptTimeout = timeoutMs ?? this.timeoutMs;

    let lastErr: unknown;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt > 0) await sleep(this.backoffMs * 2 ** (attempt - 1));
      if (signal?.aborted) throw new AgentGuardNetworkError("request aborted", signal.reason);

      // Fresh headers + timestamp + nonce per attempt so retries are never rejected as replays.
      const headers: Record<string, string> = { ...baseHeaders };
      if (this.signingSecret) {
        const sig = await (this.opts.signer ?? signRequest)({ secret: this.signingSecret, method, path, body: payload ?? "" });
        headers["x-agentguard-signature"] = sig.signature;
        headers["x-agentguard-timestamp"] = sig.timestamp;
        headers["x-agentguard-nonce"] = sig.nonce;
      }

      const controller = new AbortController();
      const onAbort = () => controller.abort(signal?.reason);
      signal?.addEventListener("abort", onAbort, { once: true });
      const timer = setTimeout(() => controller.abort(new AgentGuardTimeoutError(perAttemptTimeout)), perAttemptTimeout);

      let res: Response;
      try {
        res = await this.fetchImpl(`${this.baseUrl}${path}`, { method, headers, body: payload, signal: controller.signal });
      } catch (err) {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        if (signal?.aborted) throw new AgentGuardNetworkError("request aborted", signal.reason);
        lastErr = controller.signal.reason instanceof AgentGuardTimeoutError
          ? controller.signal.reason
          : new AgentGuardNetworkError(`AgentGuard request failed: ${(err as Error)?.message ?? String(err)}`, err);
        continue; // retry network/timeouts
      }
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);

      const text = await res.text();
      let parsed: unknown = undefined;
      if (text) {
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = text;
        }
      }

      if (res.ok) return parsed;

      const message = (parsed as { message?: string } | undefined)?.message;
      const httpErr = new AgentGuardHttpError(res.status, parsed, message ? `AgentGuard API ${res.status}: ${message}` : undefined);
      if (res.status >= 500) {
        lastErr = httpErr;
        continue; // retry 5xx
      }
      throw httpErr;
    }
    throw lastErr;
  }
}

const VERDICTS = new Set(["allow", "block", "escalate"]);
const APPROVAL_STATUSES = new Set<ApprovalStatus>(["pending", "approved", "expired", "rejected", "unknown"]);

/** Fail closed on malformed status responses: anything unrecognised is not `approved`. */
function assertApprovalStatus(raw: unknown, auditId: string): ApprovalStatusResponse {
  const r = raw as Partial<ApprovalStatusResponse> | null;
  if (!r || typeof r !== "object" || typeof r.status !== "string" || !APPROVAL_STATUSES.has(r.status)) {
    throw new AgentGuardProtocolError("malformed approval status response");
  }
  if (r.auditId !== auditId) throw new AgentGuardProtocolError("approval status response is for a different audit id");
  return r as ApprovalStatusResponse;
}

/**
 * Fail closed on malformed server responses: a response without a recognised
 * verdict must never be interpreted as permission to proceed.
 */
function assertCheckResponse(raw: unknown): Record<string, unknown> {
  const r = raw as { decision?: { verdict?: unknown }; auditId?: unknown } | null;
  if (!r || typeof r !== "object" || !r.decision || typeof r.decision !== "object") {
    throw new AgentGuardProtocolError("malformed check response: missing decision");
  }
  if (typeof r.decision.verdict !== "string" || !VERDICTS.has(r.decision.verdict)) {
    throw new AgentGuardProtocolError("malformed check response: unknown verdict");
  }
  if (typeof r.auditId !== "string" || !r.auditId) throw new AgentGuardProtocolError("malformed check response: missing auditId");
  const a = (r as { approval?: unknown }).approval;
  if (a !== undefined) {
    const ap = a as { challenge?: unknown; expiresAt?: unknown } | null;
    if (!ap || typeof ap !== "object" || typeof ap.challenge !== "string" || !/^[0-9a-f]{64}$/.test(ap.challenge) || typeof ap.expiresAt !== "string") {
      throw new AgentGuardProtocolError("malformed check response: bad approval challenge");
    }
  }
  return r as Record<string, unknown>;
}

function reviveAudit(raw: Record<string, unknown>): AuditRecord {
  return {
    id: raw.id as string,
    recordedAt: raw.recordedAt as string,
    intent: reviveIntent(raw.intent as Record<string, unknown>),
    decision: reviveDecision(raw.decision as Record<string, unknown>),
    context: reviveContext(raw.context as Record<string, unknown>),
  };
}
