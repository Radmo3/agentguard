import type { AgentContext, AuditRecord, CheckRequest, CheckResponse, TransactionIntent } from "@agentguard/core";
import { AgentGuardHttpError, AgentGuardNetworkError, AgentGuardTimeoutError } from "./errors.js";
import { reviveCheckResponse, reviveContext, reviveDecision, reviveIntent, serializeRequest } from "./serialization.js";

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface AgentGuardClientOptions {
  baseUrl: string;
  apiKey?: string;
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

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export class AgentGuardClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly backoffMs: number;

  constructor(private readonly opts: AgentGuardClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
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
    return reviveCheckResponse(raw as Record<string, unknown>);
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

  async health(): Promise<{ ok: boolean; chains: string[]; policies: string[] }> {
    return (await this.request("GET", "/healthz", {})) as { ok: boolean; chains: string[]; policies: string[] };
  }

  private async request(
    method: "GET" | "POST",
    path: string,
    { body, timeoutMs, signal }: { body?: unknown; timeoutMs?: number; signal?: AbortSignal },
  ): Promise<unknown> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (body !== undefined) headers["content-type"] = "application/json";
    if (this.opts.apiKey) headers["x-api-key"] = this.opts.apiKey;
    const payload = body === undefined ? undefined : serializeRequest(body);
    const perAttemptTimeout = timeoutMs ?? this.timeoutMs;

    let lastErr: unknown;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt > 0) await sleep(this.backoffMs * 2 ** (attempt - 1));
      if (signal?.aborted) throw new AgentGuardNetworkError("request aborted", signal.reason);

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

function reviveAudit(raw: Record<string, unknown>): AuditRecord {
  return {
    id: raw.id as string,
    recordedAt: raw.recordedAt as string,
    intent: reviveIntent(raw.intent as Record<string, unknown>),
    decision: reviveDecision(raw.decision as Record<string, unknown>),
    context: reviveContext(raw.context as Record<string, unknown>),
  };
}
