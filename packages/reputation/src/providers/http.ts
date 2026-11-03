import type { Chain } from "@agentguard/core";
import {
  ReputationProviderError,
  type LookupOptions,
  type ReputationProvider,
  type ReputationSignal,
  type ReputationVerdict,
} from "../types.js";
import { boundEvidenceRecord, clampScore, isVerdict, makeSignal, sanitizeTags, withTimeout } from "../util.js";

/** Minimal `fetch` shape (global fetch satisfies it; tests inject a mock). */
export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body?: string; signal: AbortSignal }) => Promise<ResponseLike>;

export interface ResponseLike {
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  body?: ReadableStream<Uint8Array> | null;
  text(): Promise<string>;
}

/**
 * What a mapping function may return. Everything is re-validated and bounded by
 * the provider, so a buggy/malicious mapper cannot smuggle oversized tags.
 */
export interface MappedResponse {
  verdict: ReputationVerdict;
  score?: number;
  tags?: string[];
  evidence?: Record<string, unknown>;
}

export interface HttpRequestSpec {
  url: string;
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  body?: unknown;
}

export interface HttpProviderOptions {
  name: string;
  /** Build the request for an address. Called per attempt. */
  buildRequest: (chain: Chain, address: string, chainId?: number | string) => HttpRequestSpec;
  /**
   * Map validated upstream JSON (already size/JSON checked) to a signal. Return `null`
   * to mean "upstream has no opinion" (verdict unknown). Throw to signal a schema problem.
   */
  mapResponse: (json: unknown, ctx: { chain: Chain; address: string; chainId?: number | string }) => MappedResponse | null;
  /**
   * Optional structural pre-validation of the upstream JSON BEFORE mapResponse runs.
   * Return false (or throw) to reject. Defaults to: must be a non-null object or array.
   */
  validateUpstream?: (json: unknown) => boolean;
  /** Per-attempt timeout in ms (default 3000). */
  timeoutMs?: number;
  /** Number of retries after the first attempt (default 1). Only 5xx/network/timeout are retried. */
  retries?: number;
  /** Max accepted response bytes (default 256 KiB). */
  maxResponseBytes?: number;
  /** Max accepted nesting depth of upstream JSON (default 16). */
  maxJsonDepth?: number;
  fetch?: FetchLike;
  /** Backoff between retries in ms (default 100). Set 0 in tests. */
  retryDelayMs?: number;
  now?: () => Date;
}

/**
 * Generic adapter for external intel APIs (GoPlus / Blockaid / ScamSniffer-style).
 * Upstream is treated as untrusted: bounded size, strict JSON, depth limit, tag
 * sanitization and evidence bounding all happen here regardless of the mapper.
 */
export class HttpProvider implements ReputationProvider {
  readonly name: string;
  private readonly o: Required<Pick<HttpProviderOptions, "timeoutMs" | "retries" | "maxResponseBytes" | "maxJsonDepth" | "retryDelayMs">> &
    HttpProviderOptions;
  private readonly fetchImpl: FetchLike;

  constructor(opts: HttpProviderOptions) {
    this.name = opts.name;
    this.o = {
      ...opts,
      timeoutMs: opts.timeoutMs ?? 3000,
      retries: Math.max(0, Math.min(5, opts.retries ?? 1)),
      maxResponseBytes: opts.maxResponseBytes ?? 256 * 1024,
      maxJsonDepth: opts.maxJsonDepth ?? 16,
      retryDelayMs: opts.retryDelayMs ?? 100,
    };
    const f = opts.fetch ?? (globalThis.fetch as unknown as FetchLike | undefined);
    if (!f) throw new Error(`HttpProvider "${opts.name}": no fetch implementation available`);
    this.fetchImpl = f;
  }

  async lookup(chain: Chain, address: string, opts: LookupOptions = {}): Promise<ReputationSignal> {
    const ctx = { chain, address, chainId: opts.chainId };
    let lastErr: ReputationProviderError | undefined;
    for (let attempt = 0; attempt <= this.o.retries; attempt++) {
      if (opts.signal?.aborted) throw new ReputationProviderError("lookup aborted", this.name, "aborted");
      try {
        const json = await this.fetchJson(ctx, opts.signal);
        return this.toSignal(json, ctx);
      } catch (e) {
        const err =
          e instanceof ReputationProviderError
            ? e
            : new ReputationProviderError(`unexpected error: ${(e as Error)?.message ?? String(e)}`, this.name, "network", e);
        lastErr = err;
        if (!isRetryable(err) || attempt === this.o.retries) break;
        if (this.o.retryDelayMs > 0) await sleep(this.o.retryDelayMs * (attempt + 1));
      }
    }
    throw lastErr ?? new ReputationProviderError("lookup failed", this.name, "network");
  }

  private async fetchJson(ctx: { chain: Chain; address: string; chainId?: number | string }, outer?: AbortSignal): Promise<unknown> {
    const spec = this.o.buildRequest(ctx.chain, ctx.address, ctx.chainId);
    if (!/^https?:\/\//.test(spec.url)) {
      throw new ReputationProviderError(`refusing non-http(s) URL`, this.name, "network");
    }
    return withTimeout(
      async (signal) => {
        const combined = combineSignals(signal, outer);
        const headers: Record<string, string> = { accept: "application/json", ...(spec.headers ?? {}) };
        let body: string | undefined;
        if (spec.body !== undefined) {
          body = typeof spec.body === "string" ? spec.body : JSON.stringify(spec.body);
          headers["content-type"] ??= "application/json";
        }
        let res: ResponseLike;
        try {
          res = await this.fetchImpl(spec.url, { method: spec.method ?? "GET", headers, body, signal: combined });
        } catch (e) {
          if (combined.aborted) throw new ReputationProviderError("request aborted", this.name, "aborted", e);
          throw new ReputationProviderError(`network error: ${(e as Error)?.message ?? String(e)}`, this.name, "network", e);
        }
        if (!res.ok) {
          throw new ReputationProviderError(`upstream returned HTTP ${res.status}`, this.name, "http_status", { status: res.status });
        }
        const cl = res.headers.get("content-length");
        if (cl && Number(cl) > this.o.maxResponseBytes) {
          throw new ReputationProviderError(`upstream response too large (${cl} bytes)`, this.name, "payload_too_large");
        }
        const text = await this.readBounded(res);
        let json: unknown;
        try {
          json = JSON.parse(text);
        } catch (e) {
          throw new ReputationProviderError("upstream returned invalid JSON", this.name, "invalid_json", e);
        }
        if (jsonDepth(json) > this.o.maxJsonDepth) {
          throw new ReputationProviderError("upstream JSON nested too deeply", this.name, "invalid_schema");
        }
        return json;
      },
      this.o.timeoutMs,
      () => new ReputationProviderError(`upstream timed out after ${this.o.timeoutMs}ms`, this.name, "timeout"),
    );
  }

  private async readBounded(res: ResponseLike): Promise<string> {
    const max = this.o.maxResponseBytes;
    if (res.body && typeof res.body.getReader === "function") {
      const reader = res.body.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          total += value.byteLength;
          if (total > max) {
            try {
              await reader.cancel();
            } catch {
              /* ignore */
            }
            throw new ReputationProviderError(`upstream response exceeded ${max} bytes`, this.name, "payload_too_large");
          }
          chunks.push(value);
        }
      }
      const buf = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) {
        buf.set(c, off);
        off += c.byteLength;
      }
      return new TextDecoder().decode(buf);
    }
    const text = await res.text();
    if (Buffer.byteLength(text, "utf8") > max) {
      throw new ReputationProviderError(`upstream response exceeded ${max} bytes`, this.name, "payload_too_large");
    }
    return text;
  }

  private toSignal(json: unknown, ctx: { chain: Chain; address: string; chainId?: number | string }): ReputationSignal {
    const validate = this.o.validateUpstream ?? ((j: unknown) => j !== null && typeof j === "object");
    let valid = false;
    try {
      valid = validate(json);
    } catch (e) {
      throw new ReputationProviderError(`upstream failed validation: ${(e as Error)?.message ?? String(e)}`, this.name, "invalid_schema", e);
    }
    if (!valid) throw new ReputationProviderError("upstream failed schema validation", this.name, "invalid_schema");

    let mapped: MappedResponse | null;
    try {
      mapped = this.o.mapResponse(json, ctx);
    } catch (e) {
      throw new ReputationProviderError(`response mapping failed: ${(e as Error)?.message ?? String(e)}`, this.name, "invalid_schema", e);
    }
    const fetchedAt = (this.o.now ?? (() => new Date()))().toISOString();
    if (mapped === null || mapped === undefined) {
      return makeSignal(this.name, "unknown", { score: 50, tags: ["no_data"], fetchedAt });
    }
    if (!mapped || typeof mapped !== "object" || !isVerdict(mapped.verdict)) {
      throw new ReputationProviderError("mapper returned invalid verdict", this.name, "invalid_schema");
    }
    return makeSignal(this.name, mapped.verdict, {
      score: mapped.score === undefined ? undefined : clampScore(mapped.score),
      tags: sanitizeTags(mapped.tags),
      evidence: boundEvidenceRecord(mapped.evidence),
      fetchedAt,
    });
  }
}

function isRetryable(e: ReputationProviderError): boolean {
  if (e.code === "timeout" || e.code === "network") return true;
  if (e.code === "http_status") {
    const s = (e.cause as { status?: number } | undefined)?.status ?? 0;
    return s >= 500 || s === 429;
  }
  return false;
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function combineSignals(a: AbortSignal, b?: AbortSignal): AbortSignal {
  if (!b) return a;
  const c = new AbortController();
  const onAbort = () => c.abort();
  if (a.aborted || b.aborted) c.abort();
  a.addEventListener("abort", onAbort, { once: true });
  b.addEventListener("abort", onAbort, { once: true });
  return c.signal;
}

export function jsonDepth(v: unknown, d = 0): number {
  if (v === null || typeof v !== "object") return d;
  let max = d + 1;
  if (max > 64) return max; // bail early on pathological inputs
  for (const child of Array.isArray(v) ? v : Object.values(v as Record<string, unknown>)) {
    const cd = jsonDepth(child, d + 1);
    if (cd > max) max = cd;
    if (max > 64) break;
  }
  return max;
}
