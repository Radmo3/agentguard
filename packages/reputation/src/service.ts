import type { Chain, SimulationResult, TransactionIntent } from "@agentguard/core";
import { LruCache } from "./cache.js";
import {
  ReputationProviderError,
  type AggregatedReputation,
  type ProviderFailure,
  type ReputationProvider,
  type ReputationSignal,
  type ReputationVerdict,
} from "./types.js";
import { cacheKey, clampScore, normalizeAddress, sanitizeTags, withTimeout } from "./util.js";

export type FailMode = "closed" | "open";

export interface ReputationServiceOptions {
  providers: ReputationProvider[];
  /** Per-provider timeout in ms (default 3000). */
  providerTimeoutMs?: number;
  /**
   * "closed" (default): any provider failure/timeout forces verdict "unknown" (unless a
   * surviving provider says malicious/suspicious), adds tag `provider_error` and lifts the
   * score to at least `errorScoreFloor`.
   * "open": failures are recorded in `errors`/tags but do not change verdict or score,
   * unless every provider failed.
   */
  failMode?: FailMode;
  /** Minimum score applied on provider failure in fail-closed mode (default 50, min 50). */
  errorScoreFloor?: number;
  cache?: {
    /** Max cached addresses (default 10_000). */
    maxEntries?: number;
    /** TTL for conclusive results — malicious/suspicious/trusted (default 10 min). */
    ttlMs?: number;
    /** TTL for "unknown" results — negative caching (default 60 s). */
    negativeTtlMs?: number;
    /** TTL for results that included a provider error (default 5 s; 0 disables). */
    errorTtlMs?: number;
  };
  /** Clock, for tests. */
  now?: () => Date;
  /** Also prefetch approval spenders from `simulation.approvals` (default true). */
  includeApprovalSpenders?: boolean;
}

export interface ServiceLookupOptions {
  chainId?: number | string;
  /** Bypass the cache for this call (result is still written back). */
  force?: boolean;
}

const RANK: Record<ReputationVerdict, number> = { malicious: 3, suspicious: 2, trusted: 1, unknown: 0 };

/**
 * Fans a lookup out to every provider with an individual timeout, aggregates the
 * signals, and caches the result. See `aggregate()` for precedence rules.
 */
export class ReputationService {
  readonly providers: readonly ReputationProvider[];
  readonly failMode: FailMode;
  private readonly timeoutMs: number;
  private readonly errorFloor: number;
  private readonly ttlMs: number;
  private readonly negativeTtlMs: number;
  private readonly errorTtlMs: number;
  private readonly cache: LruCache<AggregatedReputation>;
  private readonly inflight = new Map<string, Promise<AggregatedReputation>>();
  private readonly now: () => Date;
  private readonly includeApprovalSpenders: boolean;

  constructor(opts: ReputationServiceOptions) {
    if (!Array.isArray(opts.providers)) throw new Error("ReputationService requires a providers array");
    const names = new Set<string>();
    for (const p of opts.providers) {
      if (names.has(p.name)) throw new Error(`duplicate provider name "${p.name}"`);
      names.add(p.name);
    }
    this.providers = [...opts.providers];
    this.failMode = opts.failMode ?? "closed";
    this.timeoutMs = opts.providerTimeoutMs ?? 3000;
    this.errorFloor = Math.max(50, clampScore(opts.errorScoreFloor ?? 50));
    this.ttlMs = opts.cache?.ttlMs ?? 10 * 60_000;
    this.negativeTtlMs = opts.cache?.negativeTtlMs ?? 60_000;
    this.errorTtlMs = opts.cache?.errorTtlMs ?? 5_000;
    this.now = opts.now ?? (() => new Date());
    this.cache = new LruCache<AggregatedReputation>(opts.cache?.maxEntries ?? 10_000, () => this.now().getTime());
    this.includeApprovalSpenders = opts.includeApprovalSpenders ?? true;
  }

  /** Synchronous cache read. Returns undefined when not cached (or expired). Used by the policy rule. */
  peek(chain: Chain, address: string, chainId?: number | string): AggregatedReputation | undefined {
    const hit = this.cache.get(cacheKey(chain, address, chainId));
    return hit ? { ...hit, cached: true } : undefined;
  }

  get cacheSize(): number {
    return this.cache.size;
  }

  clearCache(): void {
    this.cache.clear();
  }

  /** Look up one address, consulting the cache first. Never rejects. */
  async lookup(chain: Chain, address: string, opts: ServiceLookupOptions = {}): Promise<AggregatedReputation> {
    const key = cacheKey(chain, address, opts.chainId);
    if (!opts.force) {
      const hit = this.cache.get(key);
      if (hit) return { ...hit, cached: true };
      const pending = this.inflight.get(key);
      if (pending) return pending;
    }
    const p = this.fetchAndCache(chain, address, opts.chainId, key).finally(() => {
      if (this.inflight.get(key) === p) this.inflight.delete(key);
    });
    this.inflight.set(key, p);
    return p;
  }

  async lookupMany(chain: Chain, addresses: string[], opts: ServiceLookupOptions = {}): Promise<AggregatedReputation[]> {
    const uniq = [...new Set(addresses.map((a) => normalizeAddress(a, chain)))];
    return Promise.all(uniq.map((a) => this.lookup(chain, a, opts)));
  }

  /** All addresses the policy rule will consult for this intent/simulation pair. */
  targetsFor(intent: TransactionIntent, simulation?: SimulationResult): string[] {
    const set = new Set<string>();
    const add = (a: unknown) => {
      if (typeof a === "string" && a.trim() !== "") set.add(normalizeAddress(a, intent.chain));
    };
    add(intent.to);
    for (const c of simulation?.contractsTouched ?? []) add(c);
    for (const r of simulation?.recipients ?? []) add(r);
    if (this.includeApprovalSpenders) for (const ap of simulation?.approvals ?? []) add(ap.spender);
    return [...set];
  }

  /**
   * Warm the cache for everything the policy rule will look at. The integration layer
   * MUST `await` this before running the (synchronous) policy engine; otherwise the
   * rule sees cache misses and escalates with tag `not_prefetched`.
   */
  async prefetch(intent: TransactionIntent, simulation?: SimulationResult): Promise<AggregatedReputation[]> {
    const targets = this.targetsFor(intent, simulation);
    return Promise.all(targets.map((a) => this.lookup(intent.chain, a, { chainId: intent.chainId })));
  }

  // -----------------------------------------------------------------------

  private async fetchAndCache(chain: Chain, address: string, chainId: number | string | undefined, key: string) {
    const settled = await Promise.all(this.providers.map((p) => this.runProvider(p, chain, address, chainId)));
    const signals: ReputationSignal[] = [];
    const errors: ProviderFailure[] = [];
    for (const s of settled) {
      if ("signal" in s) signals.push(s.signal);
      else errors.push(s.error);
    }
    const agg = aggregate({
      chain,
      address: normalizeAddress(address, chain),
      chainId,
      signals,
      errors,
      failMode: this.failMode,
      errorScoreFloor: this.errorFloor,
      fetchedAt: this.now().toISOString(),
    });
    const ttl = errors.length > 0 ? this.errorTtlMs : agg.verdict === "unknown" ? this.negativeTtlMs : this.ttlMs;
    if (ttl > 0) this.cache.set(key, agg, ttl);
    return agg;
  }

  private async runProvider(
    p: ReputationProvider,
    chain: Chain,
    address: string,
    chainId: number | string | undefined,
  ): Promise<{ signal: ReputationSignal } | { error: ProviderFailure }> {
    try {
      const raw = await withTimeout(
        (signal) => p.lookup(chain, address, { chainId, signal }),
        this.timeoutMs,
        () => new ReputationProviderError(`provider "${p.name}" timed out after ${this.timeoutMs}ms`, p.name, "timeout"),
      );
      return { signal: normalizeSignal(raw, p.name) };
    } catch (e) {
      const isTimeout = e instanceof ReputationProviderError && e.code === "timeout";
      const message = e instanceof Error ? e.message : String(e);
      return { error: { source: p.name, kind: isTimeout ? "timeout" : "error", message: message.slice(0, 256) } };
    }
  }
}

/** Re-validate a provider's output; providers are in-process but still treated defensively. */
export function normalizeSignal(raw: ReputationSignal, source: string): ReputationSignal {
  if (!raw || typeof raw !== "object") throw new ReputationProviderError("provider returned a non-object signal", source, "invalid_schema");
  const verdict: ReputationVerdict = RANK[raw.verdict] !== undefined ? raw.verdict : "unknown";
  return {
    source,
    verdict,
    score: clampScore(raw.score),
    tags: sanitizeTags(raw.tags),
    evidence: raw.evidence && typeof raw.evidence === "object" ? raw.evidence : undefined,
    fetchedAt: typeof raw.fetchedAt === "string" ? raw.fetchedAt : new Date().toISOString(),
  };
}

export interface AggregateInput {
  chain: Chain;
  address: string;
  chainId?: number | string;
  signals: ReputationSignal[];
  errors: ProviderFailure[];
  failMode: FailMode;
  errorScoreFloor: number;
  fetchedAt: string;
}

/**
 * Precedence: any malicious => malicious; else any suspicious => suspicious; else any
 * trusted => trusted; else unknown. Score = max over signals. Tags = union (+ service
 * tags). In fail-closed mode, provider errors downgrade "trusted"/"unknown" to
 * "unknown", add `provider_error` and lift score to >= errorScoreFloor.
 */
export function aggregate(input: AggregateInput): AggregatedReputation {
  const { signals, errors } = input;
  let verdict: ReputationVerdict = "unknown";
  let score = 0;
  const tags = new Set<string>();
  for (const s of signals) {
    if (RANK[s.verdict] > RANK[verdict]) verdict = s.verdict;
    if (s.score > score) score = s.score;
    for (const t of s.tags) tags.add(t);
  }
  if (signals.length === 0) {
    verdict = "unknown";
    score = Math.max(score, input.errorScoreFloor);
    tags.add("all_providers_failed");
    if (errors.length === 0) tags.add("no_providers");
  }
  if (errors.length > 0) {
    tags.add("provider_error");
    for (const e of errors) tags.add(e.kind === "timeout" ? "provider_timeout" : "provider_failed");
    if (input.failMode === "closed") {
      if (verdict === "trusted") verdict = "unknown";
      if (verdict === "unknown") score = Math.max(score, input.errorScoreFloor);
    }
  }
  return {
    chain: input.chain,
    address: input.address,
    chainId: input.chainId,
    verdict,
    score: clampScore(score),
    tags: [...tags],
    signals,
    errors,
    fetchedAt: input.fetchedAt,
    cached: false,
  };
}
