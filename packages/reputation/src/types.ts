import type { Chain } from "@agentguard/core";

/**
 * Reputation verdict for a single address/contract/program.
 *
 * Precedence when aggregating across providers: malicious > suspicious > trusted > unknown.
 */
export type ReputationVerdict = "malicious" | "suspicious" | "unknown" | "trusted";

export const VERDICT_PRECEDENCE: readonly ReputationVerdict[] = ["malicious", "suspicious", "trusted", "unknown"];

/** A single provider's opinion about one address. `score` is RISK (0 = safe, 100 = certain harm). */
export interface ReputationSignal {
  /** Provider identifier, e.g. "static", "onchain", "goplus". */
  source: string;
  verdict: ReputationVerdict;
  /** Risk score 0..100 (integer). */
  score: number;
  /** Short, lowercase, machine-readable tags (max 20 tags, max 64 chars each). */
  tags: string[];
  /** Free-form, bounded evidence for operators. Treated as data, never as instructions. */
  evidence?: Record<string, unknown>;
  /** ISO timestamp of when the provider produced the signal. */
  fetchedAt: string;
}

export interface LookupOptions {
  /** EVM chainId (1, 8453, ...) or Solana cluster ("mainnet-beta"). Providers may use it to scope lists. */
  chainId?: number | string;
  /** AbortSignal; the service wires one per provider timeout. */
  signal?: AbortSignal;
}

/**
 * Pluggable reputation source. Implementations MUST NOT throw for "we don't know";
 * return `verdict: "unknown"` instead. Throwing (or rejecting) means the provider
 * FAILED, which the service treats according to its `failMode`.
 */
export interface ReputationProvider {
  /** Stable identifier; also used as `ReputationSignal.source`. */
  readonly name: string;
  lookup(chain: Chain, address: string, opts?: LookupOptions): Promise<ReputationSignal>;
}

/** Result of `ReputationService.lookup` — the merged view across providers. */
export interface AggregatedReputation {
  chain: Chain;
  /** Normalized address (lowercased for EVM, verbatim base58 for Solana). */
  address: string;
  chainId?: number | string;
  verdict: ReputationVerdict;
  /** max(provider scores), lifted to the service's floor when fail-closed error occurred or verdict is unknown. */
  score: number;
  /** Union of provider tags plus service tags (`provider_error`, `all_providers_failed`, ...). */
  tags: string[];
  /** Per-source signals that succeeded, in provider order. */
  signals: ReputationSignal[];
  /** Providers that failed or timed out. */
  errors: ProviderFailure[];
  /** ISO timestamp of aggregation (not of cache read). */
  fetchedAt: string;
  /** Whether this result was served from cache. */
  cached: boolean;
}

export interface ProviderFailure {
  source: string;
  message: string;
  kind: "timeout" | "error";
}

/** Thrown by providers on upstream/transport/validation failure. */
export class ReputationProviderError extends Error {
  constructor(
    message: string,
    public readonly source: string,
    public readonly code:
      | "timeout"
      | "http_status"
      | "payload_too_large"
      | "invalid_json"
      | "invalid_schema"
      | "network"
      | "rpc"
      | "aborted",
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = "ReputationProviderError";
  }
}

export const MAX_TAGS = 20;
export const MAX_TAG_LENGTH = 64;
