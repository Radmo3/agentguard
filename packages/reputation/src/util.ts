import type { Chain } from "@signhold/core";
import { MAX_TAGS, MAX_TAG_LENGTH, type ReputationSignal, type ReputationVerdict } from "./types.js";

/** Addresses are case-insensitive on EVM, case-sensitive (base58) on Solana. */
export function normalizeAddress(address: string, chain: Chain): string {
  const t = address.trim();
  return chain === "evm" ? t.toLowerCase() : t;
}

const EVM_RE = /^0x[0-9a-fA-F]{40}$/;
const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

/** Loose syntactic validity check. Providers may still answer "unknown" for odd inputs. */
export function isPlausibleAddress(address: string, chain: Chain): boolean {
  return chain === "evm" ? EVM_RE.test(address.trim()) : BASE58_RE.test(address.trim());
}

/** Cache key: chain + optional chainId + normalized address. */
export function cacheKey(chain: Chain, address: string, chainId?: number | string): string {
  return `${chain}:${chainId ?? "*"}:${normalizeAddress(address, chain)}`;
}

export function clampScore(n: unknown): number {
  const v = typeof n === "number" && Number.isFinite(n) ? n : 0;
  return Math.max(0, Math.min(100, Math.round(v)));
}

const TAG_RE = /^[a-z0-9][a-z0-9_.:-]*$/;

/**
 * Sanitize a tag list from an untrusted source: strings only, trimmed, lowercased,
 * restricted charset, max 64 chars, deduplicated, max 20 entries. Oversized or
 * malformed tags are DROPPED (never truncated, to avoid producing a different
 * but valid-looking tag).
 */
export function sanitizeTags(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of input) {
    if (out.length >= MAX_TAGS) break;
    if (typeof raw !== "string") continue;
    const t = raw.trim().toLowerCase();
    if (t.length === 0 || t.length > MAX_TAG_LENGTH || !TAG_RE.test(t)) continue;
    if (seen.has(t)) continue;
    seen.add(t);
    out.push(t);
  }
  return out;
}

export const VERDICTS: ReadonlySet<ReputationVerdict> = new Set(["malicious", "suspicious", "unknown", "trusted"]);

export function isVerdict(v: unknown): v is ReputationVerdict {
  return typeof v === "string" && VERDICTS.has(v as ReputationVerdict);
}

/** Default risk score for a verdict when a provider does not supply one. */
export function defaultScoreFor(verdict: ReputationVerdict): number {
  switch (verdict) {
    case "malicious":
      return 100;
    case "suspicious":
      return 70;
    case "unknown":
      return 50;
    case "trusted":
      return 0;
  }
}

/** Build a well-formed signal, applying all bounds. */
export function makeSignal(
  source: string,
  verdict: ReputationVerdict,
  partial: { score?: number; tags?: unknown; evidence?: Record<string, unknown>; fetchedAt?: string } = {},
): ReputationSignal {
  return {
    source,
    verdict,
    score: clampScore(partial.score ?? defaultScoreFor(verdict)),
    tags: sanitizeTags(partial.tags ?? []),
    evidence: partial.evidence,
    fetchedAt: partial.fetchedAt ?? new Date().toISOString(),
  };
}

/**
 * Bound an untrusted evidence object: max depth 3, max 32 keys per object, strings cut
 * to 512 chars, arrays cut to 32 entries. Functions/symbols/bigints are stringified or dropped.
 */
export function boundEvidence(input: unknown, depth = 0): unknown {
  if (depth > 3) return "[truncated]";
  if (input === null || input === undefined) return input;
  if (typeof input === "string") return input.length > 512 ? input.slice(0, 512) + "…" : input;
  if (typeof input === "number" || typeof input === "boolean") return input;
  if (typeof input === "bigint") return input.toString();
  if (Array.isArray(input)) return input.slice(0, 32).map((v) => boundEvidence(v, depth + 1));
  if (typeof input === "object") {
    const out: Record<string, unknown> = {};
    let n = 0;
    for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
      if (n++ >= 32) break;
      if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
      out[k.slice(0, 64)] = boundEvidence(v, depth + 1);
    }
    return out;
  }
  return undefined;
}

export function boundEvidenceRecord(input: unknown): Record<string, unknown> | undefined {
  const b = boundEvidence(input);
  return b && typeof b === "object" && !Array.isArray(b) ? (b as Record<string, unknown>) : undefined;
}

/** Promise with timeout that also aborts the supplied controller. */
export function withTimeout<T>(
  run: (signal: AbortSignal) => Promise<T>,
  ms: number,
  onTimeout: () => Error,
): Promise<T> {
  const controller = new AbortController();
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      controller.abort();
      reject(onTimeout());
    }, ms);
    run(controller.signal).then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}
