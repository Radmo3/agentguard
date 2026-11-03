import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Chain } from "@agentguard/core";
import type { LookupOptions, ReputationProvider, ReputationSignal } from "../types.js";
import { clampScore, makeSignal, normalizeAddress, sanitizeTags } from "../util.js";

/** One row of an allow/deny list. */
export interface ListEntry {
  chain: Chain;
  /** When omitted the entry matches any chainId on that chain. */
  chainId?: number | string;
  address: string;
  label?: string;
  tags?: string[];
  /** Optional explicit risk score override (0..100). */
  score?: number;
}

export interface ListFile {
  version?: number;
  entries: ListEntry[];
}

export interface StaticListProviderOptions {
  name?: string;
  allow?: ListEntry[];
  deny?: ListEntry[];
  /** Include the bundled seed list of well-known trusted contracts (default true). */
  includeSeed?: boolean;
}

interface Stored {
  label?: string;
  tags: string[];
  score?: number;
  chainId?: number | string;
}

const MAX_FILE_BYTES = 8 * 1024 * 1024;

function key(chain: Chain, address: string, chainId: number | string | undefined): string {
  return `${chain}:${chainId === undefined ? "*" : String(chainId)}:${normalizeAddress(address, chain)}`;
}

function isChain(v: unknown): v is Chain {
  return v === "evm" || v === "solana";
}

/** Strictly validate a parsed list file; rejects anything malformed instead of partially loading. */
export function parseListFile(json: unknown, origin = "<inline>"): ListEntry[] {
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    throw new Error(`${origin}: list file must be an object with an "entries" array`);
  }
  const entries = (json as { entries?: unknown }).entries;
  if (!Array.isArray(entries)) throw new Error(`${origin}: "entries" must be an array`);
  return entries.map((e, i) => {
    if (!e || typeof e !== "object") throw new Error(`${origin}: entry ${i} is not an object`);
    const r = e as Record<string, unknown>;
    if (!isChain(r.chain)) throw new Error(`${origin}: entry ${i} has invalid chain`);
    if (typeof r.address !== "string" || r.address.trim() === "") {
      throw new Error(`${origin}: entry ${i} has invalid address`);
    }
    if (r.chainId !== undefined && typeof r.chainId !== "number" && typeof r.chainId !== "string") {
      throw new Error(`${origin}: entry ${i} has invalid chainId`);
    }
    if (r.tags !== undefined && !Array.isArray(r.tags)) throw new Error(`${origin}: entry ${i} has invalid tags`);
    if (r.score !== undefined && (typeof r.score !== "number" || !Number.isFinite(r.score))) {
      throw new Error(`${origin}: entry ${i} has invalid score`);
    }
    const out: ListEntry = { chain: r.chain, address: r.address.trim() };
    if (r.chainId !== undefined) out.chainId = r.chainId;
    if (typeof r.label === "string") out.label = r.label.slice(0, 128);
    if (r.tags) out.tags = sanitizeTags(r.tags);
    if (r.score !== undefined) out.score = clampScore(r.score);
    return out;
  });
}

export function loadListFile(path: string): ListEntry[] {
  const buf = readFileSync(path);
  if (buf.byteLength > MAX_FILE_BYTES) throw new Error(`${path}: list file exceeds ${MAX_FILE_BYTES} bytes`);
  let json: unknown;
  try {
    json = JSON.parse(buf.toString("utf8"));
  } catch (e) {
    throw new Error(`${path}: invalid JSON (${(e as Error).message})`);
  }
  return parseListFile(json, path);
}

let seedCache: ListEntry[] | undefined;

/** The bundled seed list of well-known trusted contracts/programs (data/trusted-seed.json). */
export function bundledTrustedSeed(): ListEntry[] {
  if (!seedCache) {
    const p = fileURLToPath(new URL("../../data/trusted-seed.json", import.meta.url));
    seedCache = loadListFile(p);
  }
  return seedCache.map((e) => ({ ...e, tags: e.tags ? [...e.tags] : undefined }));
}

/**
 * Allow/deny lists held in memory. Deny wins over allow. Lookups are case-normalized
 * per chain and scoped by chainId: an entry with a chainId only matches that chainId;
 * an entry without one matches any chainId on its chain.
 */
export class StaticListProvider implements ReputationProvider {
  readonly name: string;
  private readonly allow = new Map<string, Stored>();
  private readonly deny = new Map<string, Stored>();

  constructor(opts: StaticListProviderOptions = {}) {
    this.name = opts.name ?? "static";
    if (opts.includeSeed !== false) this.addAllow(bundledTrustedSeed());
    if (opts.allow) this.addAllow(opts.allow);
    if (opts.deny) this.addDeny(opts.deny);
  }

  /** Construct from JSON files on disk (synchronously; intended for startup). */
  static fromFiles(opts: { allowFiles?: string[]; denyFiles?: string[]; includeSeed?: boolean; name?: string }) {
    const allow = (opts.allowFiles ?? []).flatMap(loadListFile);
    const deny = (opts.denyFiles ?? []).flatMap(loadListFile);
    return new StaticListProvider({ allow, deny, includeSeed: opts.includeSeed, name: opts.name });
  }

  addAllow(entries: ListEntry[]): this {
    for (const e of entries) this.allow.set(key(e.chain, e.address, e.chainId), toStored(e));
    return this;
  }

  addDeny(entries: ListEntry[]): this {
    for (const e of entries) this.deny.set(key(e.chain, e.address, e.chainId), toStored(e));
    return this;
  }

  get sizes(): { allow: number; deny: number } {
    return { allow: this.allow.size, deny: this.deny.size };
  }

  private find(map: Map<string, Stored>, chain: Chain, address: string, chainId?: number | string) {
    if (chainId !== undefined) {
      const scoped = map.get(key(chain, address, chainId));
      if (scoped) return scoped;
    }
    return map.get(key(chain, address, undefined));
  }

  async lookup(chain: Chain, address: string, opts: LookupOptions = {}): Promise<ReputationSignal> {
    const fetchedAt = new Date().toISOString();
    const denied = this.find(this.deny, chain, address, opts.chainId);
    if (denied) {
      return makeSignal(this.name, "malicious", {
        score: denied.score ?? 100,
        tags: ["denylisted", ...denied.tags],
        evidence: { list: "deny", label: denied.label, scope: denied.chainId ?? "any" },
        fetchedAt,
      });
    }
    const allowed = this.find(this.allow, chain, address, opts.chainId);
    if (allowed) {
      return makeSignal(this.name, "trusted", {
        score: allowed.score ?? 0,
        tags: ["allowlisted", ...allowed.tags],
        evidence: { list: "allow", label: allowed.label, scope: allowed.chainId ?? "any" },
        fetchedAt,
      });
    }
    return makeSignal(this.name, "unknown", { score: 50, tags: ["not_listed"], fetchedAt });
  }
}

function toStored(e: ListEntry): Stored {
  return { label: e.label, tags: sanitizeTags(e.tags ?? []), score: e.score, chainId: e.chainId };
}
