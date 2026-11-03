import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditIntegrity, AuditRecord } from "@agentguard/core";
import { sealRecord, type AuditSigner } from "./integrity.js";
import { reviveAuditRecord, stringifyWithBigints } from "./serialization.js";
import type { AuditListQuery, AuditPage, AuditStore } from "./types.js";

function paginate(all: AuditRecord[], query: AuditListQuery): AuditPage {
  // `all` is in insertion order; we serve newest first.
  const filtered = query.agentId ? all.filter((r) => r.context.agentId === query.agentId) : all.slice();
  filtered.reverse();
  const offset = query.cursor ? Number.parseInt(query.cursor, 10) : 0;
  if (!Number.isFinite(offset) || offset < 0) throw new RangeError("invalid cursor");
  const limit = Math.max(1, Math.min(query.limit, 500));
  const items = filtered.slice(offset, offset + limit);
  const next = offset + limit;
  return { items, nextCursor: next < filtered.length ? String(next) : undefined };
}

function sliceRange(all: AuditRecord[], fromSeq: number, toSeq: number): AuditRecord[] {
  const from = Math.max(0, fromSeq);
  const to = Math.min(all.length - 1, toSeq);
  if (to < from) return [];
  return all.slice(from, to + 1);
}

export interface AuditStoreOptions {
  /** Ed25519 signer; when set every record carries a signature. */
  signer?: AuditSigner;
}

/**
 * Base for chained stores: every `record()` seals the body onto the chain head
 * (hash-chained, optionally signed) before it is persisted. Sealing is
 * serialised through a promise chain so concurrent requests never race for
 * the same `seq`.
 */
abstract class ChainedAuditStore implements AuditStore {
  protected readonly records: AuditRecord[] = [];
  protected readonly byId = new Map<string, AuditRecord>();
  protected head: AuditIntegrity | undefined;
  private chain: Promise<void> = Promise.resolve();

  constructor(protected readonly opts: AuditStoreOptions = {}) {}

  protected abstract persist(rec: AuditRecord): Promise<void>;
  protected ensureLoaded(): Promise<void> {
    return Promise.resolve();
  }

  async record(rec: AuditRecord): Promise<AuditRecord> {
    await this.ensureLoaded();
    let sealed!: AuditRecord;
    const run = this.chain.then(async () => {
      sealed = sealRecord(rec, this.head, { signer: this.opts.signer });
      await this.persist(sealed);
      this.records.push(sealed);
      this.byId.set(sealed.id, sealed);
      this.head = sealed.integrity;
    });
    // Keep the chain alive even if this append fails; the failure is surfaced to the caller.
    this.chain = run.catch(() => undefined);
    await run;
    return sealed;
  }

  async get(id: string): Promise<AuditRecord | undefined> {
    await this.ensureLoaded();
    return this.byId.get(id);
  }

  async list(query: AuditListQuery): Promise<AuditPage> {
    await this.ensureLoaded();
    return paginate(this.records, query);
  }

  async range(fromSeq: number, toSeq: number): Promise<AuditRecord[]> {
    await this.ensureLoaded();
    return sliceRange(this.records, fromSeq, toSeq);
  }

  async headIntegrity(): Promise<AuditIntegrity | undefined> {
    await this.ensureLoaded();
    return this.head;
  }

  get size(): number {
    return this.records.length;
  }

  get signerKeyId(): string | undefined {
    return this.opts.signer?.keyId;
  }
}

export class InMemoryAuditStore extends ChainedAuditStore {
  protected async persist(): Promise<void> {
    /* nothing to do */
  }
}

/**
 * Append-only JSONL file store. Keeps an in-memory index that is hydrated from
 * the file on first use, so reads are cheap and writes are a single append.
 * On load the existing chain head is adopted so new records continue the chain;
 * the file is NOT verified on load (use `GET /v1/audit/verify` or
 * `scripts/verify-audit.ts`).
 */
export class JsonlAuditStore extends ChainedAuditStore {
  private loaded: Promise<void> | undefined;

  constructor(
    private readonly filePath: string,
    opts: AuditStoreOptions = {},
  ) {
    super(opts);
  }

  private async load(): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true });
    let text: string;
    try {
      text = await readFile(this.filePath, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
      throw err;
    }
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const rec = reviveAuditRecord(JSON.parse(trimmed));
      this.records.push(rec);
      this.byId.set(rec.id, rec);
      if (rec.integrity) this.head = rec.integrity;
    }
  }

  protected override ensureLoaded(): Promise<void> {
    if (!this.loaded) this.loaded = this.load();
    return this.loaded;
  }

  protected async persist(rec: AuditRecord): Promise<void> {
    await appendFile(this.filePath, stringifyWithBigints(rec) + "\n", "utf8");
  }
}
