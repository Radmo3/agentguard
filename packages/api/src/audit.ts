import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditRecord } from "@agentguard/core";
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

export class InMemoryAuditStore implements AuditStore {
  private readonly records: AuditRecord[] = [];
  private readonly byId = new Map<string, AuditRecord>();

  async record(rec: AuditRecord): Promise<void> {
    this.records.push(rec);
    this.byId.set(rec.id, rec);
  }

  async get(id: string): Promise<AuditRecord | undefined> {
    return this.byId.get(id);
  }

  async list(query: AuditListQuery): Promise<AuditPage> {
    return paginate(this.records, query);
  }

  get size(): number {
    return this.records.length;
  }
}

/**
 * Append-only JSONL file store. Keeps an in-memory index that is hydrated from
 * the file on first use, so reads are cheap and writes are a single append.
 */
export class JsonlAuditStore implements AuditStore {
  private readonly records: AuditRecord[] = [];
  private readonly byId = new Map<string, AuditRecord>();
  private loaded: Promise<void> | undefined;
  private writeChain: Promise<void> = Promise.resolve();

  constructor(private readonly filePath: string) {}

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
    }
  }

  private ensureLoaded(): Promise<void> {
    if (!this.loaded) this.loaded = this.load();
    return this.loaded;
  }

  async record(rec: AuditRecord): Promise<void> {
    await this.ensureLoaded();
    const line = stringifyWithBigints(rec) + "\n";
    // Serialise appends so concurrent requests never interleave partial lines.
    this.writeChain = this.writeChain.then(() => appendFile(this.filePath, line, "utf8"));
    await this.writeChain;
    this.records.push(rec);
    this.byId.set(rec.id, rec);
  }

  async get(id: string): Promise<AuditRecord | undefined> {
    await this.ensureLoaded();
    return this.byId.get(id);
  }

  async list(query: AuditListQuery): Promise<AuditPage> {
    await this.ensureLoaded();
    return paginate(this.records, query);
  }
}
