#!/usr/bin/env tsx
/**
 * Verify the hash chain (and optionally Ed25519 signatures) of a JSONL audit file.
 *
 *   npx tsx packages/api/scripts/verify-audit.ts <audit.jsonl> [--public-key <pem|hex|base64>]... [--require-signatures] [--from N] [--to N] [--json]
 *
 * Exit code 0 when the chain verifies, 1 on failure, 2 on usage error.
 */
import { createReadStream } from "node:fs";
import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import type { KeyObject } from "node:crypto";
import type { AuditRecord } from "@agentguard/core";
import { keyIdOf, loadEd25519PublicKey, verifyChain, type VerifyResult } from "../src/integrity.js";
import { reviveAuditRecord } from "../src/serialization.js";

interface Args {
  file?: string;
  publicKeys: string[];
  requireSignatures: boolean;
  from: number;
  to?: number;
  json: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { publicKeys: [], requireSignatures: false, from: 0, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--public-key" || a === "-k") args.publicKeys.push(argv[++i] ?? "");
    else if (a === "--require-signatures") args.requireSignatures = true;
    else if (a === "--from") args.from = Number(argv[++i]);
    else if (a === "--to") args.to = Number(argv[++i]);
    else if (a === "--json") args.json = true;
    else if (a === "-h" || a === "--help") usage(0);
    else if (!args.file) args.file = a;
    else usage(2, `unexpected argument '${a}'`);
  }
  if (!args.file) usage(2, "missing <audit.jsonl>");
  return args;
}

function usage(code: number, msg?: string): never {
  if (msg) console.error(`error: ${msg}`);
  console.error("usage: verify-audit.ts <audit.jsonl> [--public-key <pem-file|hex|base64>]... [--require-signatures] [--from N] [--to N] [--json]");
  process.exit(code);
}

async function loadKey(material: string): Promise<KeyObject> {
  // Accept a path to a PEM file or inline material.
  let text = material;
  try {
    text = await readFile(material, "utf8");
  } catch {
    /* inline */
  }
  return loadEd25519PublicKey(text);
}

async function* readRecords(file: string, from: number, to: number | undefined): AsyncGenerator<AuditRecord> {
  const rl = createInterface({ input: createReadStream(file, "utf8"), crlfDelay: Infinity });
  let lineNo = 0;
  for await (const line of rl) {
    lineNo++;
    const trimmed = line.trim();
    if (!trimmed) continue;
    let rec: AuditRecord;
    try {
      rec = reviveAuditRecord(JSON.parse(trimmed));
    } catch (err) {
      throw new Error(`line ${lineNo}: unparseable record (${(err as Error).message})`);
    }
    const seq = rec.integrity?.seq;
    if (seq !== undefined) {
      if (seq < from) continue;
      if (to !== undefined && seq > to) break;
    }
    yield rec;
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const publicKeys = new Map<string, KeyObject>();
  for (const k of args.publicKeys) {
    const pk = await loadKey(k);
    publicKeys.set(keyIdOf(pk), pk);
  }

  const records: AuditRecord[] = [];
  for await (const r of readRecords(args.file!, args.from, args.to)) records.push(r);

  const result: VerifyResult = verifyChain(records, {
    publicKeys: publicKeys.size ? publicKeys : undefined,
    requireSignatures: args.requireSignatures,
  });

  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`records checked: ${result.checked}  signed: ${result.signedCount}  range: ${result.firstSeq ?? "-"}..${result.lastSeq ?? "-"}`);
    if (result.lastHash) console.log(`head hash: ${result.lastHash}`);
    if (result.ok) console.log("OK: audit chain verified");
    else {
      console.error(`FAIL: ${result.failures.length} problem(s)`);
      for (const f of result.failures) console.error(`  seq=${f.seq} id=${f.id} ${f.reason}${f.detail ? ` (${f.detail})` : ""}`);
    }
  }
  process.exit(result.ok ? 0 : 1);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(2);
});
