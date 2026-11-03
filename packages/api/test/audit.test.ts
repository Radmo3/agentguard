import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AuditRecord } from "@agentguard/core";
import { InMemoryAuditStore, JsonlAuditStore } from "../src/audit.js";
import { okSimulation } from "./fakes.js";

function rec(id: string, agentId: string): AuditRecord {
  return {
    id,
    recordedAt: new Date().toISOString(),
    intent: { id: `i-${id}`, chain: "evm", from: "0x1111111111111111111111111111111111111111", value: 123n, data: "0x00" },
    context: { agentId, now: new Date("2026-01-01T00:00:00Z") },
    decision: {
      intentId: `i-${id}`,
      verdict: "allow",
      findings: [],
      riskScore: 1,
      explanation: "ok",
      simulation: okSimulation(),
      policyId: "p",
      policyVersion: 1,
      evaluatedAt: new Date().toISOString(),
    },
  };
}

describe("InMemoryAuditStore", () => {
  it("records, gets and lists", async () => {
    const s = new InMemoryAuditStore();
    await s.record(rec("1", "a"));
    await s.record(rec("2", "b"));
    expect((await s.get("1"))?.context.agentId).toBe("a");
    expect((await s.list({ limit: 10 })).items.map((r) => r.id)).toEqual(["2", "1"]);
    expect((await s.list({ limit: 10, agentId: "b" })).items.map((r) => r.id)).toEqual(["2"]);
  });
});

describe("JsonlAuditStore", () => {
  let dir: string;
  beforeEach(async () => (dir = await mkdtemp(join(tmpdir(), "agentguard-audit-"))));
  afterEach(async () => rm(dir, { recursive: true, force: true }));

  it("appends one JSON line per record and reloads with bigints revived", async () => {
    const file = join(dir, "nested", "audit.jsonl");
    const s1 = new JsonlAuditStore(file);
    await Promise.all([s1.record(rec("1", "a")), s1.record(rec("2", "a")), s1.record(rec("3", "b"))]);

    const text = await readFile(file, "utf8");
    expect(text.trim().split("\n")).toHaveLength(3);
    for (const line of text.trim().split("\n")) expect(() => JSON.parse(line)).not.toThrow();

    const s2 = new JsonlAuditStore(file);
    const got = await s2.get("2");
    expect(got?.intent.value).toBe(123n);
    expect(got?.decision.simulation?.deltas[0].amount).toBe(-1_000_000_000_000_000_000n);
    expect(got?.decision.simulation?.approvals[0].next).toBe((1n << 256n) - 1n);
    expect(got?.decision.simulation?.gasEstimate).toBe(21_000n);
    expect(got?.context.now).toBeInstanceOf(Date);

    const page = await s2.list({ limit: 2, agentId: "a" });
    expect(page.items.map((r) => r.id)).toEqual(["2", "1"]);
    expect(page.nextCursor).toBeUndefined();

    await s2.record(rec("4", "a"));
    expect((await readFile(file, "utf8")).trim().split("\n")).toHaveLength(4);
  });
});
