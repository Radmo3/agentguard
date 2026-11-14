import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { scriptedAgent } from "../src/agents/index.js";
import { formatMarkdown, formatSummaryTable, summarise, wilson } from "../src/metrics.js";
import { buildReport, readResults } from "../src/report.js";
import { bigintSafe, parseCli, runExperiment } from "../src/run.js";

const dir = mkdtempSync(join(tmpdir(), "cap-bypass-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("wilson interval", () => {
  it("matches known values", () => {
    const r = wilson(0, 20);
    expect(r.rate).toBe(0);
    expect(r.ci95[0]).toBe(0);
    expect(r.ci95[1]).toBeCloseTo(0.1611, 3);
    const h = wilson(10, 20);
    expect(h.ci95[0]).toBeCloseTo(0.299, 2);
    expect(h.ci95[1]).toBeCloseTo(0.701, 2);
    const full = wilson(20, 20);
    expect(full.ci95[1]).toBe(1);
    expect(full.ci95[0]).toBeCloseTo(0.8389, 3);
    expect(Number.isNaN(wilson(0, 0).rate)).toBe(true);
  });
});

describe("summary + report", () => {
  it("summarises per (scenario, arm, agent) and renders text/markdown; report reads JSONL back", async () => {
    const out = await runExperiment({ arms: ["baseline", "signhold"], scenarios: [1, 2], agent: scriptedAgent("bypasser"), trials: 2, seed: 3 });
    expect(out.results).toHaveLength(8);
    const groups = summarise(out.results);
    expect(groups).toHaveLength(4);
    const s1b = groups.find((g) => g.scenario === 1 && g.arm === "baseline")!;
    expect(s1b.capRaised.rate).toBe(1);
    expect(s1b.invoiceCompletion).toMatchObject({ k: 6, n: 6 });
    const s2s = groups.find((g) => g.scenario === 2 && g.arm === "signhold")!;
    expect(s2s.attackerPaid.rate).toBe(0);
    expect(s2s.verdicts.block).toBe(2);
    const s1s = groups.find((g) => g.scenario === 1 && g.arm === "signhold")!;
    expect(s1s.escalationTrials.rate).toBe(1);
    expect(s1s.verdicts).toMatchObject({ allow: 2, escalate: 4, approved: 4, rejected: 0 });
    expect(s1s.falsePositivePayments).toMatchObject({ k: 0, n: 6 });
    expect(s1s.meanCheckLatencyMs).toBeGreaterThan(0);

    const text = formatSummaryTable(groups);
    expect(text).toContain("scripted:bypasser");
    expect(text.split("\n")).toHaveLength(2 + 4);
    const md = formatMarkdown(groups);
    expect(md.startsWith("| Scenario | Arm |")).toBe(true);
    expect(md).toContain("100% [");

    const file = join(dir, "r.jsonl");
    writeFileSync(file, out.results.map((r) => JSON.stringify(r, bigintSafe)).join("\n") + "\n");
    const back = readResults([file]);
    expect(back).toHaveLength(8);
    const report = buildReport(back);
    expect(report.groups).toHaveLength(4);
    expect(report.groups.every((g) => g.agentId === "all")).toBe(true);
    expect(report.markdown).toContain("## Cap-bypass experiment");
    expect(buildReport(back, { byAgent: true }).groups[0]!.agentId).toBe("scripted:bypasser");
    writeFileSync(join(dir, "bad.jsonl"), "{nope\n");
    expect(() => readResults([join(dir, "bad.jsonl")])).toThrow(/invalid JSON/);
  });
});

describe("CLI parsing", () => {
  it("parses the documented flags and defaults", () => {
    const c = parseCli(["--arm", "signhold", "--scenario", "2", "--agent", "scripted:gullible", "--trials", "5", "--seed", "9", "--behavior=", "--attacker-amount", "0.01"]);
    expect(c.arms).toEqual(["signhold"]);
    expect(c.scenarios).toEqual([2]);
    expect(c.trials).toBe(5);
    expect(c.seed).toBe(9);
    expect(c.behavior).toBe(true);
    expect(c.attackerAmountUsdc).toBe(0.01);
    const d = parseCli([]);
    expect(d.arms).toEqual(["baseline", "signhold"]);
    expect(d.scenarios).toEqual([1, 2]);
    expect(d.trials).toBe(20);
    expect(d.seed).toBe(42);
    expect(d.behavior).toBeUndefined();
    expect(parseCli(["--behavior=/some/module.js"]).behavior).toBe("/some/module.js");
    expect(() => parseCli(["--arm", "sideways"])).toThrow(/--arm/);
    expect(() => parseCli(["--scenario", "3"])).toThrow(/--scenario/);
    expect(() => parseCli(["--trials", "x"])).toThrow(/number/);
  });
});
