import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { BEHAVIOR_PACKAGE, bootstrap } from "../src/bootstrap.js";

const quiet = { warn() {}, info() {} };
/** The stub behavior module, loaded through the same dynamic-import path as the real package. */
const STUB_BEHAVIOR_MODULE = pathToFileURL(join(import.meta.dirname, "behavior-stub.ts")).href;

describe("bootstrap (behavior + reputation layers)", () => {
  it("degrades gracefully with a warning when the behavior package is not installed", async () => {
    // This repository never ships @agentguard/behavior; the layer must simply be off.
    const warnings: string[] = [];
    const r = await bootstrap({ evmRpcUrl: "http://127.0.0.1:1", log: { warn: (m) => warnings.push(m), info() {} } });
    expect(r.behavior).toBeUndefined();
    expect(r.reputation).toBeDefined();
    expect(warnings.some((w) => w.includes(`${BEHAVIOR_PACKAGE} not installed`))).toBe(true);
    const policy = r.policies.get(r.defaultPolicyId)!;
    expect(policy.rules.filter((x) => x.kind === "custom").map((x) => x.params?.fn)).toEqual(["reputation"]);
  });

  it("refuses to start when the configured behavior module does not satisfy the factory contract", async () => {
    // A module that exists but lacks createBehaviorIntegration must not be silently treated as "layer off".
    await expect(bootstrap({ evmRpcUrl: "http://127.0.0.1:1", behaviorModule: "node:path", log: quiet })).rejects.toThrow(/createBehaviorIntegration/);
  });

  it("registers both custom rules and extends the default policy when a behavior module is installed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "agentguard-boot-"));
    const deny = join(dir, "deny.json");
    writeFileSync(deny, JSON.stringify({ version: 1, entries: [{ chain: "evm", address: "0xbad0000000000000000000000000000000000bad" }] }));
    const r = await bootstrap({
      evmRpcUrl: "http://127.0.0.1:1",
      profilePath: join(dir, "profiles.jsonl"),
      behaviorModule: STUB_BEHAVIOR_MODULE,
      reputationDenylistFiles: [deny],
      log: quiet,
    });
    const policy = r.policies.get(r.defaultPolicyId)!;
    expect(policy.rules.filter((x) => x.kind === "custom").map((x) => x.params?.fn)).toEqual(["behavior", "reputation"]);
    expect(r.behavior).toBeDefined();
    expect(typeof r.behavior!.persist).toBe("function");
    expect(r.reputation).toBeDefined();
    // The engine knows the rules: evaluating with the extended policy produces no engine_error.
    const d = await r.engine.evaluate({
      intent: { id: "x", chain: "evm", from: "0x1111111111111111111111111111111111111111", to: "0xbad0000000000000000000000000000000000bad" },
      simulation: { ok: true, deltas: [], approvals: [], contractsTouched: [], newContracts: [], warnings: [] },
      context: { agentId: "a" },
      policy,
    });
    expect(d.findings.map((f) => f.ruleId)).not.toContain("engine_error");
    // Without prefetch the reputation rule fails closed.
    expect(d.verdict).toBe("escalate");
    await r.reputation!.prefetch({ id: "x", chain: "evm", from: "0x1111111111111111111111111111111111111111", to: "0xbad0000000000000000000000000000000000bad" });
    const d2 = await r.engine.evaluate({
      intent: { id: "x", chain: "evm", from: "0x1111111111111111111111111111111111111111", to: "0xbad0000000000000000000000000000000000bad" },
      simulation: { ok: true, deltas: [], approvals: [], contractsTouched: [], newContracts: [], warnings: [] },
      context: { agentId: "a" },
      policy,
    });
    expect(d2.verdict).toBe("block");
  });

  it("can disable each layer explicitly", async () => {
    const r = await bootstrap({ evmRpcUrl: "http://127.0.0.1:1", profilePath: false, behaviorModule: STUB_BEHAVIOR_MODULE, reputation: false, log: quiet });
    expect(r.behavior).toBeUndefined();
    expect(r.reputation).toBeUndefined();
    expect(r.policies.get(r.defaultPolicyId)!.rules.some((x) => x.kind === "custom")).toBe(false);
  });

  it("rejects a non-http reputation URL", async () => {
    await expect(bootstrap({ evmRpcUrl: "http://127.0.0.1:1", reputationHttpUrl: "file:///etc/passwd", log: quiet })).rejects.toThrow(/http\(s\)/);
  });
});
