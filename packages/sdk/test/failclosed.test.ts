import { describe, expect, it, vi } from "vitest";
import { AgentGuardClient, AgentGuardClientError, GuardEscalatedError, guard } from "../src/index.js";
import { decisionJson, jsonResponse, mockFetch } from "./helpers.js";

interface EvmTx { to: string; value: bigint }
const toIntent = (tx: EvmTx) => ({ chain: "evm" as const, from: "0x1111111111111111111111111111111111111111", to: tx.to, value: tx.value });
const tx: EvmTx = { to: "0x2222222222222222222222222222222222222222", value: 1n };

function signer() {
  return { sendTransaction: vi.fn(async () => "hash"), signTransaction: vi.fn(async () => "sig") };
}

/** The SDK must never let a transaction through when the check itself fails. */
describe("guard() fails closed", () => {
  it("does not call the signer when the API is unreachable", async () => {
    const { fetch } = mockFetch(new Error("ECONNREFUSED"));
    const s = signer();
    const g = guard(s, new AgentGuardClient({ baseUrl: "http://gw", fetch, retries: 0 }), { toIntent, context: { agentId: "a" } });
    await expect(g.sendTransaction(tx)).rejects.toBeInstanceOf(AgentGuardClientError);
    expect(s.sendTransaction).not.toHaveBeenCalled();
  });

  it("does not call the signer on 5xx, 429, 401 or 400", async () => {
    for (const status of [500, 429, 401, 400]) {
      const { fetch } = mockFetch(jsonResponse(status, { error: "x" }));
      const s = signer();
      const g = guard(s, new AgentGuardClient({ baseUrl: "http://gw", fetch, retries: 0 }), { toIntent, context: { agentId: "a" } });
      await expect(g.sendTransaction(tx)).rejects.toBeInstanceOf(AgentGuardClientError);
      expect(s.sendTransaction).not.toHaveBeenCalled();
    }
  });

  it("treats malformed or unknown verdicts as escalation", async () => {
    for (const body of [
      { decision: { ...decisionJson("allow"), verdict: "ALLOW" }, auditId: "a" },
      { decision: { ...decisionJson("allow"), verdict: undefined }, auditId: "a" },
      { auditId: "a" },
      "not json at all",
      null,
    ]) {
      const { fetch } = mockFetch(() => new Response(typeof body === "string" ? body : JSON.stringify(body), { status: 200 }));
      const s = signer();
      const g = guard(s, new AgentGuardClient({ baseUrl: "http://gw", fetch, retries: 0 }), { toIntent, context: { agentId: "a" } });
      await expect(g.sendTransaction(tx)).rejects.toBeInstanceOf(AgentGuardClientError);
      expect(s.sendTransaction).not.toHaveBeenCalled();
    }
  });

  it("does not call the signer when onEscalate / onDecision / toIntent / context throw", async () => {
    const { fetch } = mockFetch(jsonResponse(200, { decision: decisionJson("escalate"), auditId: "a" }));
    const client = new AgentGuardClient({ baseUrl: "http://gw", fetch });
    const s1 = signer();
    await expect(guard(s1, client, { toIntent, context: { agentId: "a" }, onEscalate: () => { throw new Error("ui down"); } }).sendTransaction(tx)).rejects.toThrow("ui down");
    expect(s1.sendTransaction).not.toHaveBeenCalled();

    const { fetch: f2 } = mockFetch(jsonResponse(200, { decision: decisionJson("allow"), auditId: "a" }));
    const c2 = new AgentGuardClient({ baseUrl: "http://gw", fetch: f2 });
    const s2 = signer();
    await expect(guard(s2, c2, { toIntent, context: { agentId: "a" }, onDecision: () => { throw new Error("metrics"); } }).sendTransaction(tx)).rejects.toThrow("metrics");
    expect(s2.sendTransaction).not.toHaveBeenCalled();

    const s3 = signer();
    await expect(guard(s3, c2, { toIntent: () => { throw new Error("map"); }, context: { agentId: "a" } }).sendTransaction(tx)).rejects.toThrow("map");
    expect(s3.sendTransaction).not.toHaveBeenCalled();

    const s4 = signer();
    await expect(guard(s4, c2, { toIntent, context: () => { throw new Error("ctx"); } }).sendTransaction(tx)).rejects.toThrow("ctx");
    expect(s4.sendTransaction).not.toHaveBeenCalled();
  });

  it("only a literal `true` from onEscalate proceeds", async () => {
    for (const ret of [1, "true", {}, [], null, undefined, false]) {
      const { fetch } = mockFetch(jsonResponse(200, { decision: decisionJson("escalate"), auditId: "a" }));
      const s = signer();
      const g = guard(s, new AgentGuardClient({ baseUrl: "http://gw", fetch }), { toIntent, context: { agentId: "a" }, onEscalate: () => ret as never });
      await expect(g.sendTransaction(tx)).rejects.toBeInstanceOf(GuardEscalatedError);
      expect(s.sendTransaction).not.toHaveBeenCalled();
    }
  });
});
