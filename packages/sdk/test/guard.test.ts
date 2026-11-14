import { describe, expect, it, vi } from "vitest";
import { SignholdClient, GuardBlockedError, GuardEscalatedError, guard } from "../src/index.js";
import { decisionJson, jsonResponse, mockFetch } from "./helpers.js";

interface EvmTx { to: string; value: bigint; data?: `0x${string}` }

function makeSigner() {
  return {
    address: "0xagent",
    signTransaction: vi.fn(async (tx: EvmTx) => `signed:${tx.to}`),
    sendTransaction: vi.fn(async (tx: EvmTx) => `hash:${tx.to}`),
    getChainId: () => 1,
  };
}

function clientWith(verdict: "allow" | "block" | "escalate") {
  const { fetch, calls } = mockFetch(jsonResponse(200, { decision: decisionJson(verdict), auditId: `aud-${verdict}` }));
  return { client: new SignholdClient({ baseUrl: "http://gw", fetch }), calls };
}

const toIntent = (tx: EvmTx) => ({ chain: "evm" as const, chainId: 1, from: "0xagent", to: tx.to, value: tx.value, data: tx.data });
const tx: EvmTx = { to: "0xdest", value: 7n, data: "0xabcd" };

describe("guard()", () => {
  it("checks then passes through on allow, keeping other props intact", async () => {
    const signer = makeSigner();
    const { client, calls } = clientWith("allow");
    const g = guard(signer, client, { toIntent, context: { agentId: "agent" }, generateId: () => "intent-1" });

    expect(await g.sendTransaction(tx)).toBe("hash:0xdest");
    expect(await g.signTransaction(tx)).toBe("signed:0xdest");
    expect(g.address).toBe("0xagent");
    expect(g.getChainId()).toBe(1);
    expect(g.__signholdInner).toBe(signer);
    expect(signer.sendTransaction).toHaveBeenCalledWith(tx);
    expect(calls).toHaveLength(2);
    const body = JSON.parse(calls[0].init.body as string);
    expect(body.intent).toMatchObject({ id: "intent-1", chain: "evm", to: "0xdest", value: "7", data: "0xabcd" });
  });

  it("throws GuardBlockedError and never calls the signer on block", async () => {
    const signer = makeSigner();
    const { client } = clientWith("block");
    const g = guard(signer, client, { toIntent, context: { agentId: "agent" } });
    const err = await g.sendTransaction(tx).catch((e) => e);
    expect(err).toBeInstanceOf(GuardBlockedError);
    expect(err.auditId).toBe("aud-block");
    expect(err.decision.verdict).toBe("block");
    expect(signer.sendTransaction).not.toHaveBeenCalled();
  });

  it("throws GuardEscalatedError by default on escalate", async () => {
    const signer = makeSigner();
    const { client } = clientWith("escalate");
    const g = guard(signer, client, { toIntent, context: { agentId: "agent" } });
    await expect(g.signTransaction(tx)).rejects.toBeInstanceOf(GuardEscalatedError);
    expect(signer.signTransaction).not.toHaveBeenCalled();
  });

  it("advisory mode (approval: \"callback\") invokes onEscalate; proceeds only when it returns true", async () => {
    const signer = makeSigner();
    const { client } = clientWith("escalate");
    const onEscalate = vi.fn(async () => true);
    const warn = vi.fn();
    const g = guard(signer, client, { toIntent, context: { agentId: "agent" }, approval: "callback", onEscalate, warn });
    expect(await g.sendTransaction(tx)).toBe("hash:0xdest");
    expect(onEscalate).toHaveBeenCalledOnce();
    expect(onEscalate.mock.calls[0][0]).toMatchObject({ method: "sendTransaction", auditId: "aud-escalate" });

    const g2 = guard(makeSigner(), client, { toIntent, context: { agentId: "agent" }, approval: "callback", onEscalate: () => false, warn });
    await expect(g2.sendTransaction(tx)).rejects.toBeInstanceOf(GuardEscalatedError);
  });

  it("supports async toIntent + context functions and onDecision (Solana-style wrapper)", async () => {
    const keypairWrapper = { signTransaction: vi.fn(async (raw: string) => `sig:${raw}`) };
    const { client, calls } = clientWith("allow");
    const onDecision = vi.fn();
    const g = guard(keypairWrapper, client, {
      toIntent: async (raw: string) => ({ chain: "solana" as const, chainId: "mainnet-beta", from: "So1", raw }),
      context: async (intent) => ({ agentId: `sol-${intent.chain}` }),
      onDecision,
    });
    expect(await g.signTransaction("AAAA")).toBe("sig:AAAA");
    const body = JSON.parse(calls[0].init.body as string);
    expect(body.intent.raw).toBe("AAAA");
    expect(body.context.agentId).toBe("sol-solana");
    expect(typeof body.intent.id).toBe("string");
    expect(onDecision).toHaveBeenCalledOnce();
  });
});
