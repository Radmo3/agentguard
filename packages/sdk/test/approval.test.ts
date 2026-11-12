/**
 * Server-verified human approval (I-HITL) from the SDK's side. The invariant under
 * test: nothing in this process can turn `escalate` into permission to sign. The
 * SDK can only *observe* an approval the server verified.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ADVISORY_MODE_WARNING,
  AgentGuardClient,
  AgentGuardProtocolError,
  ApprovalDeniedError,
  ApprovalTimeoutError,
  GuardEscalatedError,
  __resetAdvisoryWarning,
  guard,
} from "../src/index.js";
import { decisionJson, jsonResponse, mockFetch } from "./helpers.js";

interface EvmTx { to: string; value: bigint }
const toIntent = (tx: EvmTx) => ({ chain: "evm" as const, from: "0x1111111111111111111111111111111111111111", to: tx.to, value: tx.value });
const tx: EvmTx = { to: "0x2222222222222222222222222222222222222222", value: 1n };
const AUDIT = "7d2e1c3a-1111-4222-8333-444455556666";
const CHALLENGE = "a".repeat(64);
const EXPIRES = "2026-01-01T00:15:00.000Z";

const escalateResponse = () => jsonResponse(200, { decision: decisionJson("escalate"), auditId: AUDIT, approval: { challenge: CHALLENGE, expiresAt: EXPIRES } });
const status = (s: string, extra: Record<string, unknown> = {}) => jsonResponse(200, { auditId: AUDIT, status: s, expiresAt: EXPIRES, ...extra });
const approvedStatus = () => status("approved", { approvedBy: "ops-phone", approvalId: "appr-1", approvedAt: "2026-01-01T00:01:00.000Z" });

function signer() {
  return { sendTransaction: vi.fn(async () => "hash"), signTransaction: vi.fn(async () => "sig") };
}

describe("client.check surfaces the approval challenge", () => {
  it("passes `approval` through and rejects a malformed one", async () => {
    const { fetch } = mockFetch(escalateResponse());
    const c = new AgentGuardClient({ baseUrl: "http://gw", fetch });
    const res = await c.check({ id: "i", chain: "evm", from: "0x1" }, { agentId: "a" });
    expect(res.approval).toEqual({ challenge: CHALLENGE, expiresAt: EXPIRES });

    const bad = mockFetch(jsonResponse(200, { decision: decisionJson("escalate"), auditId: AUDIT, approval: { challenge: "zz", expiresAt: EXPIRES } }));
    const c2 = new AgentGuardClient({ baseUrl: "http://gw", fetch: bad.fetch });
    await expect(c2.check({ id: "i", chain: "evm", from: "0x1" }, { agentId: "a" })).rejects.toBeInstanceOf(AgentGuardProtocolError);
  });
});

describe("client.waitForApproval", () => {
  it("polls GET /v1/approvals/:auditId and resolves on a literal `approved`", async () => {
    const { fetch, calls } = mockFetch(status("pending"), status("pending"), approvedStatus());
    const c = new AgentGuardClient({ baseUrl: "http://gw", fetch });
    const polls: string[] = [];
    const granted = await c.waitForApproval(AUDIT, { intervalMs: 50, timeoutMs: 5_000, onPoll: (s) => void polls.push(s.status) });
    expect(granted).toEqual({ auditId: AUDIT, status: "approved", approvedBy: "ops-phone", approvalId: "appr-1", approvedAt: "2026-01-01T00:01:00.000Z" });
    expect(polls).toEqual(["pending", "pending", "approved"]);
    for (const call of calls) {
      expect(call.init.method).toBe("GET");
      expect(call.url).toBe(`http://gw/v1/approvals/${AUDIT}`);
      expect(call.init.body).toBeUndefined();
    }
  });

  it("times out while pending", async () => {
    const { fetch } = mockFetch(status("pending"));
    const c = new AgentGuardClient({ baseUrl: "http://gw", fetch });
    const err = await c.waitForApproval(AUDIT, { intervalMs: 50, timeoutMs: 200 }).catch((e) => e);
    expect(err).toBeInstanceOf(ApprovalTimeoutError);
    expect(err.lastStatus).toBe("pending");
  });

  for (const terminal of ["expired", "rejected", "unknown"]) {
    it(`throws ApprovalDeniedError on '${terminal}' without waiting`, async () => {
      const { fetch, calls } = mockFetch(status(terminal));
      const c = new AgentGuardClient({ baseUrl: "http://gw", fetch });
      const err = await c.waitForApproval(AUDIT, { intervalMs: 50, timeoutMs: 5_000 }).catch((e) => e);
      expect(err).toBeInstanceOf(ApprovalDeniedError);
      expect(err.status).toBe(terminal);
      expect(calls).toHaveLength(1);
    });
  }

  it("fails closed on malformed status bodies and on a status for a different audit id", async () => {
    for (const body of [
      { auditId: AUDIT, status: "APPROVED" },
      { auditId: AUDIT, status: "approved" }, // approved but no approvedBy / approvalId
      { auditId: "other", status: "approved", approvedBy: "x", approvalId: "y" },
      { status: "approved", approvedBy: "x", approvalId: "y" },
      "approved",
      null,
    ]) {
      const { fetch } = mockFetch(() => new Response(typeof body === "string" ? body : JSON.stringify(body), { status: 200 }));
      const c = new AgentGuardClient({ baseUrl: "http://gw", fetch, retries: 0 });
      await expect(c.waitForApproval(AUDIT, { intervalMs: 50, timeoutMs: 1_000 })).rejects.toBeInstanceOf(AgentGuardProtocolError);
    }
  });

  it("a 4xx while polling is not an approval", async () => {
    const { fetch } = mockFetch(jsonResponse(403, { error: "forbidden" }));
    const c = new AgentGuardClient({ baseUrl: "http://gw", fetch, retries: 0 });
    await expect(c.waitForApproval(AUDIT, { intervalMs: 50, timeoutMs: 1_000 })).rejects.toThrow();
  });
});

describe("guard() in server mode (default)", () => {
  beforeEach(() => __resetAdvisoryWarning());
  afterEach(() => __resetAdvisoryWarning());

  it("throws GuardEscalatedError carrying auditId + challenge, never calls the signer", async () => {
    const { fetch } = mockFetch(escalateResponse());
    const s = signer();
    const g = guard(s, new AgentGuardClient({ baseUrl: "http://gw", fetch }), { toIntent, context: { agentId: "a" } });
    const err = await g.sendTransaction(tx).catch((e) => e);
    expect(err).toBeInstanceOf(GuardEscalatedError);
    expect(err.auditId).toBe(AUDIT);
    expect(err.challenge).toBe(CHALLENGE);
    expect(err.approvalExpiresAt).toBe(EXPIRES);
    expect(s.sendTransaction).not.toHaveBeenCalled();
  });

  it("refuses a local onEscalate callback at construction time (it cannot approve anything)", () => {
    const { fetch } = mockFetch(escalateResponse());
    const client = new AgentGuardClient({ baseUrl: "http://gw", fetch });
    const onEscalate = vi.fn(async () => true);
    expect(() => guard(signer(), client, { toIntent, context: { agentId: "a" }, onEscalate })).toThrow(/onEscalate is not allowed/);
    expect(() => guard(signer(), client, { toIntent, context: { agentId: "a" }, approval: "server", onEscalate })).toThrow(/onEscalate is not allowed/);
    expect(onEscalate).not.toHaveBeenCalled();
  });

  it("never consults any local callback on escalate, even one injected after construction", async () => {
    const { fetch } = mockFetch(escalateResponse());
    const s = signer();
    const opts = { toIntent, context: { agentId: "a" } } as Parameters<typeof guard>[2];
    const g = guard(s, new AgentGuardClient({ baseUrl: "http://gw", fetch }), opts);
    // A compromised agent mutating the options object after the fact gains nothing.
    const injected = vi.fn(async () => true);
    (opts as { onEscalate?: unknown }).onEscalate = injected;
    (opts as { approval?: unknown }).approval = "callback";
    await expect(g.sendTransaction(tx)).rejects.toBeInstanceOf(GuardEscalatedError);
    expect(injected).not.toHaveBeenCalled();
    expect(s.sendTransaction).not.toHaveBeenCalled();
  });

  it("onEscalationPending is notified but its return value cannot approve", async () => {
    const { fetch } = mockFetch(escalateResponse());
    const s = signer();
    const pending = vi.fn(async () => true as unknown as void);
    const g = guard(s, new AgentGuardClient({ baseUrl: "http://gw", fetch }), { toIntent, context: { agentId: "a" }, onEscalationPending: pending });
    await expect(g.sendTransaction(tx)).rejects.toBeInstanceOf(GuardEscalatedError);
    expect(pending).toHaveBeenCalledOnce();
    expect(pending.mock.calls[0][0]).toMatchObject({ auditId: AUDIT, approval: { challenge: CHALLENGE } });
    expect(s.sendTransaction).not.toHaveBeenCalled();
  });

  it("with waitForApproval: signs only after the server reports `approved`", async () => {
    const { fetch, calls } = mockFetch(escalateResponse(), status("pending"), approvedStatus());
    const s = signer();
    const g = guard(s, new AgentGuardClient({ baseUrl: "http://gw", fetch }), {
      toIntent, context: { agentId: "a" }, waitForApproval: { intervalMs: 50, timeoutMs: 5_000 },
    });
    expect(await g.sendTransaction(tx)).toBe("hash");
    expect(s.sendTransaction).toHaveBeenCalledOnce();
    expect(calls.map((c) => c.init.method)).toEqual(["POST", "GET", "GET"]);
  });

  it("with waitForApproval: timeout / expiry / rejection never reach the signer", async () => {
    for (const responses of [
      [escalateResponse(), status("pending")],
      [escalateResponse(), status("expired")],
      [escalateResponse(), status("rejected")],
      [escalateResponse(), status("unknown")],
    ]) {
      const { fetch } = mockFetch(...responses);
      const s = signer();
      const g = guard(s, new AgentGuardClient({ baseUrl: "http://gw", fetch }), {
        toIntent, context: { agentId: "a" }, waitForApproval: { intervalMs: 50, timeoutMs: 150 },
      });
      await expect(g.sendTransaction(tx)).rejects.toThrow();
      expect(s.sendTransaction).not.toHaveBeenCalled();
    }
  });

  it("with waitForApproval but no challenge from the server (no approver keys registered) it throws immediately", async () => {
    const { fetch, calls } = mockFetch(jsonResponse(200, { decision: decisionJson("escalate"), auditId: AUDIT }));
    const s = signer();
    const g = guard(s, new AgentGuardClient({ baseUrl: "http://gw", fetch }), { toIntent, context: { agentId: "a" }, waitForApproval: true });
    const err = await g.sendTransaction(tx).catch((e) => e);
    expect(err).toBeInstanceOf(GuardEscalatedError);
    expect(err.message).toContain("no approver keys");
    expect(calls).toHaveLength(1);
    expect(s.sendTransaction).not.toHaveBeenCalled();
  });
});

describe("guard() advisory mode (approval: \"callback\")", () => {
  beforeEach(() => __resetAdvisoryWarning());
  afterEach(() => __resetAdvisoryWarning());

  it("warns loudly exactly once per process", () => {
    const { fetch } = mockFetch(escalateResponse());
    const client = new AgentGuardClient({ baseUrl: "http://gw", fetch });
    const warn = vi.fn();
    guard(signer(), client, { toIntent, context: { agentId: "a" }, approval: "callback", onEscalate: () => true, warn });
    guard(signer(), client, { toIntent, context: { agentId: "a" }, approval: "callback", onEscalate: () => true, warn });
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0][0]).toBe(ADVISORY_MODE_WARNING);
    expect(ADVISORY_MODE_WARNING).toMatch(/NOT inalienable/);
  });

  it("requires an onEscalate function and rejects waitForApproval", () => {
    const { fetch } = mockFetch(escalateResponse());
    const client = new AgentGuardClient({ baseUrl: "http://gw", fetch });
    expect(() => guard(signer(), client, { toIntent, context: { agentId: "a" }, approval: "callback", warn: () => {} })).toThrow(/requires an onEscalate/);
    expect(() => guard(signer(), client, { toIntent, context: { agentId: "a" }, approval: "callback", onEscalate: () => true, waitForApproval: true, warn: () => {} })).toThrow(/waitForApproval/);
  });
});
