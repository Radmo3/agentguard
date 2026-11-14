import { describe, expect, it } from "vitest";
import type { TransactionIntent } from "@signhold/core";
import { SignholdClient, SignholdHttpError, SignholdNetworkError, SignholdTimeoutError } from "../src/index.js";
import { decisionJson, jsonResponse, mockFetch } from "./helpers.js";

const intent: TransactionIntent = { id: "intent-1", chain: "evm", from: "0xa", to: "0xb", value: 42n, data: "0x01" };
const ctx = { agentId: "agent" };

describe("SignholdClient.check", () => {
  it("serialises bigints as strings, sends api key, revives bigints in the response", async () => {
    const { fetch, calls } = mockFetch(jsonResponse(200, { decision: decisionJson("allow"), auditId: "aud-1" }));
    const client = new SignholdClient({ baseUrl: "http://gw/", apiKey: "k", fetch, policyId: "default" });
    const res = await client.check(intent, ctx);

    expect(calls[0].url).toBe("http://gw/v1/check");
    expect(calls[0].init.method).toBe("POST");
    expect((calls[0].init.headers as Record<string, string>)["x-api-key"]).toBe("k");
    const sent = JSON.parse(calls[0].init.body as string);
    expect(sent.intent.value).toBe("42");
    expect(sent.policyId).toBe("default");
    expect(sent.context.agentId).toBe("agent");

    expect(res.auditId).toBe("aud-1");
    expect(res.decision.verdict).toBe("allow");
    expect(res.decision.simulation?.deltas[0].amount).toBe(-5_000_000_000_000_000_000n);
    expect(res.decision.simulation?.approvals[0].next).toBe((1n << 256n) - 1n);
    expect(res.decision.simulation?.gasEstimate).toBe(21_000n);
  });

  it("retries on 5xx then succeeds", async () => {
    const { fetch, calls } = mockFetch(
      jsonResponse(503, { error: "x" }),
      jsonResponse(500, { error: "y" }),
      jsonResponse(200, { decision: decisionJson("allow"), auditId: "aud-2" }),
    );
    const client = new SignholdClient({ baseUrl: "http://gw", fetch, retries: 2, retryBackoffMs: 1 });
    const res = await client.check(intent, ctx);
    expect(res.auditId).toBe("aud-2");
    expect(calls).toHaveLength(3);
  });

  it("gives up after retries with the last HTTP error", async () => {
    const { fetch, calls } = mockFetch(jsonResponse(502, { message: "bad gateway" }));
    const client = new SignholdClient({ baseUrl: "http://gw", fetch, retries: 1, retryBackoffMs: 1 });
    const err = await client.check(intent, ctx).catch((e) => e);
    expect(err).toBeInstanceOf(SignholdHttpError);
    expect(err.status).toBe(502);
    expect(err.code).toBe("server_error");
    expect(err.message).toContain("bad gateway");
    expect(calls).toHaveLength(2);
  });

  it("does not retry 4xx and surfaces typed error", async () => {
    const { fetch, calls } = mockFetch(jsonResponse(401, { error: "unauthorized", message: "missing key" }));
    const client = new SignholdClient({ baseUrl: "http://gw", fetch, retryBackoffMs: 1 });
    const err = await client.check(intent, ctx).catch((e) => e);
    expect(err).toBeInstanceOf(SignholdHttpError);
    expect(err.code).toBe("unauthorized");
    expect(err.body.message).toBe("missing key");
    expect(calls).toHaveLength(1);
  });

  it("retries network errors", async () => {
    const { fetch, calls } = mockFetch(new Error("ECONNREFUSED"), jsonResponse(200, { decision: decisionJson("allow"), auditId: "a" }));
    const client = new SignholdClient({ baseUrl: "http://gw", fetch, retryBackoffMs: 1 });
    await client.check(intent, ctx);
    expect(calls).toHaveLength(2);
  });

  it("times out and reports SignholdTimeoutError", async () => {
    const fetch = async (_url: string, init: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => reject(init.signal!.reason));
      });
    const client = new SignholdClient({ baseUrl: "http://gw", fetch, timeoutMs: 10, retries: 0 });
    const err = await client.check(intent, ctx).catch((e) => e);
    expect(err).toBeInstanceOf(SignholdTimeoutError);
    expect(err).toBeInstanceOf(SignholdNetworkError);
    expect(err.code).toBe("timeout");
  });

  it("fetches and revives audit records", async () => {
    const record = {
      id: "aud-9",
      recordedAt: "2026-01-01T00:00:00.000Z",
      intent: { ...intent, value: "42" },
      decision: decisionJson("block"),
      context: { agentId: "agent", now: "2026-01-01T00:00:00.000Z" },
    };
    const { fetch, calls } = mockFetch(jsonResponse(200, record), jsonResponse(200, { items: [record], nextCursor: "1" }));
    const client = new SignholdClient({ baseUrl: "http://gw", fetch });
    const one = await client.getAudit("aud-9");
    expect(one.intent.value).toBe(42n);
    expect(one.context.now).toBeInstanceOf(Date);
    const page = await client.listAudit({ agentId: "agent", limit: 1 });
    expect(calls[1].url).toBe("http://gw/v1/audit?agentId=agent&limit=1");
    expect(page.items[0].decision.verdict).toBe("block");
    expect(page.nextCursor).toBe("1");
  });
});
