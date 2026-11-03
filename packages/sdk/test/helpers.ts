import { vi } from "vitest";
import type { Decision } from "@agentguard/core";
import type { FetchLike } from "../src/client.js";

export function decisionJson(verdict: Decision["verdict"], intentId = "intent-1") {
  return {
    intentId,
    verdict,
    findings: verdict === "allow" ? [] : [{ ruleId: "r", kind: "max_tx_usd", verdict, message: "nope" }],
    riskScore: verdict === "allow" ? 3 : 90,
    explanation: `because ${verdict}`,
    simulation: {
      ok: true,
      deltas: [{ asset: "native", decimals: 18, amount: "-5000000000000000000" }],
      approvals: [{ token: "t", spender: "s", previous: "0", next: "115792089237316195423570985008687907853269984665640564039457584007913129639935", unlimited: true }],
      contractsTouched: [],
      newContracts: [],
      gasEstimate: "21000",
      warnings: [],
    },
    policyId: "p",
    policyVersion: 1,
    evaluatedAt: "2026-01-01T00:00:00.000Z",
  };
}

/** Returns a factory so each fetch call gets a fresh, unconsumed Response. */
export function jsonResponse(status: number, body: unknown): () => Response {
  return () => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** Mock fetch returning the given responses in order (functions are called lazily). */
export function mockFetch(...responses: Array<Response | Error | (() => Response | Error | Promise<Response>)>) {
  let i = 0;
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fn = vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const next = responses[Math.min(i++, responses.length - 1)];
    const v = typeof next === "function" ? await next() : next;
    if (v instanceof Error) throw v;
    return v;
  }) as unknown as FetchLike & { mock: { calls: unknown[][] } };
  return { fetch: fn, calls };
}
