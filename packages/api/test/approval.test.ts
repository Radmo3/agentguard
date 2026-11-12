/**
 * Server-verified human approval (I-HITL, arXiv:2610.35835).
 *
 * The property under test: the only way an `escalate` decision becomes an
 * approval is a valid Ed25519 signature, by a key registered on the server, over
 * the challenge the server issued for that exact audit record, inside the window,
 * once. Everything else is a generic 403 and an `approval_rejected` audit record.
 */
import { execFile } from "node:child_process";
import { generateKeyPairSync, sign as edSign, type KeyObject } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { AuditRecord } from "@agentguard/core";
import { computeApprovalChallenge } from "@agentguard/core";
import { ApproverRegistry, PendingApprovalStore, parseApproverKeysEnv, summarizeApprovals } from "../src/approvals.js";
import { InMemoryAuditStore, JsonlAuditStore } from "../src/audit.js";
import { createEd25519Signer, keyIdOf, loadEd25519PublicKey, verifyChain } from "../src/integrity.js";
import { createServer } from "../src/server.js";
import type { ServerOptions } from "../src/types.js";
import { stringifyWithBigints } from "../src/serialization.js";
import { FakeAdapter, FakeEngine, intentId, requestBody, testPolicy } from "./fakes.js";

const execFileP = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const tsx = join(here, "..", "..", "..", "node_modules", ".bin", "tsx");
const script = (name: string) => join(here, "..", "scripts", name);

// ---- "Trusted device": an Ed25519 key pair that only this helper ever touches ----
interface Device {
  keyId: string;
  publicKeyB64: string;
  privateKey: KeyObject;
  sign(challenge: string): string;
}
function device(keyId: string): Device {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = (publicKey.export({ type: "spki", format: "der" }) as Buffer).subarray(-32);
  return {
    keyId,
    publicKeyB64: raw.toString("base64"),
    privateKey,
    sign: (challenge) => edSign(null, Buffer.from(challenge, "utf8"), privateKey).toString("base64"),
  };
}

const AGENT_KEY = "agent-api-key";
const APPROVER_API_KEY = "approver-api-key";
const agentHeaders = { "x-api-key": AGENT_KEY };
const approverHeaders = { "x-api-key": APPROVER_API_KEY };

async function build(opts: Partial<ServerOptions> & { verdict?: "allow" | "block" | "escalate"; devices?: Device[]; now?: () => number } = {}) {
  const { verdict = "escalate", devices = [], now, ...rest } = opts;
  const engine = new FakeEngine(verdict);
  const signer = createEd25519Signer(generateKeyPairSync("ed25519").privateKey);
  const pk = loadEd25519PublicKey(signer.publicKeyPem);
  const audit = new InMemoryAuditStore({ signer });
  const app = await createServer({
    engine,
    adapters: { evm: new FakeAdapter("evm") },
    policies: new Map([[testPolicy.id, testPolicy]]),
    audit,
    apiKeys: [{ id: "agent", key: AGENT_KEY }, { id: "approver-device", key: APPROVER_API_KEY }],
    auditPublicKeys: new Map([[keyIdOf(pk), pk]]),
    approvers: devices.map((d) => ({ keyId: d.keyId, publicKey: d.publicKeyB64 })),
    approvals: { ttlMs: 60_000, clockSkewMs: 5_000, now },
    logger: false,
    rateLimit: false,
    env: "test",
    ...rest,
  });
  return { app, audit, engine, auditPublicKeys: new Map([[keyIdOf(pk), pk]]) };
}

async function check(app: FastifyInstance, n = 1) {
  const body = requestBody();
  (body.intent as Record<string, unknown>).id = intentId(n);
  const res = await app.inject({ method: "POST", url: "/v1/check", payload: body, headers: agentHeaders });
  expect(res.statusCode).toBe(200);
  return res.json() as { decision: { verdict: string }; auditId: string; approval?: { challenge: string; expiresAt: string } };
}

function submission(d: Device, auditId: string, challenge: string, over: Record<string, unknown> = {}) {
  return { auditId, keyId: d.keyId, signature: d.sign(challenge), approvedAt: new Date().toISOString(), ...over };
}

async function approve(app: FastifyInstance, body: unknown, headers: Record<string, string> = approverHeaders) {
  const res = await app.inject({ method: "POST", url: "/v1/approvals", payload: body, headers });
  return { res, json: res.json() as Record<string, unknown> };
}

async function statusOf(app: FastifyInstance, auditId: string) {
  const res = await app.inject({ method: "GET", url: `/v1/approvals/${auditId}`, headers: agentHeaders });
  expect(res.statusCode).toBe(200);
  return res.json() as { status: string; expiresAt?: string; approvedBy?: string; approvalId?: string };
}

describe("escalation binding", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("an escalate decision carries a challenge bound to the sealed audit record; allow/block do not", async () => {
    const phone = device("ops-phone");
    const built = await build({ devices: [phone] });
    app = built.app;
    const r = await check(app);
    expect(r.decision.verdict).toBe("escalate");
    expect(r.approval?.challenge).toMatch(/^[0-9a-f]{64}$/);
    expect(Date.parse(r.approval!.expiresAt)).toBeGreaterThan(Date.now());

    const rec = (await built.audit.get(r.auditId))!;
    expect(rec.type).toBe("check");
    expect(rec.approvalRequest?.challenge).toBe(r.approval!.challenge);
    // Deterministic and recomputable by anyone holding the record.
    const recomputed = computeApprovalChallenge({
      auditId: rec.id, intent: rec.intent, decision: rec.decision, policyId: rec.decision.policyId,
      policyVersion: rec.decision.policyVersion, agentId: rec.context.agentId, issuedAt: rec.approvalRequest!.issuedAt,
    });
    expect(recomputed).toBe(r.approval!.challenge);
    // and sealed into the signed chain
    expect(verifyChain([rec], { publicKeys: built.auditPublicKeys, requireSignatures: true }).ok).toBe(true);

    for (const verdict of ["allow", "block"] as const) {
      const b = await build({ devices: [phone], verdict });
      const rr = await check(b.app);
      expect(rr.decision.verdict).toBe(verdict);
      expect(rr.approval).toBeUndefined();
      expect((await b.audit.get(rr.auditId))!.approvalRequest).toBeUndefined();
      await b.app.close();
    }
  });

  it("without registered approver keys an escalation has no challenge and status is unknown", async () => {
    ({ app } = await build({ devices: [] }));
    const r = await check(app);
    expect(r.decision.verdict).toBe("escalate");
    expect(r.approval).toBeUndefined();
    expect((await statusOf(app, r.auditId)).status).toBe("unknown");
  });

  it("the challenge changes when any bound field changes", () => {
    const base = {
      auditId: "a", policyId: "p", policyVersion: 1, agentId: "ag", issuedAt: "2026-01-01T00:00:00.000Z",
      intent: { id: "i", chain: "evm" as const, from: "0x1", value: 5n },
      decision: { intentId: "i", verdict: "escalate" as const, findings: [], riskScore: 50, explanation: "x", policyId: "p", policyVersion: 1, evaluatedAt: "t", simulation: { ok: true, deltas: [], approvals: [], contractsTouched: [], newContracts: [], warnings: [], rawTrace: { huge: true } } },
    };
    const c0 = computeApprovalChallenge(base);
    expect(computeApprovalChallenge({ ...base, intent: { ...base.intent, value: 6n } })).not.toBe(c0);
    expect(computeApprovalChallenge({ ...base, auditId: "b" })).not.toBe(c0);
    expect(computeApprovalChallenge({ ...base, agentId: "other" })).not.toBe(c0);
    expect(computeApprovalChallenge({ ...base, policyVersion: 2 })).not.toBe(c0);
    expect(computeApprovalChallenge({ ...base, issuedAt: "2026-01-01T00:00:01.000Z" })).not.toBe(c0);
    expect(computeApprovalChallenge({ ...base, decision: { ...base.decision, verdict: "allow" } })).not.toBe(c0);
    // rawTrace is explicitly excluded
    expect(computeApprovalChallenge({ ...base, decision: { ...base.decision, simulation: { ...base.decision.simulation, rawTrace: undefined } } })).toBe(c0);
  });
});

describe("POST /v1/approvals", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("happy path: registered device signs the challenge -> allow, single use, chained audit record", async () => {
    const phone = device("ops-phone");
    const built = await build({ devices: [phone] });
    app = built.app;
    const r = await check(app);
    expect((await statusOf(app, r.auditId)).status).toBe("pending");

    const { res, json } = await approve(app, submission(phone, r.auditId, r.approval!.challenge, { reason: "looks fine\u0000\u001b" }));
    expect(res.statusCode).toBe(200);
    expect(json).toMatchObject({ verdict: "allow", auditId: r.auditId });
    expect(typeof json.approvalId).toBe("string");
    expect(typeof json.approvalAuditId).toBe("string");

    const st = await statusOf(app, r.auditId);
    expect(st).toMatchObject({ status: "approved", approvedBy: "ops-phone", approvalId: json.approvalId });

    const rec = (await built.audit.get(json.approvalAuditId as string))!;
    expect(rec.type).toBe("approval");
    expect(rec.approval).toMatchObject({ checkAuditId: r.auditId, challenge: r.approval!.challenge, outcome: "approved", approverKeyId: "ops-phone", approvalId: json.approvalId, reason: "looks fine" });
    expect(rec.principal).toMatchObject({ approverKeyId: "ops-phone", apiKeyId: "approver-device" });
    expect(rec.intent.id).toBe(intentId(1));
    const chain = await built.audit.range(0, 10);
    expect(chain.map((x) => x.type)).toEqual(["check", "approval"]);
    expect(verifyChain(chain, { publicKeys: built.auditPublicKeys, requireSignatures: true }).ok).toBe(true);
    const prov = summarizeApprovals(chain);
    expect(prov).toHaveLength(1);
    expect(prov[0]).toMatchObject({ type: "approval", checkAuditId: r.auditId, checkSeq: 0, seq: 1, approverKeyId: "ops-phone", problems: [] });
  });

  const rejectionCases: Array<{ name: string; run: (ctx: { app: FastifyInstance; phone: Device; r: Awaited<ReturnType<typeof check>> }) => Promise<unknown>; finalStatus?: string }> = [
    {
      name: "wrong key (registered id, signature from a different private key)",
      run: ({ app, phone, r }) => approve(app, { ...submission(device("imposter"), r.auditId, r.approval!.challenge), keyId: phone.keyId }),
      finalStatus: "rejected",
    },
    {
      name: "unregistered key (valid signature, unknown id)",
      run: ({ app, r }) => { const other = device("not-registered"); return approve(app, submission(other, r.auditId, r.approval!.challenge)); },
      finalStatus: "rejected",
    },
    {
      name: "signature over a different challenge",
      run: ({ app, phone, r }) => approve(app, submission(phone, r.auditId, "b".repeat(64))),
      finalStatus: "rejected",
    },
    {
      name: "tampered auditId (signature valid for a different record's challenge)",
      run: async ({ app, phone, r }) => {
        const r2 = await check(app, 2);
        return approve(app, { ...submission(phone, r2.auditId, r2.approval!.challenge), auditId: r.auditId });
      },
      finalStatus: "rejected",
    },
    {
      name: "unknown auditId",
      run: ({ app, phone, r }) => approve(app, submission(phone, "99999999-9999-4999-8999-999999999999", r.approval!.challenge)),
      finalStatus: "pending",
    },
    {
      name: "approvedAt before the challenge was issued",
      run: ({ app, phone, r }) => approve(app, submission(phone, r.auditId, r.approval!.challenge, { approvedAt: "2020-01-01T00:00:00.000Z" })),
      finalStatus: "rejected",
    },
    {
      name: "approvedAt after expiry",
      run: ({ app, phone, r }) => approve(app, submission(phone, r.auditId, r.approval!.challenge, { approvedAt: "2099-01-01T00:00:00.000Z" })),
      finalStatus: "rejected",
    },
  ];

  for (const c of rejectionCases) {
    it(`rejects: ${c.name} -> generic 403 + approval_rejected audit record`, async () => {
      const phone = device("ops-phone");
      const built = await build({ devices: [phone] });
      app = built.app;
      const r = await check(app);
      const { res, json } = (await c.run({ app, phone, r })) as { res: { statusCode: number }; json: Record<string, unknown> };
      expect(res.statusCode).toBe(403);
      expect(json).toEqual({ error: "approval_rejected", message: "approval could not be verified", requestId: expect.any(String) });
      expect((await statusOf(app, r.auditId)).status).toBe(c.finalStatus);
      const rejected = (await built.audit.range(0, 100)).filter((x) => x.type === "approval_rejected");
      if (c.finalStatus === "pending") {
        expect(rejected).toHaveLength(0); // unknown audit id: nothing to link, logged only
      } else {
        expect(rejected).toHaveLength(1);
        expect(rejected[0].approval).toMatchObject({ checkAuditId: r.auditId, outcome: "rejected" });
        expect(rejected[0].approval!.rejectionReason).toBeTruthy();
        expect(summarizeApprovals(await built.audit.range(0, 100))[0]).toMatchObject({ type: "approval_rejected", problems: [] });
      }
      // A burned challenge can no longer be approved, even with a perfectly valid signature.
      if (c.finalStatus === "rejected") {
        const again = await approve(app, submission(phone, r.auditId, r.approval!.challenge));
        expect(again.res.statusCode).toBe(403);
      }
    });
  }

  it("rejects an expired challenge and the status becomes `expired`", async () => {
    let t = Date.parse("2026-01-01T00:00:00.000Z");
    const phone = device("ops-phone");
    ({ app } = await build({ devices: [phone], now: () => t }));
    const r = await check(app);
    expect(r.approval!.expiresAt).toBe(new Date(t + 60_000).toISOString());
    t += 61_000;
    expect((await statusOf(app, r.auditId)).status).toBe("expired");
    const { res } = await approve(app, submission(phone, r.auditId, r.approval!.challenge, { approvedAt: new Date(t).toISOString() }));
    expect(res.statusCode).toBe(403);
    expect((await statusOf(app, r.auditId)).status).toBe("expired");
  });

  it("replay: the same valid approval cannot be used twice, and the first stays approved", async () => {
    const phone = device("ops-phone");
    const built = await build({ devices: [phone] });
    app = built.app;
    const r = await check(app);
    const body = submission(phone, r.auditId, r.approval!.challenge);
    expect((await approve(app, body)).res.statusCode).toBe(200);
    expect((await approve(app, body)).res.statusCode).toBe(403);
    expect((await approve(app, submission(phone, r.auditId, r.approval!.challenge))).res.statusCode).toBe(403);
    expect((await statusOf(app, r.auditId)).status).toBe("approved");
    const types = (await built.audit.range(0, 100)).map((x) => x.type);
    expect(types).toEqual(["check", "approval", "approval_rejected", "approval_rejected"]);
    expect(summarizeApprovals(await built.audit.range(0, 100)).filter((p) => p.type === "approval")).toHaveLength(1);
  });

  it("concurrent valid submissions: exactly one wins", async () => {
    const phone = device("ops-phone");
    ({ app } = await build({ devices: [phone] }));
    const r = await check(app);
    const results = await Promise.all(Array.from({ length: 5 }, () => approve(app, submission(phone, r.auditId, r.approval!.challenge))));
    expect(results.filter((x) => x.res.statusCode === 200)).toHaveLength(1);
    expect(results.filter((x) => x.res.statusCode === 403)).toHaveLength(4);
  });

  for (const verdict of ["block", "allow"] as const) {
    it(`refuses an approval for a '${verdict}' decision (only escalate is approvable)`, async () => {
      const phone = device("ops-phone");
      const built = await build({ devices: [phone], verdict });
      app = built.app;
      const r = await check(app);
      const rec = (await built.audit.get(r.auditId))!;
      // Even if the device signs what the challenge *would* be, there is nothing pending to approve.
      const wouldBe = computeApprovalChallenge({ auditId: rec.id, intent: rec.intent, decision: rec.decision, policyId: rec.decision.policyId, policyVersion: rec.decision.policyVersion, agentId: rec.context.agentId, issuedAt: rec.recordedAt });
      const { res, json } = await approve(app, submission(phone, r.auditId, wouldBe));
      expect(res.statusCode).toBe(403);
      expect(json.error).toBe("approval_rejected");
      expect((await statusOf(app, r.auditId)).status).toBe("unknown");
      const rejected = (await built.audit.range(0, 100)).filter((x) => x.type === "approval_rejected");
      expect(rejected).toHaveLength(1);
      expect(rejected[0].approval!.rejectionReason).toContain("not_escalate");
    });
  }

  it("malformed bodies are 400 (strict schema) and never create audit records", async () => {
    const phone = device("ops-phone");
    const built = await build({ devices: [phone] });
    app = built.app;
    const r = await check(app);
    const good = submission(phone, r.auditId, r.approval!.challenge);
    const bad: unknown[] = [
      {},
      { ...good, extra: 1 },
      { ...good, auditId: "not-a-uuid" },
      { ...good, keyId: "bad id!" },
      { ...good, signature: "short" },
      { ...good, signature: good.signature.slice(0, 87) + "!" },
      { ...good, signature: Buffer.alloc(63).toString("base64") },
      { ...good, approvedAt: "yesterday" },
      { ...good, reason: "x".repeat(600) },
      { ...good, approvedAt: 12345 },
      [good],
      "nope",
    ];
    for (const b of bad) {
      const res = await app.inject({ method: "POST", url: "/v1/approvals", payload: typeof b === "string" ? JSON.stringify(b) : b, headers: { ...approverHeaders, "content-type": "application/json" } });
      expect(res.statusCode, JSON.stringify(b)).toBe(400);
      expect(res.json().error).toBe("bad_request");
      expect(JSON.stringify(res.json())).not.toContain(good.signature);
    }
    expect((await built.audit.range(0, 100)).map((x) => x.type)).toEqual(["check"]);
    expect((await statusOf(app, r.auditId)).status).toBe("pending");
    // the challenge was not burned by schema-level garbage: a real approval still works
    expect((await approve(app, good)).res.statusCode).toBe(200);
  });

  it("requires API key auth and the rate limiter covers it", async () => {
    const phone = device("ops-phone");
    ({ app } = await build({ devices: [phone], rateLimit: { max: 3, timeWindowMs: 60_000 } }));
    const r = await check(app);
    const noKey = await app.inject({ method: "POST", url: "/v1/approvals", payload: submission(phone, r.auditId, r.approval!.challenge) });
    expect(noKey.statusCode).toBe(401);
    let last = 0;
    for (let i = 0; i < 5; i++) last = (await approve(app, submission(device("x"), r.auditId, r.approval!.challenge))).res.statusCode;
    expect(last).toBe(429);
  });

  it("fails closed when the audit store cannot record the approval", async () => {
    const phone = device("ops-phone");
    const built = await build({ devices: [phone] });
    app = built.app;
    const r = await check(app);
    const orig = built.audit.record.bind(built.audit);
    let fail = true;
    built.audit.record = async (rec: AuditRecord) => {
      if (fail && rec.type === "approval") throw new Error("disk full");
      return orig(rec);
    };
    const { res } = await approve(app, submission(phone, r.auditId, r.approval!.challenge));
    expect(res.statusCode).toBe(503);
    expect(res.json().error).toBe("audit_unavailable");
    expect((await statusOf(app, r.auditId)).status).toBe("rejected");
    fail = false;
    expect((await approve(app, submission(phone, r.auditId, r.approval!.challenge))).res.statusCode).toBe(403);
  });
});

describe("GET /v1/approvals/:auditId", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("reports pending -> approved with approver identity; unknown ids are unknown; it is read-only", async () => {
    const phone = device("ops-phone");
    ({ app } = await build({ devices: [phone] }));
    const r = await check(app);
    expect(await statusOf(app, r.auditId)).toEqual({ auditId: r.auditId, status: "pending", expiresAt: r.approval!.expiresAt });
    expect((await statusOf(app, "99999999-9999-4999-8999-999999999999")).status).toBe("unknown");
    expect((await app.inject({ method: "GET", url: "/v1/approvals/not-a-uuid", headers: agentHeaders })).statusCode).toBe(404);
    expect((await app.inject({ method: "GET", url: `/v1/approvals/${r.auditId}` })).statusCode).toBe(401);
    // polling a hundred times changes nothing
    for (let i = 0; i < 100; i++) expect((await statusOf(app, r.auditId)).status).toBe("pending");
    await approve(app, submission(phone, r.auditId, r.approval!.challenge));
    const st = await statusOf(app, r.auditId);
    expect(st).toMatchObject({ status: "approved", approvedBy: "ops-phone", expiresAt: r.approval!.expiresAt });
    expect(typeof st.approvalId).toBe("string");
  });
});

describe("approver key registry", () => {
  it("parses AGENTGUARD_APPROVER_KEYS and refuses malformed entries", () => {
    const a = device("a"), b = device("b.c-d_e");
    const parsed = parseApproverKeysEnv(` a:${a.publicKeyB64}, ${b.keyId}:${b.publicKeyB64} `);
    expect(parsed.map((k) => k.keyId)).toEqual(["a", "b.c-d_e"]);
    expect(parseApproverKeysEnv(undefined)).toEqual([]);
    expect(() => parseApproverKeysEnv("nocolon")).toThrow();
    expect(() => parseApproverKeysEnv("a:")).toThrow();
    expect(() => parseApproverKeysEnv(":abc")).toThrow();
    expect(() => parseApproverKeysEnv("bad id:" + a.publicKeyB64)).toThrow();
    expect(() => new ApproverRegistry(parseApproverKeysEnv("a:notakey"))).toThrow();
    expect(() => new ApproverRegistry([{ keyId: "a", publicKey: a.publicKeyB64 }, { keyId: "a", publicKey: b.publicKeyB64 }])).toThrow(/duplicate/);
    expect(() => new ApproverRegistry([{ keyId: "a", publicKey: a.publicKeyB64 }, { keyId: "b", publicKey: a.publicKeyB64 }])).toThrow(/same key/);
  });

  it("refuses to register the audit signing key as an approver (key separation)", async () => {
    const signer = createEd25519Signer(generateKeyPairSync("ed25519").privateKey);
    const pk = loadEd25519PublicKey(signer.publicKeyPem);
    await expect(
      createServer({
        engine: new FakeEngine(), adapters: { evm: new FakeAdapter("evm") }, policies: new Map([[testPolicy.id, testPolicy]]),
        audit: new InMemoryAuditStore({ signer }), auditPublicKeys: new Map([[keyIdOf(pk), pk]]),
        approvers: [{ keyId: "sneaky", publicKey: signer.publicKeyPem }], logger: false, rateLimit: false, env: "test",
      }),
    ).rejects.toThrow(/server-held key/);
  });

  it("verify() is false for unknown ids, garbage signatures and foreign keys; true only for the registered key", () => {
    const a = device("a");
    const reg = new ApproverRegistry([{ keyId: "a", publicKey: a.publicKeyB64 }]);
    const ch = "c".repeat(64);
    expect(reg.verify("a", ch, a.sign(ch))).toBe(true);
    expect(reg.verify("b", ch, a.sign(ch))).toBe(false);
    expect(reg.verify("a", ch, device("x").sign(ch))).toBe(false);
    expect(reg.verify("a", "d".repeat(64), a.sign(ch))).toBe(false);
    expect(reg.verify("a", ch, "not base64 at all!!")).toBe(false);
    expect(reg.verify("a", ch, "")).toBe(false);
    expect(reg.verify("a", ch, Buffer.alloc(64).toString("base64"))).toBe(false);
  });
});

describe("PendingApprovalStore", () => {
  it("is bounded and evicts settled/expired entries first", () => {
    let t = 1_000_000;
    const s = new PendingApprovalStore({ ttlMs: 1000, maxPending: 3, now: () => t });
    const issue = (id: string) => s.issue({ auditId: id, challenge: "0".repeat(64), issuedAt: new Date(t).toISOString(), expiresAt: new Date(t + 1000).toISOString(), agentId: "a" });
    issue("1"); issue("2"); issue("3");
    expect(() => issue("1")).toThrow(/already issued/);
    s.reject("2");
    issue("4"); // evicts "2" (settled)
    expect(s.get("2")).toBeUndefined();
    expect(s.size).toBe(3);
    t += 2000;
    issue("5"); // everything else expired
    expect(s.status("1").status).toBe("unknown");
    expect(s.status("5").status).toBe("pending");
    expect(s.claim("5", { keyId: "k", approvedAt: "x" })).toBeTruthy();
    expect(s.claim("5", { keyId: "k", approvedAt: "x" })).toBeUndefined();
    expect(s.status("5")).toMatchObject({ status: "approved" });
    s.invalidate("5");
    expect(s.status("5").status).toBe("rejected");
    expect(() => new PendingApprovalStore({ ttlMs: 0 })).toThrow();
  });
});

describe("approver tooling (the 'trusted device') end to end", () => {
  let dir: string;
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it("keygen -> escalate -> approve.ts refuses a mismatched challenge, signs the right one -> verify-audit lists the provenance", async () => {
    dir = await mkdtemp(join(tmpdir(), "agentguard-approver-"));
    const keyFile = join(dir, "ops-phone.key");

    // 1. Key generation happens on the device; only the public half goes to the server.
    const gen = await execFileP(tsx, [script("approver-keygen.ts"), "--id", "ops-phone", "--out", keyFile]);
    const envLine = /AGENTGUARD_APPROVER_KEYS=(\S+)/.exec(gen.stdout)![1];
    expect(gen.stdout).not.toContain("PRIVATE KEY-----"); // the private key went to the file, not stdout
    expect(await readFile(keyFile, "utf8")).toContain("-----BEGIN PRIVATE KEY-----");
    const approvers = parseApproverKeysEnv(envLine);
    expect(approvers).toEqual([{ keyId: "ops-phone", publicKey: expect.any(String) }]);

    // 2. Server with those keys and a JSONL audit file.
    const auditFile = join(dir, "audit.jsonl");
    const signer = createEd25519Signer(generateKeyPairSync("ed25519").privateKey);
    const pem = join(dir, "audit-pub.pem");
    await writeFile(pem, signer.publicKeyPem);
    app = await createServer({
      engine: new FakeEngine("escalate"), adapters: { evm: new FakeAdapter("evm") }, policies: new Map([[testPolicy.id, testPolicy]]),
      audit: new JsonlAuditStore(auditFile, { signer }), apiKeys: [{ id: "agent", key: AGENT_KEY }, { id: "approver-device", key: APPROVER_API_KEY }],
      approvers, logger: false, rateLimit: false, env: "test",
    });
    const r = await check(app);
    const recordFile = join(dir, "record.json");
    const recRes = await app.inject({ method: "GET", url: `/v1/audit/${r.auditId}`, headers: agentHeaders });
    await writeFile(recordFile, recRes.body);

    // 3. The device refuses to sign a challenge that does not match the record it is shown.
    const forged = "f".repeat(64);
    const refused = await execFileP(tsx, [script("approve.ts"), "--key", keyFile, "--key-id", "ops-phone", "--audit-id", r.auditId, "--challenge", forged, "--record", recordFile]).catch((e: { code: number; stderr: string }) => e);
    expect(refused.code).toBe(1);
    expect(refused.stderr).toContain("REFUSING TO SIGN");

    // 4. It signs the genuine one; the output is exactly the POST /v1/approvals body.
    const signed = await execFileP(tsx, [script("approve.ts"), "--key", keyFile, "--key-id", "ops-phone", "--audit-id", r.auditId, "--challenge", r.approval!.challenge, "--record", recordFile, "--reason", "checked with ops"]);
    const body = JSON.parse(signed.stdout) as Record<string, unknown>;
    expect(body).toMatchObject({ auditId: r.auditId, keyId: "ops-phone", reason: "checked with ops" });
    const { res } = await approve(app, body);
    expect(res.statusCode).toBe(200);
    expect((await statusOf(app, r.auditId)).status).toBe("approved");
    // the same signed body cannot be submitted again
    expect((await approve(app, body)).res.statusCode).toBe(403);

    // 5. Offline verification lists the approval chain: check -> approval -> rejected replay.
    const okRun = await execFileP(tsx, [script("verify-audit.ts"), auditFile, "--public-key", pem, "--require-signatures"]);
    expect(okRun.stdout).toContain("approvals: 1 approved, 1 rejected attempt(s)");
    expect(okRun.stdout).toMatch(/seq=1 approval\s+-> check seq=0 key=ops-phone at=/);
    expect(okRun.stdout).toMatch(/seq=2 approval_rejected -> check seq=0 key=ops-phone reason=already_used/);
    expect(okRun.stdout).toContain("OK: audit chain verified; approval provenance intact");
    const asJson = await execFileP(tsx, [script("verify-audit.ts"), auditFile, "--json"]);
    expect(JSON.parse(asJson.stdout).approvals).toHaveLength(2);

    // 6. Re-pointing the approval at another record breaks both the hash chain and the provenance.
    const lines = (await readFile(auditFile, "utf8")).trim().split("\n");
    const approvalLine = JSON.parse(lines[1]);
    approvalLine.approval.checkAuditId = "99999999-9999-4999-8999-999999999999";
    lines[1] = stringifyWithBigints(approvalLine);
    await writeFile(auditFile, lines.join("\n") + "\n");
    const failRun = await execFileP(tsx, [script("verify-audit.ts"), auditFile, "--json"]).catch((e: { code: number; stdout: string }) => e);
    expect(failRun.code).toBe(1);
    const out = JSON.parse(failRun.stdout);
    expect(out.failures[0].reason).toBe("hash_mismatch");
    expect(out.approvals[0].problems).toContain("missing_check");
  }, 60_000);
});

describe("summarizeApprovals", () => {
  it("flags approvals that do not link to an escalated check with the same challenge, but not recorded rejections", () => {
    const base = (id: string, verdict: "allow" | "escalate", challenge?: string): AuditRecord => ({
      id, type: "check", recordedAt: "t", intent: { id: "i", chain: "evm", from: "0x1" }, context: { agentId: "a" },
      decision: { intentId: "i", verdict, findings: [], riskScore: 1, explanation: "", policyId: "p", policyVersion: 1, evaluatedAt: "t" },
      ...(challenge ? { approvalRequest: { challenge, issuedAt: "t", expiresAt: "t" } } : {}),
    });
    const appr = (id: string, checkAuditId: string, challenge: string, type: "approval" | "approval_rejected"): AuditRecord => ({
      ...base(id, "escalate"), type, approval: { checkAuditId, challenge, outcome: type === "approval" ? "approved" : "rejected" },
    });
    const C = "c".repeat(64);
    const out = summarizeApprovals([
      base("esc", "escalate", C), base("alw", "allow"),
      appr("ok", "esc", C, "approval"),
      appr("dup", "esc", C, "approval"),
      appr("wrongch", "esc", "d".repeat(64), "approval"),
      appr("onallow", "alw", C, "approval"),
      appr("dangling", "nope", C, "approval"),
      appr("rej-allow", "alw", "", "approval_rejected"),
      appr("rej-dangling", "nope", "", "approval_rejected"),
    ]);
    expect(Object.fromEntries(out.map((p) => [p.recordId, p.problems]))).toEqual({
      ok: [], dup: ["duplicate_approval"], wrongch: ["challenge_mismatch", "duplicate_approval"], onallow: ["check_not_escalate", "challenge_mismatch"],
      dangling: ["missing_check"], "rej-allow": [], "rej-dangling": ["missing_check"],
    });
  });
});
