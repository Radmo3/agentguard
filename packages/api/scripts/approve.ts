#!/usr/bin/env tsx
/**
 * Approver device CLI: sign an escalation challenge with an approver private key and
 * (optionally) submit it to the AgentGuard API.
 *
 *   npx tsx packages/api/scripts/approve.ts --key ./ops-phone.key --key-id ops-phone \
 *       --audit-id <auditId> --challenge <64 hex> [--reason "..."] \
 *       [--record ./audit-record.json] [--url https://agentguard --api-key <approver api key>]
 *
 * Without --url the signed approval JSON is printed, to be delivered to the API by
 * any channel (the body of POST /v1/approvals). With --url it is POSTed directly.
 *
 * --record <file>: the sealed check record (GET /v1/audit/:auditId). When given, the
 * CLI recomputes the challenge from the record and REFUSES to sign if it differs from
 * --challenge, so the human is signing exactly the transaction shown in that record
 * and not a value an agent made up. Use it whenever the challenge reached you through
 * the agent.
 *
 * This CLI stands in for the "trusted device" of the I-HITL design. In production the
 * private key lives on a phone keystore, HSM or hardware key; the only requirement is
 * that the agent process cannot read it or ask it to sign.
 */
import { readFile } from "node:fs/promises";
import { sign as edSign } from "node:crypto";
import { computeApprovalChallenge, CHALLENGE_RE, type ApprovalSubmission } from "@agentguard/core";
import { loadEd25519PrivateKey } from "../src/integrity.js";
import { reviveAuditRecord } from "../src/serialization.js";

interface Args {
  key?: string;
  keyId?: string;
  auditId?: string;
  challenge?: string;
  reason?: string;
  record?: string;
  url?: string;
  apiKey?: string;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function usage(code: number, msg?: string): never {
  if (msg) console.error(`error: ${msg}`);
  console.error(
    "usage: approve.ts --key <private-key-file> --key-id <keyId> --audit-id <uuid> --challenge <64 hex> [--reason <text>] [--record <audit-record.json>] [--url <api base url> --api-key <key>]",
  );
  process.exit(code);
}

function parseArgs(argv: string[]): Args {
  const a: Args = {};
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    const next = () => argv[++i] ?? usage(2, `missing value for ${x}`);
    if (x === "--key") a.key = next();
    else if (x === "--key-id") a.keyId = next();
    else if (x === "--audit-id") a.auditId = next();
    else if (x === "--challenge") a.challenge = next();
    else if (x === "--reason") a.reason = next();
    else if (x === "--record") a.record = next();
    else if (x === "--url") a.url = next();
    else if (x === "--api-key") a.apiKey = next();
    else if (x === "-h" || x === "--help") usage(0);
    else usage(2, `unexpected argument '${x}'`);
  }
  if (!a.key || !a.keyId || !a.auditId || !a.challenge) usage(2, "--key, --key-id, --audit-id and --challenge are required");
  if (!UUID_RE.test(a.auditId)) usage(2, "--audit-id must be a UUID");
  if (!CHALLENGE_RE.test(a.challenge)) usage(2, "--challenge must be 64 lowercase hex characters");
  if ((a.url && !a.apiKey) || (!a.url && a.apiKey)) usage(2, "--url and --api-key go together");
  if (a.url && !/^https?:\/\//.test(a.url)) usage(2, "--url must be an http(s) URL");
  return a;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const privateKey = loadEd25519PrivateKey(await readFile(args.key!, "utf8"));

  if (args.record) {
    const rec = reviveAuditRecord(JSON.parse(await readFile(args.record, "utf8")));
    if (rec.id !== args.auditId) throw new Error(`record id ${rec.id} does not match --audit-id`);
    if (rec.decision.verdict !== "escalate") throw new Error(`record verdict is '${rec.decision.verdict}'; only escalate decisions are approvable`);
    if (!rec.approvalRequest) throw new Error("record carries no approvalRequest (server had no approver keys when it was issued)");
    const recomputed = computeApprovalChallenge({
      auditId: rec.id,
      intent: rec.intent,
      decision: rec.decision,
      policyId: rec.decision.policyId,
      policyVersion: rec.decision.policyVersion,
      agentId: rec.context.agentId,
      issuedAt: rec.approvalRequest.issuedAt,
    });
    if (recomputed !== args.challenge || rec.approvalRequest.challenge !== args.challenge) {
      throw new Error("REFUSING TO SIGN: --challenge does not match the challenge bound to this audit record");
    }
    console.error(`record ${rec.id}: ${rec.intent.chain} from ${rec.intent.from} to ${rec.intent.to ?? "(n/a)"}; verdict escalate; risk ${rec.decision.riskScore}/100`);
    console.error(`  ${rec.decision.explanation}`);
    console.error(`  challenge verified against the record`);
  }

  const submission: ApprovalSubmission = {
    auditId: args.auditId!,
    keyId: args.keyId!,
    signature: edSign(null, Buffer.from(args.challenge!, "utf8"), privateKey).toString("base64"),
    approvedAt: new Date().toISOString(),
  };
  if (args.reason) submission.reason = args.reason;

  if (!args.url) {
    console.log(JSON.stringify(submission, null, 2));
    return;
  }

  const res = await fetch(`${args.url.replace(/\/+$/, "")}/v1/approvals`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json", "x-api-key": args.apiKey! },
    body: JSON.stringify(submission),
  });
  const text = await res.text();
  console.log(`${res.status} ${text}`);
  process.exit(res.ok ? 0 : 1);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
