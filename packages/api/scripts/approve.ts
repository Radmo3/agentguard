#!/usr/bin/env tsx
/**
 * Approver device CLI: show a human the escalated transaction, obtain their explicit
 * confirmation, sign the server-bound challenge with the approver private key, and
 * (optionally) submit it to the AgentGuard API.
 *
 *   # fetch the sealed record from the server with the DEVICE's own API key, show it, sign, submit
 *   npx tsx packages/api/scripts/approve.ts --key ./ops-phone.key --key-id ops-phone \
 *       --audit-id <auditId> --url https://agentguard --api-key <approver api key> [--reason "..."]
 *
 *   # offline: the sealed record was obtained out of band (GET /v1/audit/:auditId); print the signed body
 *   npx tsx packages/api/scripts/approve.ts --key ./ops-phone.key --key-id ops-phone \
 *       --audit-id <auditId> --record ./audit-record.json [--challenge <64 hex>]
 *
 * I-HITL "trusted display" rule (Breckenridge et al., arXiv:2610.35835): the human must
 * see, on a display the agent cannot drive, exactly the action they approve. So this
 * CLI never signs a bare challenge. It always obtains the sealed audit record from the
 * server (or from a file obtained out of band), recomputes the challenge from that
 * record, shows the decoded transaction, and refuses to sign if a --challenge passed
 * on the command line (which may have come through the agent) does not match.
 *
 * The terminal is the trusted display only if this process runs on a host the agent
 * cannot reach. --yes skips the interactive confirmation and exists for tests and
 * scripted demos; a production approver must not use it.
 */
import { readFile } from "node:fs/promises";
import { sign as edSign } from "node:crypto";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import {
  computeApprovalChallenge,
  CHALLENGE_RE,
  toDecimal,
  type ApprovalSubmission,
  type AuditRecord,
} from "@agentguard/core";
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
  yes?: boolean;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function usage(code: number, msg?: string): never {
  if (msg) console.error(`error: ${msg}`);
  console.error(
    "usage: approve.ts --key <private-key-file> --key-id <keyId> --audit-id <uuid> (--url <api base url> --api-key <key> | --record <audit-record.json>) [--challenge <64 hex>] [--reason <text>] [--yes]",
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
    else if (x === "--yes") a.yes = true;
    else if (x === "-h" || x === "--help") usage(0);
    else usage(2, `unexpected argument '${x}'`);
  }
  if (!a.key || !a.keyId || !a.auditId) usage(2, "--key, --key-id and --audit-id are required");
  if (!UUID_RE.test(a.auditId)) usage(2, "--audit-id must be a UUID");
  if (a.challenge !== undefined && !CHALLENGE_RE.test(a.challenge)) usage(2, "--challenge must be 64 lowercase hex characters");
  if ((a.url && !a.apiKey) || (!a.url && a.apiKey)) usage(2, "--url and --api-key go together");
  if (a.url && !/^https?:\/\//.test(a.url)) usage(2, "--url must be an http(s) URL");
  if (!a.url && !a.record) {
    usage(2, "REFUSING TO SIGN a bare challenge: the record must be fetched (--url/--api-key) or supplied (--record) so the transaction can be shown before signing");
  }
  return a;
}

async function loadRecord(args: Args): Promise<AuditRecord> {
  if (args.url) {
    const res = await fetch(`${args.url.replace(/\/+$/, "")}/v1/audit/${args.auditId}`, {
      headers: { accept: "application/json", "x-api-key": args.apiKey! },
    });
    if (!res.ok) throw new Error(`could not fetch audit record: HTTP ${res.status}`);
    return reviveAuditRecord(JSON.parse(await res.text()));
  }
  return reviveAuditRecord(JSON.parse(await readFile(args.record!, "utf8")));
}

const short = (s: string) => (s.length > 18 ? `${s.slice(0, 10)}…${s.slice(-6)}` : s);
const stripControl = (s: string) => s.replace(/[\u0000-\u001f\u007f-\u009f]/g, "").slice(0, 200);

function display(rec: AuditRecord): void {
  const { intent, decision } = rec;
  const sim = decision.simulation;
  const line = (s: string) => console.error(s);
  line("");
  line("================ ESCALATED TRANSACTION — REVIEW BEFORE APPROVING ================");
  line(`audit id   : ${rec.id}`);
  line(`agent      : ${rec.context.agentId}${rec.context.tenantId ? ` (tenant ${rec.context.tenantId})` : ""}`);
  line(`chain      : ${intent.chain}${intent.chainId !== undefined ? ` / ${intent.chainId}` : ""}`);
  line(`from       : ${intent.from}`);
  line(`to         : ${intent.to ?? "(none)"}`);
  if (intent.value !== undefined) line(`native val : ${intent.value.toString()} base units`);
  if (sim) {
    line(`simulation : ${sim.ok ? "ok" : `FAILED${sim.revertReason ? ` (${sim.revertReason})` : ""}`}`);
    if (sim.recipients?.length) line(`recipients : ${sim.recipients.join(", ")}`);
    for (const d of sim.deltas) {
      const amt = toDecimal(d.amount, d.decimals);
      line(`  delta    : ${amt > 0 ? "+" : ""}${amt} ${d.symbol ?? short(d.asset)}${d.usdValue !== undefined ? ` (~$${d.usdValue.toFixed(2)})` : ""}`);
    }
    for (const a of sim.approvals) {
      line(`  approval : ${short(a.token)} -> spender ${a.spender}${a.unlimited ? " UNLIMITED" : ` ${a.next.toString()}`}${a.spenderIsContract === false ? " (EOA spender)" : ""}`);
    }
    if (sim.contractsTouched.length) line(`contracts  : ${sim.contractsTouched.join(", ")}`);
    if (sim.newContracts.length) line(`NEW/unknown: ${sim.newContracts.join(", ")}`);
    for (const w of sim.warnings) line(`  warning  : ${w}`);
  }
  line(`verdict    : ${decision.verdict}  risk ${decision.riskScore}/100  policy ${decision.policyId}@${decision.policyVersion}`);
  for (const f of decision.findings) line(`  finding  : [${f.verdict}] ${f.ruleId}: ${f.message}`);
  line(`explanation: ${decision.explanation}`);
  if (intent.description) {
    line(`AGENT-SUPPLIED TEXT (untrusted, not evidence): ${JSON.stringify(stripControl(intent.description))}`);
  }
  line("===================================================================================");
  line("");
}

async function confirm(args: Args): Promise<void> {
  if (args.yes) {
    console.error("warning: --yes given; interactive confirmation skipped (not for production approvers)");
    return;
  }
  if (!stdin.isTTY) {
    throw new Error("REFUSING TO SIGN: no interactive terminal to confirm on (pass --yes only for tests)");
  }
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    const answer = await rl.question("Type APPROVE to sign this transaction, anything else to abort: ");
    if (answer.trim() !== "APPROVE") throw new Error("aborted by approver");
  } finally {
    rl.close();
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const privateKey = loadEd25519PrivateKey(await readFile(args.key!, "utf8"));

  const rec = await loadRecord(args);
  if (rec.id !== args.auditId) throw new Error(`record id ${rec.id} does not match --audit-id`);
  if (rec.decision.verdict !== "escalate") throw new Error(`record verdict is '${rec.decision.verdict}'; only escalate decisions are approvable`);
  if (!rec.approvalRequest) throw new Error("record carries no approvalRequest (server had no approver keys when it was issued)");

  const challenge = computeApprovalChallenge({
    auditId: rec.id,
    intent: rec.intent,
    decision: rec.decision,
    policyId: rec.decision.policyId,
    policyVersion: rec.decision.policyVersion,
    agentId: rec.context.agentId,
    issuedAt: rec.approvalRequest.issuedAt,
  });
  if (rec.approvalRequest.challenge !== challenge) {
    throw new Error("REFUSING TO SIGN: the record's challenge does not match the record's own contents (record tampered)");
  }
  if (args.challenge !== undefined && args.challenge !== challenge) {
    throw new Error("REFUSING TO SIGN: --challenge does not match the challenge bound to this audit record");
  }

  display(rec);
  console.error(`challenge ${challenge} recomputed from the sealed record`);
  await confirm(args);

  const submission: ApprovalSubmission = {
    auditId: rec.id,
    keyId: args.keyId!,
    signature: edSign(null, Buffer.from(challenge, "utf8"), privateKey).toString("base64"),
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
