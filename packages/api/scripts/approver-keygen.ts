#!/usr/bin/env tsx
/**
 * Generate an Ed25519 approver key pair for server-verified human approval (I-HITL).
 *
 *   npx tsx packages/api/scripts/approver-keygen.ts --id ops-phone [--out ./ops-phone.key]
 *
 * Prints the AGENTGUARD_APPROVER_KEYS entry for the server (public half only) and
 * writes the private key (PKCS#8 PEM, mode 0600) to --out, or to stdout when --out
 * is omitted.
 *
 * THE PRIVATE KEY IS THE HUMAN'S CREDENTIAL. Run this ON THE APPROVER DEVICE and keep
 * the key there: a phone keystore, an HSM, a hardware key, or at minimum an operator
 * laptop that the agent cannot reach. Never copy it to the agent host, the AgentGuard
 * host, CI, or a shared secrets store the agent can read. If the agent can read this
 * key, approval is no longer inalienable: the agent can approve itself.
 */
import { generateKeyPairSync } from "node:crypto";
import { writeFileSync } from "node:fs";

const ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;

function usage(code: number, msg?: string): never {
  if (msg) console.error(`error: ${msg}`);
  console.error("usage: approver-keygen.ts --id <keyId> [--out <private-key-file>]");
  process.exit(code);
}

function main(): void {
  const argv = process.argv.slice(2);
  let id: string | undefined;
  let out: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--id") id = argv[++i];
    else if (a === "--out") out = argv[++i];
    else if (a === "-h" || a === "--help") usage(0);
    else usage(2, `unexpected argument '${a}'`);
  }
  if (!id) usage(2, "--id is required");
  if (!ID_RE.test(id)) usage(2, `--id must match ${ID_RE}`);

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const rawPub = (publicKey.export({ type: "spki", format: "der" }) as Buffer).subarray(-32);
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  console.log("# Register the PUBLIC key on the AgentGuard server (append to existing entries with a comma):");
  console.log(`AGENTGUARD_APPROVER_KEYS=${id}:${rawPub.toString("base64")}`);
  console.log();
  if (out) {
    writeFileSync(out, privatePem, { mode: 0o600, flag: "wx" });
    console.log(`# PRIVATE key written to ${out} (mode 0600). Keep it on this device only.`);
  } else {
    console.log("# PRIVATE key (keep on the approver device only; pass --out to write it to a file instead):");
    console.log(privatePem.trimEnd());
  }
  console.log();
  console.log(`# Approve an escalation from this device:`);
  console.log(`#   npx tsx packages/api/scripts/approve.ts --key ${out ?? "<private-key-file>"} --key-id ${id} --audit-id <auditId> --challenge <challenge> [--url https://agentguard --api-key <approver api key>]`);
}

main();
