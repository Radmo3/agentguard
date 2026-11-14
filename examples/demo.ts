/**
 * Signhold end-to-end demo.
 *
 * Starts the HTTP API in-process with the real policy engine, the conservative
 * default policy extended with the reputation rule, and EVM / Solana adapters
 * backed by in-memory mock RPC clients (no network), then submits transactions
 * through the SDK client:
 *
 *   (a) small ERC-20 transfer                       -> allow
 *   (b) unlimited ERC-20 approve                    -> block
 *   (c) call into an unknown new contract           -> escalate
 *   (d) Solana SPL token transfer                   -> allow
 *   (e) bounded ERC-20 approve to an EOA            -> block   (no protocol needs an EOA spender)
 *   (f) transfer to a denylisted contract           -> block   (contract reputation)
 *   (g) reputation provider outage                  -> escalate (fail closed)
 *   (h) escalated tx + human approval (I-HITL)      -> escalate, then: the agent's own approval
 *       attempt is refused (403), the approver device signs the challenge, the server
 *       verifies it and the status becomes `approved`
 *
 * The behavioral anomaly layer (`@signhold/behavior`, separately licensed) is not
 * part of this repository; when installed it plugs into `createServer` through
 * `ServerOptions.behavior` and adds the "learned baseline then drain" detection.
 *
 * Run with: npx tsx examples/demo.ts
 */
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { encodeAbiParameters, encodeFunctionData, type Hex } from "viem";
import {
  Keypair, PublicKey, SystemProgram, TransactionMessage, VersionedTransaction,
  type AccountInfo, type SimulatedTransactionResponse,
} from "@solana/web3.js";
import { ACCOUNT_SIZE, AccountLayout, MINT_SIZE, MintLayout, TOKEN_PROGRAM_ID, createTransferCheckedInstruction } from "@solana/spl-token";
import { UINT256_MAX, type AgentContext, type TransactionIntent, type Verdict } from "@signhold/core";
import { PolicyEngine, conservativeDefaultPolicy } from "@signhold/policy";
import { EvmAdapter, ERC20_ABI, type PublicClientLike } from "@signhold/sim-evm";
import { SolanaAdapter, type ConnectionLike } from "@signhold/sim-solana";
import { ReputationService, StaticListProvider, createReputationRule, type ReputationProvider } from "@signhold/reputation";
import { REPUTATION_RULE, createServer, InMemoryAuditStore, withCustomRules } from "@signhold/api";
import { SignholdClient } from "@signhold/sdk";

// ---------------------------------------------------------------------------
// Approver device fixture. In production this is a phone / HSM / hardware key the
// agent cannot reach; here it is a key pair that only `trustedDevice.sign` touches.
// Only the PUBLIC half is handed to the server (SIGNHOLD_APPROVER_KEYS).
// ---------------------------------------------------------------------------
function makeTrustedDevice(keyId: string) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyB64 = (publicKey.export({ type: "spki", format: "der" }) as Buffer).subarray(-32).toString("base64");
  return { keyId, publicKeyB64, sign: (challenge: string) => edSign(null, Buffer.from(challenge, "utf8"), privateKey).toString("base64") };
}

/** Plain HTTP POST of an approval body (what `packages/api/scripts/approve.ts --url` does). Deliberately not an SDK method. */
async function postApproval(baseUrl: string, apiKey: string, body: Record<string, unknown>) {
  const res = await fetch(`${baseUrl}/v1/approvals`, { method: "POST", headers: { "content-type": "application/json", "x-api-key": apiKey }, body: JSON.stringify(body) });
  return { status: res.status, json: (await res.json()) as { error?: string; verdict?: string; approvalId?: string } };
}

// ---------------------------------------------------------------------------
// EVM fixture: a mock viem-like client. USDC-ish token with 6 decimals, $1 each.
// ---------------------------------------------------------------------------
const AGENT = "0x1111111111111111111111111111111111111111";
const BOB = "0x2222222222222222222222222222222222222222";
const USDC = "0x3333333333333333333333333333333333333333";
const ROUTER = "0x4444444444444444444444444444444444444444";
const NEW_CONTRACT = "0x9999999999999999999999999999999999999999"; // deployed, but never seen before
const EOA = "0x5555555555555555555555555555555555555555";          // a plain wallet, not a contract
const DENYLISTED = "0xbad0000000000000000000000000000000000bad";   // on the operator's reputation denylist

const SEL_DECIMALS = encodeFunctionData({ abi: ERC20_ABI, functionName: "decimals" });
const SEL_SYMBOL = encodeFunctionData({ abi: ERC20_ABI, functionName: "symbol" });
const SEL_ALLOWANCE = "0xdd62ed3e";

function mockEvmClient(): PublicClientLike {
  const deployed = new Set([USDC, ROUTER, NEW_CONTRACT, DENYLISTED]);
  return {
    async call({ data }) {
      const d = data ?? "0x";
      if (d === SEL_DECIMALS) return { data: encodeAbiParameters([{ type: "uint8" }], [6]) };
      if (d === SEL_SYMBOL) return { data: encodeAbiParameters([{ type: "string" }], ["USDC"]) };
      if (d.startsWith(SEL_ALLOWANCE)) return { data: encodeAbiParameters([{ type: "uint256" }], [0n]) };
      return { data: "0x" }; // everything else "succeeds"
    },
    async estimateGas() { return 52_000n; },
    async getCode({ address }) { return deployed.has(address.toLowerCase()) ? ("0x6001" as Hex) : ("0x" as Hex); },
  };
}

// ---------------------------------------------------------------------------
// Solana fixture: a mock Connection with an agent ATA holding 10 USDC-ish tokens.
// ---------------------------------------------------------------------------
const solAgent = Keypair.generate();
const solBob = Keypair.generate();
const mint = Keypair.generate().publicKey;
const agentAta = Keypair.generate().publicKey;
const bobAta = Keypair.generate().publicKey;

function tokenAccountData(owner: PublicKey, amount: bigint): Buffer {
  const buf = Buffer.alloc(ACCOUNT_SIZE);
  AccountLayout.encode({
    mint, owner, amount, delegateOption: 0, delegate: PublicKey.default, state: 1, isNativeOption: 0, isNative: 0n,
    delegatedAmount: 0n, closeAuthorityOption: 0, closeAuthority: PublicKey.default,
  }, buf);
  return buf;
}
function mintData(decimals: number): Buffer {
  const buf = Buffer.alloc(MINT_SIZE);
  MintLayout.encode({
    mintAuthorityOption: 0, mintAuthority: PublicKey.default, supply: 0n, decimals, isInitialized: true,
    freezeAuthorityOption: 0, freezeAuthority: PublicKey.default,
  }, buf);
  return buf;
}
const acct = (owner: PublicKey, lamports: number, data: Buffer = Buffer.alloc(0)): AccountInfo<Buffer> =>
  ({ owner, lamports, data: data as Buffer<ArrayBuffer>, executable: false, rentEpoch: 0 });

function mockSolanaConnection(): ConnectionLike {
  const A = solAgent.publicKey.toBase58();
  const pre: Record<string, AccountInfo<Buffer>> = {
    [A]: acct(SystemProgram.programId, 1_000_000_000),
    [agentAta.toBase58()]: acct(TOKEN_PROGRAM_ID, 2_039_280, tokenAccountData(solAgent.publicKey, 10_000_000n)),
    [bobAta.toBase58()]: acct(TOKEN_PROGRAM_ID, 2_039_280, tokenAccountData(solBob.publicKey, 0n)),
    [mint.toBase58()]: acct(TOKEN_PROGRAM_ID, 1, mintData(6)),
  };
  const post: Record<string, AccountInfo<Buffer>> = {
    ...pre,
    [A]: acct(SystemProgram.programId, 999_995_000),
    [agentAta.toBase58()]: acct(TOKEN_PROGRAM_ID, 2_039_280, tokenAccountData(solAgent.publicKey, 7_500_000n)),
    [bobAta.toBase58()]: acct(TOKEN_PROGRAM_ID, 2_039_280, tokenAccountData(solBob.publicKey, 2_500_000n)),
  };
  return {
    async getAccountInfo(pk) { return pre[pk.toBase58()] ?? null; },
    async getMultipleAccountsInfo(pks) { return pks.map((pk) => pre[pk.toBase58()] ?? null); },
    async simulateTransaction(_tx, config) {
      const addresses = config?.accounts?.addresses ?? [];
      const value: SimulatedTransactionResponse = {
        err: null,
        logs: ["Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA log: Instruction: TransferChecked"],
        unitsConsumed: 4_644,
        accounts: addresses.map((a) => {
          const info = post[a];
          if (!info) return null;
          return { executable: false, owner: info.owner.toBase58(), lamports: info.lamports, data: [info.data.toString("base64"), "base64"] };
        }),
      };
      return { context: { slot: 1 }, value };
    },
  };
}

function buildSolanaTx(): string {
  const ix = createTransferCheckedInstruction(agentAta, mint, bobAta, solAgent.publicKey, 2_500_000n, 6);
  const msg = new TransactionMessage({
    payerKey: solAgent.publicKey, recentBlockhash: "11111111111111111111111111111111", instructions: [ix],
  }).compileToV0Message();
  return Buffer.from(new VersionedTransaction(msg).serialize()).toString("base64");
}

// ---------------------------------------------------------------------------
// Wire up: real engine + default policy + mock-backed adapters, served in-process.
// ---------------------------------------------------------------------------
async function main() {
  const priceOracle = async (asset: string) => (asset === "native" ? 2_500 : 1); // ETH/SOL $2500, tokens $1

  const evm = new EvmAdapter({
    client: mockEvmClient(),
    knownContracts: new Set([USDC, ROUTER, DENYLISTED]),
    priceOracle,
  });
  const solana = new SolanaAdapter({
    connection: mockSolanaConnection(),
    knownPrograms: new Set([SystemProgram.programId.toBase58(), TOKEN_PROGRAM_ID.toBase58()]),
    priceOracle,
  });

  // Contract reputation: bundled trusted seed + operator denylist + a flaky "intel" feed
  // that we switch off for case (g).
  let intelDown = false;
  const intel: ReputationProvider = {
    name: "intel",
    async lookup() {
      if (intelDown) throw new Error("503 Service Unavailable");
      return { source: "intel", verdict: "unknown", score: 0, tags: [], fetchedAt: new Date().toISOString() };
    },
  };
  const reputation = new ReputationService({
    providers: [new StaticListProvider({ deny: [{ chain: "evm", address: DENYLISTED, label: "known drainer", tags: ["drainer"] }] }), intel],
    providerTimeoutMs: 500,
  });
  const engine = new PolicyEngine({ customRules: { reputation: createReputationRule(reputation) } });
  const policy = withCustomRules(conservativeDefaultPolicy, [REPUTATION_RULE]);

  const trustedDevice = makeTrustedDevice("ops-phone");
  const app = await createServer({
    engine,
    adapters: { evm, solana },
    policies: new Map([[policy.id, policy]]),
    defaultPolicyId: policy.id,
    audit: new InMemoryAuditStore(),
    reputation,
    apiKeys: [{ id: "demo-agent", key: "demo-key" }, { id: "approver-device", key: "approver-key" }],
    approvers: [{ keyId: trustedDevice.keyId, publicKey: trustedDevice.publicKeyB64 }],
    logger: false,
  });
  const baseUrl = await app.listen({ port: 0, host: "127.0.0.1" });

  const client = new SignholdClient({ baseUrl, apiKey: "demo-key" });
  const context: AgentContext = { agentId: "demo-agent", spentUsdInWindow: 0, windowSeconds: 3600 };

  const cases: Array<{ name: string; expect: Verdict; intent: TransactionIntent; context?: AgentContext; before?: () => void }> = [
    {
      name: "(a) ERC-20 transfer 5 USDC",
      expect: "allow",
      intent: {
        id: "00000000-0000-4000-8000-00000000000a", chain: "evm", chainId: 1, from: AGENT, to: USDC,
        data: encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [BOB, 5_000_000n] }),
        description: "pay supplier invoice #42",
      },
    },
    {
      name: "(b) unlimited approve",
      expect: "block",
      intent: {
        id: "00000000-0000-4000-8000-00000000000b", chain: "evm", chainId: 1, from: AGENT, to: USDC,
        data: encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [ROUTER, UINT256_MAX] }),
        description: "approve router before swap",
      },
    },
    {
      name: "(c) call unknown contract",
      expect: "escalate",
      intent: {
        id: "00000000-0000-4000-8000-00000000000c", chain: "evm", chainId: 1, from: AGENT, to: NEW_CONTRACT,
        data: "0x4e71d92d", // claim()
        description: "claim airdrop from new contract",
      },
    },
    {
      name: "(d) Solana SPL transfer 2.5",
      expect: "allow",
      intent: {
        id: "00000000-0000-4000-8000-00000000000d", chain: "solana", chainId: "mainnet-beta", from: solAgent.publicKey.toBase58(),
        raw: buildSolanaTx(), description: "pay contractor in USDC",
      },
    },
  ];

  cases.push(
    {
      name: "(e) bounded approve to an EOA",
      expect: "block",
      intent: {
        id: "00000000-0000-4000-8000-00000000000e", chain: "evm", chainId: 1, from: AGENT, to: USDC,
        data: encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [EOA, 50_000_000n] }), // $50: bounded and under the $100 cap
        description: "let our ops wallet spend up to 50 USDC",
      },
    },
    {
      name: "(f) transfer to denylisted contract",
      expect: "block",
      intent: {
        id: "00000000-0000-4000-8000-00000000000f", chain: "evm", chainId: 1, from: AGENT, to: USDC,
        data: encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [DENYLISTED, 5_000_000n] }),
        description: "pay invoice #43",
      },
    },
    {
      name: "(g) reputation provider outage",
      expect: "escalate",
      before: () => { intelDown = true; reputation.clearCache(); },
      intent: {
        id: "00000000-0000-4000-8000-000000000010", chain: "evm", chainId: 1, from: AGENT, to: USDC,
        data: encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [BOB, 5_000_000n] }),
        description: "pay supplier invoice #44",
      },
    },
  );

  cases.push({
    name: "(h) escalated tx + human approval",
    expect: "escalate",
    before: () => { intelDown = false; reputation.clearCache(); },
    intent: {
      id: "00000000-0000-4000-8000-000000000011", chain: "evm", chainId: 1, from: AGENT, to: NEW_CONTRACT,
      data: "0x4e71d92d", // claim()
      description: "claim airdrop from new contract (needs a human)",
    },
  });

  const rows: Array<{ case: string; verdict: string; expected: string; riskScore: number; explanation: string }> = [];
  let failures = 0;
  const approvalLog: string[] = [];
  for (const c of cases) {
    c.before?.();
    const res = await client.check(c.intent, c.context ?? context);
    const { decision } = res;
    const ok = decision.verdict === c.expect;
    if (!ok) failures++;
    rows.push({
      case: c.name,
      verdict: `${decision.verdict}${ok ? "" : "  <-- MISMATCH"}`,
      expected: c.expect,
      riskScore: decision.riskScore,
      explanation: decision.explanation,
    });

    if (c.name.startsWith("(h)") && decision.verdict === "escalate") {
      // ---- Human approval (I-HITL). Nothing in this process can approve; only the device can. ----
      const auditId = res.auditId;
      const challenge = res.approval!.challenge;
      approvalLog.push(`auditId ${auditId}`);
      approvalLog.push(`challenge ${challenge} (expires ${res.approval!.expiresAt})`);
      approvalLog.push(`status: ${(await client.getApprovalStatus(auditId)).status}`);

      // 1. The agent, holding only its API key, tries to approve its own transaction with a key it made up.
      const rogue = makeTrustedDevice("ops-phone"); // same key id, but not the registered key
      const forged = await postApproval(baseUrl, "demo-key", { auditId, keyId: rogue.keyId, signature: rogue.sign(challenge), approvedAt: new Date().toISOString() });
      if (forged.status === 200) {
        approvalLog.push("agent self-approval: ACCEPTED  <-- MISMATCH");
        failures++;
      } else {
        approvalLog.push(`agent self-approval: refused (HTTP ${forged.status} ${forged.json.error}); status: ${(await client.getApprovalStatus(auditId)).status}`);
      }

      // 2. A fresh check is needed (the forged attempt burned that challenge: fail closed); this time the
      //    agent blocks in waitForApproval while the human signs on the trusted device.
      const retry = await client.check({ ...c.intent, id: "00000000-0000-4000-8000-000000000012" }, context);
      const waiting = client.waitForApproval(retry.auditId, { intervalMs: 50, timeoutMs: 10_000 });
      const signed = { auditId: retry.auditId, keyId: trustedDevice.keyId, signature: trustedDevice.sign(retry.approval!.challenge), approvedAt: new Date().toISOString(), reason: "vendor confirmed the airdrop contract" };
      const approvalRes = await postApproval(baseUrl, "approver-key", signed); // the device's own transport credential, separate from the agent's
      const granted = await waiting;
      const final = await client.getApprovalStatus(retry.auditId);
      approvalLog.push(`new check ${retry.auditId}: device signed -> server ${approvalRes.json.verdict} (approvalId ${approvalRes.json.approvalId})`);
      approvalLog.push(`waitForApproval resolved: ${granted.status} by ${granted.approvedBy}; status: ${final.status}`);
      if (approvalRes.status !== 200 || final.status !== "approved" || granted.approvedBy !== trustedDevice.keyId) failures++;

      // 3. Replaying the same signed approval is refused.
      const replay = await postApproval(baseUrl, "approver-key", signed);
      if (replay.status === 200) {
        approvalLog.push("replay: ACCEPTED  <-- MISMATCH");
        failures++;
      } else {
        approvalLog.push(`replay of the same approval: refused (HTTP ${replay.status}); status still ${(await client.getApprovalStatus(retry.auditId)).status}`);
      }
    }
  }

  printTable(rows);
  console.log("\nHuman approval (I-HITL) for case (h):");
  for (const l of approvalLog) console.log(`- ${l}`);
  await app.close();
  if (failures > 0) {
    console.error(`\n${failures} case(s) did not match the expected verdict`);
    process.exit(1);
  }
  console.log("\nAll verdicts matched expectations.");
}

function printTable(rows: Array<{ case: string; verdict: string; expected: string; riskScore: number; explanation: string }>) {
  const widths = { case: 40, verdict: 10, expected: 9, risk: 5 };
  const pad = (s: string, w: number) => s.padEnd(w).slice(0, w);
  const line = `${pad("case", widths.case)}  ${pad("verdict", widths.verdict)}  ${pad("expected", widths.expected)}  ${pad("risk", widths.risk)}`;
  console.log(line);
  console.log("-".repeat(line.length));
  for (const r of rows) {
    console.log(`${pad(r.case, widths.case)}  ${pad(r.verdict, widths.verdict)}  ${pad(r.expected, widths.expected)}  ${pad(String(r.riskScore), widths.risk)}`);
  }
  console.log("\nExplanations:");
  for (const r of rows) console.log(`- ${r.case}: ${r.explanation}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
