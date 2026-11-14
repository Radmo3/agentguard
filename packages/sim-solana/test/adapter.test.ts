import { describe, it, expect } from "vitest";
import {
  ComputeBudgetProgram, Keypair, PublicKey, SystemProgram, TransactionInstruction, TransactionMessage,
  VersionedTransaction, type AccountInfo, type SimulatedTransactionResponse,
} from "@solana/web3.js";
import {
  ACCOUNT_SIZE, AccountLayout, MINT_SIZE, MintLayout, TOKEN_PROGRAM_ID,
  createApproveInstruction, createCloseAccountInstruction, createSetAuthorityInstruction,
  createTransferCheckedInstruction, createTransferInstruction, AuthorityType,
} from "@solana/spl-token";
import { U64_MAX } from "@signhold/core";
import { SolanaAdapter, type ConnectionLike } from "../src/index.js";

const agent = Keypair.generate();
const bob = Keypair.generate();
const mint = Keypair.generate().publicKey;
const agentAta = Keypair.generate().publicKey;
const bobAta = Keypair.generate().publicKey;
const delegate = Keypair.generate().publicKey;
const UNKNOWN_PROGRAM = Keypair.generate().publicKey;
const BLOCKHASH = "11111111111111111111111111111111";

function tokenAccountData(owner: PublicKey, amount: bigint, delegateKey?: PublicKey, delegatedAmount = 0n): Buffer {
  const buf = Buffer.alloc(ACCOUNT_SIZE);
  AccountLayout.encode({
    mint, owner, amount, delegateOption: delegateKey ? 1 : 0, delegate: delegateKey ?? PublicKey.default,
    state: 1, isNativeOption: 0, isNative: 0n, delegatedAmount, closeAuthorityOption: 0, closeAuthority: PublicKey.default,
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

function acct(owner: PublicKey, lamports: number, data: Buffer = Buffer.alloc(0)): AccountInfo<Buffer> {
  return { owner, lamports, data, executable: false, rentEpoch: 0 };
}

interface World {
  pre: Record<string, AccountInfo<Buffer>>;
  post?: Record<string, AccountInfo<Buffer>>;
  err?: unknown;
  logs?: string[];
}

function mockConnection(world: World): ConnectionLike & { lastConfig?: unknown } {
  const conn: ConnectionLike & { lastConfig?: unknown } = {
    async getAccountInfo(pk) { return world.pre[pk.toBase58()] ?? null; },
    async getMultipleAccountsInfo(pks) { return pks.map((pk) => world.pre[pk.toBase58()] ?? null); },
    async simulateTransaction(_tx, config) {
      conn.lastConfig = config;
      const addresses = config?.accounts?.addresses ?? [];
      const value: SimulatedTransactionResponse = {
        err: world.err ?? null,
        logs: world.logs ?? ["Program log: ok"],
        unitsConsumed: 1234,
        accounts: world.err ? null : addresses.map((a) => {
          const info = (world.post ?? world.pre)[a];
          if (!info) return null;
          return { executable: false, owner: info.owner.toBase58(), lamports: info.lamports, data: [info.data.toString("base64"), "base64"] };
        }),
      };
      return { context: { slot: 1 }, value };
    },
  };
  return conn;
}

function buildTx(ixs: TransactionInstruction[], payer: PublicKey = agent.publicKey): string {
  const msg = new TransactionMessage({ payerKey: payer, recentBlockhash: BLOCKHASH, instructions: ixs }).compileToV0Message();
  const tx = new VersionedTransaction(msg);
  return Buffer.from(tx.serialize()).toString("base64");
}

const intent = (raw: string, id = "1") => ({ id, chain: "solana" as const, from: agent.publicKey.toBase58(), raw });
const A = agent.publicKey.toBase58();

describe("SolanaAdapter", () => {
  it("computes a lamport delta for a plain SystemProgram transfer", async () => {
    const conn = mockConnection({
      pre: { [A]: acct(SystemProgram.programId, 5_000_000_000), [bob.publicKey.toBase58()]: acct(SystemProgram.programId, 0) },
      post: { [A]: acct(SystemProgram.programId, 3_999_995_000), [bob.publicKey.toBase58()]: acct(SystemProgram.programId, 1_000_000_000) },
    });
    const adapter = new SolanaAdapter({ connection: conn, knownPrograms: new Set([SystemProgram.programId.toBase58()]), priceOracle: async () => 100 });
    const raw = buildTx([SystemProgram.transfer({ fromPubkey: agent.publicKey, toPubkey: bob.publicKey, lamports: 1_000_000_000 })]);
    const res = await adapter.simulate(intent(raw));
    expect(res.ok).toBe(true);
    expect(res.deltas).toEqual([{ asset: "native", symbol: "SOL", decimals: 9, amount: -1_000_005_000n, usdValue: expect.closeTo(-100.0005, 3) }]);
    expect(res.contractsTouched).toEqual([SystemProgram.programId.toBase58()]);
    expect(res.newContracts).toEqual([]);
    expect(res.gasEstimate).toBe(1234n);
    expect(res.warnings).toEqual([]);
    expect((conn.lastConfig as any).accounts.addresses).toContain(A);
  });

  it("computes a token delta for an SPL transferChecked", async () => {
    const pre = {
      [A]: acct(SystemProgram.programId, 1_000_000_000),
      [agentAta.toBase58()]: acct(TOKEN_PROGRAM_ID, 2_039_280, tokenAccountData(agent.publicKey, 10_000_000n)),
      [bobAta.toBase58()]: acct(TOKEN_PROGRAM_ID, 2_039_280, tokenAccountData(bob.publicKey, 0n)),
      [mint.toBase58()]: acct(TOKEN_PROGRAM_ID, 1, mintData(6)),
    };
    const post = { ...pre,
      [agentAta.toBase58()]: acct(TOKEN_PROGRAM_ID, 2_039_280, tokenAccountData(agent.publicKey, 7_500_000n)),
      [bobAta.toBase58()]: acct(TOKEN_PROGRAM_ID, 2_039_280, tokenAccountData(bob.publicKey, 2_500_000n)),
    };
    const adapter = new SolanaAdapter({ connection: mockConnection({ pre, post }) });
    const raw = buildTx([createTransferCheckedInstruction(agentAta, mint, bobAta, agent.publicKey, 2_500_000n, 6)]);
    const res = await adapter.simulate(intent(raw));
    expect(res.ok).toBe(true);
    expect(res.deltas).toEqual([{ asset: mint.toBase58(), decimals: 6, amount: -2_500_000n }]);
    expect(res.contractsTouched).toEqual([TOKEN_PROGRAM_ID.toBase58()]);
  });

  it("falls back to decoded instructions when post-state is unavailable", async () => {
    const pre = {
      [A]: acct(SystemProgram.programId, 1_000_000_000),
      [agentAta.toBase58()]: acct(TOKEN_PROGRAM_ID, 2_039_280, tokenAccountData(agent.publicKey, 10n)),
      [mint.toBase58()]: acct(TOKEN_PROGRAM_ID, 1, mintData(6)),
    };
    const conn = mockConnection({ pre });
    conn.simulateTransaction = async () => ({ context: { slot: 1 }, value: { err: null, logs: [], accounts: null } });
    const adapter = new SolanaAdapter({ connection: conn });
    const raw = buildTx([createTransferInstruction(agentAta, bobAta, agent.publicKey, 4n)]);
    const res = await adapter.simulate(intent(raw));
    expect(res.ok).toBe(true);
    expect(res.deltas).toEqual([{ asset: mint.toBase58(), decimals: 6, amount: -4n }]);
  });

  it("flags an unlimited SPL approve", async () => {
    const pre = {
      [A]: acct(SystemProgram.programId, 1_000_000_000),
      [agentAta.toBase58()]: acct(TOKEN_PROGRAM_ID, 2_039_280, tokenAccountData(agent.publicKey, 10n, delegate, 5n)),
    };
    const adapter = new SolanaAdapter({ connection: mockConnection({ pre }) });
    const raw = buildTx([createApproveInstruction(agentAta, delegate, agent.publicKey, U64_MAX)]);
    const res = await adapter.simulate(intent(raw));
    expect(res.ok).toBe(true);
    expect(res.approvals).toEqual([{ token: mint.toBase58(), spender: delegate.toBase58(), previous: 5n, next: U64_MAX, unlimited: true }]);
    expect(res.warnings).toContain(`unlimited approval of ${mint.toBase58()} to ${delegate.toBase58()}`);
  });

  it("returns ok=false with the log tail when simulation errors", async () => {
    const pre = { [A]: acct(SystemProgram.programId, 1_000_000_000) };
    const logs = Array.from({ length: 12 }, (_, i) => `Program log: line ${i}`).concat(["Program log: Error: insufficient funds"]);
    const adapter = new SolanaAdapter({ connection: mockConnection({ pre, err: { InstructionError: [0, { Custom: 1 }] }, logs }) });
    const raw = buildTx([SystemProgram.transfer({ fromPubkey: agent.publicKey, toPubkey: bob.publicKey, lamports: 5_000_000_000 })]);
    const res = await adapter.simulate(intent(raw));
    expect(res.ok).toBe(false);
    expect(res.revertReason).toContain('{"InstructionError":[0,{"Custom":1}]}');
    expect(res.revertReason).toContain("insufficient funds");
    expect(res.revertReason).not.toContain("line 0");
    expect(res.deltas).toEqual([]);
  });

  it("does not throw when the RPC call itself rejects", async () => {
    const conn = mockConnection({ pre: { [A]: acct(SystemProgram.programId, 1) } });
    conn.simulateTransaction = async () => { throw new Error("429 too many requests"); };
    const adapter = new SolanaAdapter({ connection: conn });
    const raw = buildTx([SystemProgram.transfer({ fromPubkey: agent.publicKey, toPubkey: bob.publicKey, lamports: 1 })]);
    const res = await adapter.simulate(intent(raw));
    expect(res.ok).toBe(false);
    expect(res.revertReason).toContain("429");
  });

  it("warns on unknown programs and reports them as new", async () => {
    const pre = { [A]: acct(SystemProgram.programId, 1_000_000_000) };
    const adapter = new SolanaAdapter({ connection: mockConnection({ pre }), knownPrograms: new Set([SystemProgram.programId.toBase58()]) });
    const ix = new TransactionInstruction({ programId: UNKNOWN_PROGRAM, keys: [{ pubkey: agent.publicKey, isSigner: true, isWritable: true }], data: Buffer.from([1, 2, 3]) });
    const raw = buildTx([ix]);
    const res = await adapter.simulate(intent(raw));
    expect(res.ok).toBe(true);
    expect(res.warnings).toContain(`unknown program ${UNKNOWN_PROGRAM.toBase58()}`);
    expect(res.newContracts).toEqual([UNKNOWN_PROGRAM.toBase58()]);
    expect(res.contractsTouched).toEqual([UNKNOWN_PROGRAM.toBase58()]);
  });

  it("warns on SetAuthority, CloseAccount and compute budget anomalies", async () => {
    const pre = {
      [A]: acct(SystemProgram.programId, 1_000_000_000),
      [agentAta.toBase58()]: acct(TOKEN_PROGRAM_ID, 2_039_280, tokenAccountData(agent.publicKey, 10n)),
    };
    const adapter = new SolanaAdapter({ connection: mockConnection({ pre }) });
    const raw = buildTx([
      ComputeBudgetProgram.setComputeUnitLimit({ units: 2_000_000 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 5_000_000 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 }),
      createSetAuthorityInstruction(agentAta, agent.publicKey, AuthorityType.AccountOwner, bob.publicKey),
      createCloseAccountInstruction(agentAta, bob.publicKey, agent.publicKey),
    ]);
    const res = await adapter.simulate(intent(raw));
    expect(res.warnings).toEqual(expect.arrayContaining([
      expect.stringContaining("compute unit limit 2000000 exceeds"),
      expect.stringContaining("compute unit price 5000000"),
      "duplicate compute budget instructions",
      expect.stringContaining(`SetAuthority on ${agentAta.toBase58()}`),
      expect.stringContaining(`CloseAccount ${agentAta.toBase58()} rent -> ${bob.publicKey.toBase58()}`),
    ]));
  });

  it("fails cleanly on a missing or malformed raw transaction", async () => {
    const adapter = new SolanaAdapter({ connection: mockConnection({ pre: {} }) });
    const missing = await adapter.simulate({ id: "x", chain: "solana", from: A });
    expect(missing.ok).toBe(false);
    expect(missing.revertReason).toBe("missing raw transaction");
    const bad = await adapter.simulate(intent("bm90IGEgdHg="));
    expect(bad.ok).toBe(false);
    expect(bad.warnings).toContain("adapter_error");
  });
});
