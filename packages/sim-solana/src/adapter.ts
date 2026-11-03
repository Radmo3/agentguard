import { PublicKey, type AccountInfo, type SimulatedTransactionResponse } from "@solana/web3.js";
import { ACCOUNT_SIZE, AccountLayout, MINT_SIZE, MintLayout } from "@solana/spl-token";
import {
  isUnlimitedApproval, toDecimal,
  type ApprovalChange, type AssetDelta, type ChainAdapter, type SimulationResult, type TransactionIntent,
} from "@agentguard/core";
import type { ConnectionLike } from "./connection.js";
import {
  COMPUTE_BUDGET_PROGRAM_ID, TOKEN_PROGRAM_IDS, decodeInstruction, deserializeTransaction,
  expandInstructions, resolveAccountKeys, type DecodedIx,
} from "./decode.js";

export type PriceOracle = (asset: string) => Promise<number | undefined>;

export interface SolanaAdapterOptions {
  connection: ConnectionLike;
  /** Program ids the operator has seen before; misses are reported in `newContracts`. */
  knownPrograms?: Set<string>;
  /** Returns USD price per whole unit of an asset ("native" or mint address). */
  priceOracle?: PriceOracle;
  /** USD threshold above which a "high value" warning is emitted. Default 10_000. */
  highValueUsd?: number;
  /** Lamport threshold for the high-value warning when no price is available. Default 10 SOL. */
  highValueLamports?: bigint;
  /** Compute-unit price (micro-lamports) above which a warning is emitted. Default 1_000_000. */
  maxComputeUnitPrice?: bigint;
}

const LAMPORTS_PER_SOL = 1_000_000_000n;
const MAX_COMPUTE_UNITS = 1_400_000;
const LOG_TAIL = 8;

interface TokenAccountState { mint: string; owner: string; amount: bigint; delegate?: string; delegatedAmount: bigint }

function parseTokenAccount(owner: string, data: Uint8Array): TokenAccountState | undefined {
  if (!TOKEN_PROGRAM_IDS.has(owner) || data.length < ACCOUNT_SIZE) return undefined;
  try {
    const raw = AccountLayout.decode(data.subarray(0, ACCOUNT_SIZE));
    return {
      mint: raw.mint.toBase58(), owner: raw.owner.toBase58(), amount: raw.amount,
      delegate: raw.delegateOption ? raw.delegate.toBase58() : undefined,
      delegatedAmount: raw.delegatedAmount,
    };
  } catch { return undefined; }
}

export class SolanaAdapter implements ChainAdapter {
  readonly chain = "solana" as const;
  private readonly connection: ConnectionLike;
  private readonly known?: Set<string>;
  private readonly oracle?: PriceOracle;
  private readonly highValueUsd: number;
  private readonly highValueLamports: bigint;
  private readonly maxCuPrice: bigint;
  private readonly mintCache = new Map<string, number>();

  constructor(opts: SolanaAdapterOptions) {
    this.connection = opts.connection;
    this.known = opts.knownPrograms;
    this.oracle = opts.priceOracle;
    this.highValueUsd = opts.highValueUsd ?? 10_000;
    this.highValueLamports = opts.highValueLamports ?? 10n * LAMPORTS_PER_SOL;
    this.maxCuPrice = opts.maxComputeUnitPrice ?? 1_000_000n;
  }

  async simulate(intent: TransactionIntent): Promise<SimulationResult> {
    try {
      return await this.simulateInner(intent);
    } catch (err) {
      return {
        ok: false,
        revertReason: `adapter error: ${err instanceof Error ? err.message : String(err)}`,
        deltas: [], approvals: [], contractsTouched: [], newContracts: [],
        warnings: ["adapter_error"],
      };
    }
  }

  private async simulateInner(intent: TransactionIntent): Promise<SimulationResult> {
    const warnings: string[] = [];
    const approvals: ApprovalChange[] = [];
    const from = intent.from;

    if (!intent.raw) {
      return {
        ok: false, revertReason: "missing raw transaction", deltas: [], approvals: [],
        contractsTouched: [], newContracts: [], warnings: ["no raw transaction supplied"],
      };
    }

    // ---- 1. deserialize + decode ----------------------------------------------
    const tx = deserializeTransaction(intent.raw);
    const keys = await resolveAccountKeys(tx, this.connection);
    const instructions = expandInstructions(tx, keys);
    const decoded = instructions.map(decodeInstruction);
    const programs = new Set(instructions.map((ix) => ix.programId.toBase58()));

    const feePayer = keys.get(0)?.toBase58();
    if (feePayer && feePayer !== from) warnings.push(`fee payer ${feePayer} differs from agent wallet`);

    // ---- 2. pre-state for all writable accounts --------------------------------
    const allKeys: PublicKey[] = [];
    for (let i = 0; i < keys.length; i++) {
      const k = keys.get(i);
      if (k && tx.message.isAccountWritable(i)) allKeys.push(k);
    }
    const fromKey = new PublicKey(from);
    if (!allKeys.some((k) => k.equals(fromKey))) allKeys.push(fromKey);
    const pre = new Map<string, AccountInfo<Buffer> | null>();
    try {
      const infos = await this.connection.getMultipleAccountsInfo(allKeys);
      allKeys.forEach((k, i) => pre.set(k.toBase58(), infos[i] ?? null));
    } catch { warnings.push("could not load pre-simulation account state"); }

    const preTokens = new Map<string, TokenAccountState>();
    for (const [addr, info] of pre) {
      if (!info) continue;
      const t = parseTokenAccount(info.owner.toBase58(), info.data);
      if (t) preTokens.set(addr, t);
    }

    // ---- 3. instruction-level heuristics + approvals -----------------------------
    let cuLimitCount = 0, cuPriceCount = 0;
    for (const d of decoded) {
      switch (d.kind) {
        case "unknown":
          warnings.push(`unknown program ${d.programId}`);
          break;
        case "token.setAuthority":
          warnings.push(`SetAuthority on ${d.account} (type ${d.authorityType}) -> ${d.newAuthority ?? "none"}`);
          break;
        case "token.closeAccount":
          warnings.push(`CloseAccount ${d.account} rent -> ${d.destination}`);
          break;
        case "token.approve": {
          if (d.owner !== from) break;
          const acct = preTokens.get(d.account);
          const mint = d.mint ?? acct?.mint ?? d.account;
          const previous = acct && acct.delegate === d.delegate ? acct.delegatedAmount : 0n;
          const unlimited = isUnlimitedApproval(d.amount);
          approvals.push({ token: mint, spender: d.delegate, previous, next: d.amount, unlimited });
          if (unlimited) warnings.push(`unlimited approval of ${mint} to ${d.delegate}`);
          break;
        }
        case "token.revoke": {
          if (d.owner !== from) break;
          const acct = preTokens.get(d.account);
          if (acct?.delegate) approvals.push({ token: acct.mint, spender: acct.delegate, previous: acct.delegatedAmount, next: 0n, unlimited: false });
          break;
        }
        case "computeBudget":
          if (d.type === "SetComputeUnitLimit") {
            cuLimitCount++;
            if (d.units !== undefined && d.units > MAX_COMPUTE_UNITS) warnings.push(`compute unit limit ${d.units} exceeds maximum ${MAX_COMPUTE_UNITS}`);
          } else if (d.type === "SetComputeUnitPrice") {
            cuPriceCount++;
            if (d.microLamports !== undefined && d.microLamports > this.maxCuPrice) {
              warnings.push(`compute unit price ${d.microLamports} micro-lamports exceeds ${this.maxCuPrice}`);
            }
          }
          break;
        case "system.other":
          if (d.type === "Assign" || d.type === "AssignWithSeed") warnings.push("system Assign changes account ownership");
          break;
        default:
          break;
      }
    }
    if (cuLimitCount > 1 || cuPriceCount > 1) warnings.push("duplicate compute budget instructions");
    if (programs.has(COMPUTE_BUDGET_PROGRAM_ID) && programs.size === 1) warnings.push("transaction contains only compute budget instructions");

    // ---- 4. simulate ----------------------------------------------------------
    const watch = new Set<string>([from, ...preTokens.keys()]);
    for (const addr of pre.keys()) watch.add(addr);
    let ok = true;
    let revertReason: string | undefined;
    let sim: SimulatedTransactionResponse | undefined;
    try {
      const res = await this.connection.simulateTransaction(tx, {
        sigVerify: false, replaceRecentBlockhash: true,
        accounts: { encoding: "base64", addresses: [...watch] },
      });
      sim = res.value;
      if (sim.err) {
        ok = false;
        revertReason = formatSimError(sim.err, sim.logs);
      }
    } catch (err) {
      ok = false;
      revertReason = err instanceof Error ? err.message : String(err);
    }

    // ---- 5. deltas ------------------------------------------------------------
    const deltas: AssetDelta[] = [];
    const watchList = [...watch];
    if (ok && sim?.accounts && sim.accounts.length === watchList.length) {
      // Native delta for `from` (includes fee).
      const fromIdx = watchList.indexOf(from);
      const preFrom = pre.get(from);
      const postFrom = sim.accounts[fromIdx];
      if (preFrom !== undefined) {
        const lamportDelta = BigInt(postFrom?.lamports ?? 0) - BigInt(preFrom?.lamports ?? 0);
        if (lamportDelta !== 0n) deltas.push(await this.delta("native", lamportDelta));
      }
      // Token deltas, netted per mint.
      const net = new Map<string, { amount: bigint; decimals?: number }>();
      for (let i = 0; i < watchList.length; i++) {
        const addr = watchList[i]!;
        const preT = preTokens.get(addr);
        const post = sim.accounts[i];
        const postT = post ? parseTokenAccount(post.owner, Buffer.from(post.data[0] ?? "", "base64")) : undefined;
        const mint = postT?.mint ?? preT?.mint;
        if (!mint) continue;
        const preAmt = preT?.owner === from ? preT.amount : 0n;
        const postAmt = postT?.owner === from ? postT.amount : 0n;
        const diff = postAmt - preAmt;
        if (diff === 0n) continue;
        const cur = net.get(mint) ?? { amount: 0n };
        cur.amount += diff;
        net.set(mint, cur);
      }
      for (const [mint, { amount }] of net) deltas.push(await this.delta(mint, amount, await this.mintDecimals(mint, decoded)));
    } else if (ok) {
      // Fallback: derive from decoded instructions.
      for (const d of decoded) {
        if (d.kind === "system.transfer" && d.from === from) deltas.push(await this.delta("native", -d.lamports));
        if (d.kind === "token.transfer" && d.owner === from) {
          const mint = d.mint ?? preTokens.get(d.source)?.mint ?? preTokens.get(d.destination)?.mint ?? d.source;
          deltas.push(await this.delta(mint, -d.amount, d.decimals ?? (await this.mintDecimals(mint, decoded))));
        }
      }
    }

    // ---- 6. new programs ------------------------------------------------------
    const newContracts: string[] = [];
    if (this.known) for (const p of programs) if (!this.known.has(p)) newContracts.push(p);

    // ---- 7. value heuristics --------------------------------------------------
    let outflowUsd = 0, priced = false;
    for (const d of deltas) if (d.usdValue !== undefined) { priced = true; if (d.usdValue < 0) outflowUsd += -d.usdValue; }
    const nativeOut = -(deltas.find((d) => d.asset === "native")?.amount ?? 0n);
    if (priced && outflowUsd >= this.highValueUsd) warnings.push(`high value: ~$${outflowUsd.toFixed(2)} outflow`);
    else if (!priced && nativeOut >= this.highValueLamports) warnings.push(`high value: ${toDecimal(nativeOut, 9)} SOL`);

    return {
      ok, revertReason, deltas, approvals,
      contractsTouched: [...programs], newContracts,
      gasEstimate: sim?.unitsConsumed !== undefined ? BigInt(sim.unitsConsumed) : undefined,
      warnings: [...new Set(warnings)],
      rawTrace: sim ? { logs: sim.logs, err: sim.err, unitsConsumed: sim.unitsConsumed } : undefined,
    };
  }

  private async mintDecimals(mint: string, decoded: DecodedIx[]): Promise<number> {
    const cached = this.mintCache.get(mint);
    if (cached !== undefined) return cached;
    for (const d of decoded) {
      if (d.kind === "token.transfer" && d.mint === mint && d.decimals !== undefined) { this.mintCache.set(mint, d.decimals); return d.decimals; }
    }
    let decimals = 0;
    try {
      const info = await this.connection.getAccountInfo(new PublicKey(mint));
      if (info && info.data.length >= MINT_SIZE) decimals = MintLayout.decode(info.data.subarray(0, MINT_SIZE)).decimals;
    } catch { /* default 0 */ }
    this.mintCache.set(mint, decimals);
    return decimals;
  }

  private async delta(asset: string, amount: bigint, decimals?: number): Promise<AssetDelta> {
    const dec = asset === "native" ? 9 : (decimals ?? 0);
    const d: AssetDelta = { asset, decimals: dec, amount };
    if (asset === "native") d.symbol = "SOL";
    if (this.oracle) {
      try {
        const price = await this.oracle(asset);
        if (price !== undefined) d.usdValue = toDecimal(amount, dec) * price;
      } catch { /* best effort */ }
    }
    return d;
  }
}

function formatSimError(err: unknown, logs: string[] | null | undefined): string {
  const head = typeof err === "string" ? err : JSON.stringify(err);
  const tail = (logs ?? []).slice(-LOG_TAIL);
  return tail.length ? `${head}\n${tail.join("\n")}` : head;
}
