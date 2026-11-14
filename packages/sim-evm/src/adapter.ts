import {
  decodeEventLog, decodeFunctionResult, encodeFunctionData, isAddress, size,
  type Address, type Hex,
} from "viem";
import {
  isUnlimitedApproval, toDecimal, UINT256_MAX,
  type ApprovalChange, type AssetDelta, type ChainAdapter, type SimulationResult, type TransactionIntent,
} from "@signhold/core";
import { ERC20_ABI } from "./abis.js";
import type { PublicClientLike, TraceCall, TraceLog, TraceResult } from "./client.js";
import { decodeCalldata, parseRevertReason, type DecodedCall } from "./decode.js";

export type PriceOracle = (asset: string) => Promise<number | undefined>;

export interface EvmAdapterOptions {
  client: PublicClientLike;
  /** Lower-cased addresses the operator has seen before; misses are reported in `newContracts`. */
  knownContracts?: Set<string>;
  /** Returns USD price per whole unit of an asset ("native" or token address). */
  priceOracle?: PriceOracle;
  /** USD threshold above which a "high value" warning is emitted. Default 10_000. */
  highValueUsd?: number;
  /** Native-unit threshold (wei) used for the high-value warning when no price is available. Default 1 ETH. */
  highValueNative?: bigint;
  /** Decimals assumed for the native asset. Default 18. */
  nativeDecimals?: number;
}

interface TokenMeta { decimals: number; symbol?: string }

const lc = (s: string) => s.toLowerCase();
const ZERO = "0x0000000000000000000000000000000000000000";

export class EvmAdapter implements ChainAdapter {
  readonly chain = "evm" as const;
  private readonly client: PublicClientLike;
  private readonly known?: Set<string>;
  private readonly oracle?: PriceOracle;
  private readonly highValueUsd: number;
  private readonly highValueNative: bigint;
  private readonly nativeDecimals: number;
  private readonly metaCache = new Map<string, TokenMeta>();
  private readonly codeCache = new Map<string, boolean>();

  constructor(opts: EvmAdapterOptions) {
    this.client = opts.client;
    this.known = opts.knownContracts ? new Set([...opts.knownContracts].map(lc)) : undefined;
    this.oracle = opts.priceOracle;
    this.highValueUsd = opts.highValueUsd ?? 10_000;
    this.highValueNative = opts.highValueNative ?? 10n ** 18n;
    this.nativeDecimals = opts.nativeDecimals ?? 18;
  }

  async simulate(intent: TransactionIntent): Promise<SimulationResult> {
    try {
      return await this.simulateInner(intent);
    } catch (err) {
      // Never throw: surface unexpected adapter failures as a failed simulation.
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
    const deltas: AssetDelta[] = [];
    const approvals: ApprovalChange[] = [];
    const touched = new Set<string>();
    const recipients = new Set<string>();
    const from = lc(intent.from);
    const to = intent.to ? lc(intent.to) : undefined;
    const value = intent.value ?? 0n;
    const data = (intent.data ?? "0x") as Hex;

    if (!isAddress(from)) warnings.push(`invalid from address: ${intent.from}`);
    if (to && !isAddress(to)) warnings.push(`invalid to address: ${intent.to}`);
    if (value < 0n) {
      // A negative native value has no on-chain meaning; refuse to reason about it.
      return {
        ok: false, revertReason: "invalid native value (negative)",
        deltas: [], approvals: [], contractsTouched: to ? [to] : [], recipients: [], newContracts: [],
        warnings: ["invalid native value"],
      };
    }
    if (to) touched.add(to);
    // A plain native transfer (or any value-bearing call) makes `to` a recipient of funds.
    if (to && value > 0n) recipients.add(to);

    // ---- 1. calldata decoding -------------------------------------------------
    const decoded = decodeCalldata(data);
    const calldataTokenDeltas: AssetDelta[] = [];
    await this.applyDecoded(decoded, { from, to, value, warnings, approvals, touched, recipients, deltas: calldataTokenDeltas });
    if (decoded.kind !== "none" && decoded.kind !== "unknown") {
      const expected = expectedCalldataLength(decoded);
      const actual = size(data);
      if (expected !== undefined && actual > expected) {
        warnings.push(`calldata has ${actual - expected} trailing byte(s) beyond the ABI-encoded arguments`);
      }
    }

    // ---- 2. target heuristics -------------------------------------------------
    if (to) {
      const hasCode = await this.hasCode(to);
      if (!hasCode && data !== "0x") {
        warnings.push(`target ${to} has no code (EOA or selfdestructed) but calldata was supplied`);
      }
    } else if (data !== "0x") {
      warnings.push("contract creation (no `to`)");
    }

    // ---- 3. simulation --------------------------------------------------------
    let ok = true;
    let revertReason: string | undefined;
    let gasEstimate: bigint | undefined;
    let trace: TraceResult | undefined;
    const callArgs = { account: from as Address, to: to as Address | undefined, data, value };
    try {
      await this.client.call(callArgs);
    } catch (err) {
      ok = false;
      revertReason = parseRevertReason(err);
    }
    if (ok) {
      try { gasEstimate = await this.client.estimateGas(callArgs); } catch { /* optional */ }
      if (this.client.traceCall) {
        try { trace = await this.client.traceCall(callArgs); } catch { warnings.push("trace unavailable"); }
      }
    }

    // ---- 4. deltas ------------------------------------------------------------
    if (value > 0n) {
      deltas.push(await this.delta("native", -value));
    }
    let traceDeltas: AssetDelta[] | undefined;
    if (trace) {
      const logs = collectLogs(trace);
      traceDeltas = await this.deltasFromLogs(logs, from, approvals, warnings);
      for (const c of collectCalls(trace)) {
        if (c.to) touched.add(lc(c.to));
        const t = (c.type ?? "").toUpperCase();
        if (t === "SELFDESTRUCT") warnings.push(`selfdestruct in call to ${c.to ?? "?"}`);
        if (t === "CREATE" || t === "CREATE2") warnings.push("contract creation during call");
      }
    }
    // Trace-derived token deltas are authoritative when present; otherwise fall back to calldata.
    deltas.push(...(traceDeltas && traceDeltas.length > 0 ? traceDeltas : calldataTokenDeltas));

    // ---- 5. new contracts -----------------------------------------------------
    const newContracts: string[] = [];
    if (this.known) {
      for (const addr of touched) {
        if (!this.known.has(addr) && (await this.hasCode(addr))) newContracts.push(addr);
      }
    }

    // ---- 6. value heuristics --------------------------------------------------
    let outflowUsd = 0;
    let priced = false;
    for (const d of deltas) {
      if (d.usdValue !== undefined) { priced = true; if (d.usdValue < 0) outflowUsd += -d.usdValue; }
    }
    if (priced && outflowUsd >= this.highValueUsd) {
      warnings.push(`high value: ~$${outflowUsd.toFixed(2)} outflow`);
    } else if (!priced && value >= this.highValueNative) {
      warnings.push(`high value: ${toDecimal(value, this.nativeDecimals)} native units`);
    }

    recipients.delete(from);
    return {
      ok, revertReason, deltas, approvals,
      contractsTouched: [...touched], recipients: [...recipients], newContracts, gasEstimate,
      warnings: dedupe(warnings),
      rawTrace: trace?.raw ?? trace,
    };
  }

  private async applyDecoded(
    d: DecodedCall,
    ctx: { from: string; to?: string; value: bigint; warnings: string[]; approvals: ApprovalChange[]; touched: Set<string>; recipients: Set<string>; deltas: AssetDelta[] },
  ): Promise<void> {
    const { from, to, warnings, approvals, touched, recipients, deltas } = ctx;
    switch (d.kind) {
      case "none":
        return;
      case "unknown":
        warnings.push(`unknown function selector ${d.selector}`);
        return;
      case "erc20.transfer":
        if (to) deltas.push(await this.delta(to, -d.amount));
        recipients.add(d.to);
        return;
      case "erc20.transferFrom":
        if (to && d.from === from) deltas.push(await this.delta(to, -d.amount));
        if (to && d.to === from) deltas.push(await this.delta(to, d.amount));
        if (d.from === from) recipients.add(d.to);
        return;
      case "erc20.approve":
        if (to) approvals.push(await this.approval(to, from, d.spender, d.amount, warnings));
        return;
      case "erc20.permit":
        if (to && d.owner === from) approvals.push(await this.approval(to, from, d.spender, d.value, warnings));
        else if (d.owner !== from) warnings.push(`permit signed for a different owner ${d.owner}`);
        return;
      case "erc721.setApprovalForAll":
        if (to) {
          const next = d.approved ? UINT256_MAX : 0n;
          const spenderIsContract = await this.hasCode(d.operator);
          approvals.push({ token: to, spender: d.operator, previous: 0n, next, unlimited: d.approved, spenderIsContract });
          if (d.approved) {
            warnings.push(`unlimited approval (setApprovalForAll) of ${to} to ${d.operator}`);
            if (!spenderIsContract) warnings.push(`approval to EOA ${d.operator}`);
          }
        }
        return;
      case "swap": {
        if (d.tokenIn !== "native" && d.tokenIn) touched.add(d.tokenIn);
        if (d.tokenOut !== "native" && d.tokenOut) touched.add(d.tokenOut);
        const amountIn = d.tokenIn === "native" ? ctx.value : d.amountIn;
        if (d.tokenIn !== "native" && amountIn > 0n) deltas.push(await this.delta(d.tokenIn, -amountIn));
        if (d.tokenOut && d.amountOut > 0n) deltas.push(await this.delta(d.tokenOut, d.amountOut));
        if (d.amountOut === 0n) warnings.push(`swap ${d.name} with zero minimum output (unlimited slippage)`);
        if (d.recipient && d.recipient !== from && d.recipient !== ZERO) {
          warnings.push(`swap recipient ${d.recipient} differs from sender`);
          recipients.add(d.recipient);
        }
        return;
      }
    }
  }

  private async approval(token: string, owner: string, spender: string, next: bigint, warnings: string[]): Promise<ApprovalChange> {
    let previous = 0n;
    try {
      const res = await this.client.call({
        to: token as Address,
        data: encodeFunctionData({ abi: ERC20_ABI, functionName: "allowance", args: [owner as Address, spender as Address] }),
      });
      if (res.data && res.data !== "0x") {
        previous = decodeFunctionResult({ abi: ERC20_ABI, functionName: "allowance", data: res.data }) as bigint;
      }
    } catch { /* best effort */ }
    const unlimited = isUnlimitedApproval(next);
    if (unlimited) warnings.push(`unlimited approval of ${token} to ${spender}`);
    const spenderIsContract = await this.hasCode(spender);
    if (next > 0n && !spenderIsContract) warnings.push(`approval to EOA ${spender}`);
    return { token, spender, previous, next, unlimited, spenderIsContract };
  }

  private async deltasFromLogs(logs: TraceLog[], from: string, approvals: ApprovalChange[], warnings: string[]): Promise<AssetDelta[]> {
    const net = new Map<string, bigint>();
    for (const log of logs) {
      let ev: { eventName: string; args: any };
      try {
        ev = decodeEventLog({ abi: ERC20_ABI, data: log.data, topics: log.topics as [Hex, ...Hex[]] }) as typeof ev;
      } catch { continue; }
      const token = lc(log.address);
      if (ev.eventName === "Transfer") {
        const f = lc(ev.args.from), t = lc(ev.args.to), v: bigint = ev.args.value;
        if (f === from) net.set(token, (net.get(token) ?? 0n) - v);
        if (t === from) net.set(token, (net.get(token) ?? 0n) + v);
      } else if (ev.eventName === "Approval" && lc(ev.args.owner) === from) {
        const spender = lc(ev.args.spender);
        const next: bigint = ev.args.value;
        if (!approvals.some((a) => a.token === token && a.spender === spender)) {
          approvals.push(await this.approval(token, from, spender, next, warnings));
        }
      }
    }
    const out: AssetDelta[] = [];
    for (const [token, amount] of net) if (amount !== 0n) out.push(await this.delta(token, amount));
    return out;
  }

  private async delta(asset: string, amount: bigint): Promise<AssetDelta> {
    const meta = asset === "native" ? { decimals: this.nativeDecimals, symbol: "ETH" } : await this.tokenMeta(asset);
    const d: AssetDelta = { asset, decimals: meta.decimals, amount };
    if (meta.symbol) d.symbol = meta.symbol;
    if (this.oracle) {
      try {
        const price = await this.oracle(asset);
        if (price !== undefined) d.usdValue = toDecimal(amount, meta.decimals) * price;
      } catch { /* best effort */ }
    }
    return d;
  }

  private async tokenMeta(token: string): Promise<TokenMeta> {
    const cached = this.metaCache.get(token);
    if (cached) return cached;
    const meta: TokenMeta = { decimals: 18 };
    try {
      const r = await this.client.call({ to: token as Address, data: encodeFunctionData({ abi: ERC20_ABI, functionName: "decimals" }) });
      if (r.data && r.data !== "0x") meta.decimals = Number(decodeFunctionResult({ abi: ERC20_ABI, functionName: "decimals", data: r.data }));
    } catch { /* default 18 */ }
    try {
      const r = await this.client.call({ to: token as Address, data: encodeFunctionData({ abi: ERC20_ABI, functionName: "symbol" }) });
      if (r.data && r.data !== "0x") meta.symbol = decodeFunctionResult({ abi: ERC20_ABI, functionName: "symbol", data: r.data }) as string;
    } catch { /* optional */ }
    this.metaCache.set(token, meta);
    return meta;
  }

  private async hasCode(addr: string): Promise<boolean> {
    const a = lc(addr);
    const cached = this.codeCache.get(a);
    if (cached !== undefined) return cached;
    let has = false;
    try {
      const code = await this.client.getCode({ address: a as Address });
      has = !!code && code !== "0x" && code.length > 2;
    } catch { /* treat as unknown/no code */ }
    this.codeCache.set(a, has);
    return has;
  }
}

function collectLogs(t: TraceResult): TraceLog[] {
  const out: TraceLog[] = [...(t.logs ?? [])];
  const walk = (c: TraceCall) => { out.push(...(c.logs ?? [])); c.calls?.forEach(walk); };
  t.calls?.forEach(walk);
  return out;
}

function collectCalls(t: TraceResult): TraceCall[] {
  const out: TraceCall[] = [];
  const walk = (c: TraceCall) => { out.push(c); c.calls?.forEach(walk); };
  t.calls?.forEach(walk);
  return out;
}

function dedupe(xs: string[]): string[] { return [...new Set(xs)]; }

/**
 * Expected byte length (selector + static ABI words) for decoded calls whose
 * arguments are all static. Returns undefined for dynamic-argument calls (swaps
 * with path arrays, structs) where the length is not fixed.
 */
function expectedCalldataLength(d: DecodedCall): number | undefined {
  switch (d.kind) {
    case "erc20.transfer":
    case "erc20.approve":
    case "erc721.setApprovalForAll":
      return 4 + 2 * 32;
    case "erc20.transferFrom":
      return 4 + 3 * 32;
    case "erc20.permit":
      return 4 + 7 * 32;
    default:
      return undefined;
  }
}
