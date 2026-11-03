import { decodeFunctionData, decodeErrorResult, size, slice, type Hex } from "viem";
import { ALL_ABI } from "./abis.js";

export type DecodedCall =
  | { kind: "erc20.transfer"; to: string; amount: bigint }
  | { kind: "erc20.approve"; spender: string; amount: bigint }
  | { kind: "erc20.transferFrom"; from: string; to: string; amount: bigint }
  | { kind: "erc20.permit"; owner: string; spender: string; value: bigint }
  | { kind: "erc721.setApprovalForAll"; operator: string; approved: boolean }
  | {
      kind: "swap";
      name: string;
      tokenIn: string | "native";
      tokenOut: string | "native";
      amountIn: bigint;          // exact or maximum input
      amountOut: bigint;         // exact or minimum output
      recipient?: string;
    }
  | { kind: "unknown"; selector: string }
  | { kind: "none" };

const lc = (s: string) => s.toLowerCase();

/** Uniswap V3 packed path: token(20) fee(3) token(20) [fee(3) token(20)]... */
function v3PathEnds(path: Hex): { tokenIn: string; tokenOut: string } {
  const len = size(path);
  if (len < 20) return { tokenIn: "", tokenOut: "" };
  return { tokenIn: lc(slice(path, 0, 20)), tokenOut: lc(slice(path, len - 20, len)) };
}

/** Decode EVM calldata into a structured description. Never throws. */
export function decodeCalldata(data: Hex | undefined): DecodedCall {
  if (!data || data === "0x" || size(data) < 4) return { kind: "none" };
  const selector = slice(data, 0, 4);
  let decoded: { functionName: string; args?: readonly unknown[] };
  try {
    decoded = decodeFunctionData({ abi: ALL_ABI, data }) as typeof decoded;
  } catch {
    return { kind: "unknown", selector };
  }
  const a = (decoded.args ?? []) as any[];
  switch (decoded.functionName) {
    case "transfer":
      return { kind: "erc20.transfer", to: lc(a[0]), amount: a[1] };
    case "approve":
      return { kind: "erc20.approve", spender: lc(a[0]), amount: a[1] };
    case "transferFrom":
      return { kind: "erc20.transferFrom", from: lc(a[0]), to: lc(a[1]), amount: a[2] };
    case "permit":
      return { kind: "erc20.permit", owner: lc(a[0]), spender: lc(a[1]), value: a[2] };
    case "setApprovalForAll":
      return { kind: "erc721.setApprovalForAll", operator: lc(a[0]), approved: Boolean(a[1]) };
    case "swapExactTokensForTokens": {
      const path: string[] = a[2];
      return { kind: "swap", name: decoded.functionName, tokenIn: lc(path[0]!), tokenOut: lc(path[path.length - 1]!),
        amountIn: a[0], amountOut: a[1], recipient: lc(a[3]) };
    }
    case "swapTokensForExactTokens": {
      const path: string[] = a[2];
      return { kind: "swap", name: decoded.functionName, tokenIn: lc(path[0]!), tokenOut: lc(path[path.length - 1]!),
        amountIn: a[1], amountOut: a[0], recipient: lc(a[3]) };
    }
    case "swapExactETHForTokens": {
      const path: string[] = a[1];
      return { kind: "swap", name: decoded.functionName, tokenIn: "native", tokenOut: lc(path[path.length - 1]!),
        amountIn: 0n /* from msg.value */, amountOut: a[0], recipient: lc(a[2]) };
    }
    case "swapExactTokensForETH": {
      const path: string[] = a[2];
      return { kind: "swap", name: decoded.functionName, tokenIn: lc(path[0]!), tokenOut: "native",
        amountIn: a[0], amountOut: a[1], recipient: lc(a[3]) };
    }
    case "exactInputSingle": {
      const p = a[0];
      return { kind: "swap", name: decoded.functionName, tokenIn: lc(p.tokenIn), tokenOut: lc(p.tokenOut),
        amountIn: p.amountIn, amountOut: p.amountOutMinimum, recipient: lc(p.recipient) };
    }
    case "exactOutputSingle": {
      const p = a[0];
      return { kind: "swap", name: decoded.functionName, tokenIn: lc(p.tokenIn), tokenOut: lc(p.tokenOut),
        amountIn: p.amountInMaximum, amountOut: p.amountOut, recipient: lc(p.recipient) };
    }
    case "exactInput": {
      const p = a[0];
      const ends = v3PathEnds(p.path);
      return { kind: "swap", name: decoded.functionName, tokenIn: ends.tokenIn, tokenOut: ends.tokenOut,
        amountIn: p.amountIn, amountOut: p.amountOutMinimum, recipient: lc(p.recipient) };
    }
    default:
      return { kind: "unknown", selector };
  }
}

const PANIC_CODES: Record<number, string> = {
  0x01: "assertion failed", 0x11: "arithmetic overflow/underflow", 0x12: "division by zero",
  0x21: "invalid enum conversion", 0x22: "invalid storage byte array", 0x31: "pop on empty array",
  0x32: "array index out of bounds", 0x41: "out of memory", 0x51: "uninitialised function pointer",
};

/** Decode standard Error(string) / Panic(uint256) revert data. */
export function decodeRevertData(data: Hex): string | undefined {
  try {
    const r = decodeErrorResult({
      abi: [
        { type: "error", name: "Error", inputs: [{ name: "message", type: "string" }] },
        { type: "error", name: "Panic", inputs: [{ name: "code", type: "uint256" }] },
      ],
      data,
    });
    if (r.errorName === "Error") return String(r.args[0]);
    if (r.errorName === "Panic") {
      const code = Number(r.args[0]);
      return `panic(0x${code.toString(16)}): ${PANIC_CODES[code] ?? "unknown"}`;
    }
  } catch { /* not standard revert data */ }
  return undefined;
}

/** Best-effort human readable revert reason from any thrown error (viem or mock). */
export function parseRevertReason(err: unknown): string {
  let cur: any = err;
  let fallback: string | undefined;
  for (let i = 0; i < 8 && cur; i++) {
    if (typeof cur.data === "string" && cur.data.startsWith("0x") && cur.data.length >= 10) {
      const d = decodeRevertData(cur.data as Hex);
      if (d) return d;
    }
    if (typeof cur.reason === "string" && cur.reason) return cur.reason;
    if (typeof cur.data === "object" && cur.data && typeof cur.data.errorName === "string") {
      const args = Array.isArray(cur.data.args) ? cur.data.args.map(String).join(", ") : "";
      return `${cur.data.errorName}(${args})`;
    }
    if (!fallback && typeof cur.shortMessage === "string") fallback = cur.shortMessage;
    if (!fallback && typeof cur.details === "string") fallback = cur.details;
    cur = cur.cause;
  }
  if (fallback) return fallback;
  if (err instanceof Error) return err.message;
  return String(err);
}
