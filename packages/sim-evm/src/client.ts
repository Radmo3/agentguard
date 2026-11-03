import type { Address, Hex } from "viem";

/** Arguments accepted by the minimal `call` / `estimateGas` methods. */
export interface CallArgs {
  account?: Address;
  to?: Address;
  data?: Hex;
  value?: bigint;
}

/** Log shape returned by an optional trace provider. */
export interface TraceLog {
  address: Address;
  topics: Hex[];
  data: Hex;
}

/** Nested call shape returned by an optional trace provider (debug_traceCall callTracer-like). */
export interface TraceCall {
  from?: Address;
  to?: Address;
  type?: string;              // CALL | DELEGATECALL | STATICCALL | CREATE | SELFDESTRUCT ...
  value?: bigint | Hex;
  calls?: TraceCall[];
  logs?: TraceLog[];
}

export interface TraceResult {
  logs?: TraceLog[];
  calls?: TraceCall[];
  raw?: unknown;
}

/**
 * Minimal subset of a viem `PublicClient` used by the adapter. A real viem
 * PublicClient satisfies this interface; tests supply a mock.
 */
export interface PublicClientLike {
  call(args: CallArgs): Promise<{ data?: Hex | undefined }>;
  estimateGas(args: CallArgs): Promise<bigint>;
  getCode(args: { address: Address }): Promise<Hex | undefined>;
  /** Optional: a tracing endpoint (e.g. debug_traceCall) providing logs/calls. */
  traceCall?(args: CallArgs): Promise<TraceResult>;
}
