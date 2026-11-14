import type { Chain } from "@signhold/core";
import { ReputationProviderError, type LookupOptions, type ReputationProvider, type ReputationSignal, type ReputationVerdict } from "../types.js";
import { clampScore, isPlausibleAddress, makeSignal } from "../util.js";

// ---------------------------------------------------------------------------
// Minimal client shapes. These are structural subsets of viem's PublicClient and
// @solana/web3.js Connection so real clients (optionally wrapped) satisfy them,
// without this package depending on either library.
// ---------------------------------------------------------------------------

export type Hex = `0x${string}`;

export interface ContractCreationInfo {
  /** Block in which the contract was created. */
  blockNumber?: bigint;
  /** Unix seconds of the creation block, if known. */
  timestamp?: number;
}

/** Subset of viem `PublicClient` used by the EVM heuristics. `getCode` is required; the rest are optional. */
export interface EvmClientLike {
  getCode(args: { address: Hex }): Promise<Hex | undefined>;
  /** Optional: read a raw storage slot (used for EIP-1967 proxy detection). */
  getStorageAt?(args: { address: Hex; slot: Hex }): Promise<Hex | undefined>;
  /** Optional: current block number (used to compute age in blocks). */
  getBlockNumber?(): Promise<bigint>;
  /**
   * Optional: contract-creation lookup. Not part of standard JSON-RPC; operators can
   * back it with an indexer (Etherscan `getcontractcreation`, Alchemy, trace lookups...).
   * Return `null` when unknown.
   */
  getContractCreation?(address: Hex): Promise<ContractCreationInfo | null>;
}

/** Account shape returned by the Solana client; `owner` is base58, `data` is raw bytes. */
export interface SolanaAccountLike {
  executable: boolean;
  owner: string;
  lamports: number | bigint;
  data: Uint8Array;
}

/**
 * Subset of `@solana/web3.js` `Connection`, keyed by base58 strings rather than
 * `PublicKey` so this package stays dependency-free. Wrap a real Connection as:
 *   { getAccountInfo: (a) => conn.getAccountInfo(new PublicKey(a)).then(toLike) }
 */
export interface SolanaClientLike {
  getAccountInfo(address: string): Promise<SolanaAccountLike | null>;
}

export interface OnChainHeuristicsOptions {
  name?: string;
  evm?: EvmClientLike;
  solana?: SolanaClientLike;
  /** Assumed block time for age-in-blocks -> seconds conversion when no timestamp is available. */
  secondsPerBlock?: number;
  /** Score at or above which the verdict becomes "suspicious" (default 60). */
  suspiciousThreshold?: number;
  /** Clock, for tests. */
  now?: () => Date;
}

// EIP-1967 slots
export const EIP1967_IMPLEMENTATION_SLOT: Hex = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
export const EIP1967_BEACON_SLOT: Hex = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
export const EIP1967_ADMIN_SLOT: Hex = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";

// Solana loaders
export const BPF_LOADER_UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111";
export const BPF_LOADER_2 = "BPFLoader2111111111111111111111111111111111";
export const BPF_LOADER_1 = "BPFLoader1111111111111111111111111111111111";
export const NATIVE_LOADER = "NativeLoader1111111111111111111111111111111";
export const SYSTEM_PROGRAM = "11111111111111111111111111111111";

const DAY = 86_400;

/**
 * Derives reputation hints from on-chain state alone. Never returns "trusted" or
 * "malicious": at best it says "unknown" with descriptive tags, at worst
 * "suspicious". Throws `ReputationProviderError` on RPC failure (the service
 * then applies its fail mode).
 */
export class OnChainHeuristicsProvider implements ReputationProvider {
  readonly name: string;
  private readonly evm?: EvmClientLike;
  private readonly solana?: SolanaClientLike;
  private readonly secondsPerBlock: number;
  private readonly suspiciousThreshold: number;
  private readonly now: () => Date;

  constructor(opts: OnChainHeuristicsOptions) {
    this.name = opts.name ?? "onchain";
    this.evm = opts.evm;
    this.solana = opts.solana;
    this.secondsPerBlock = opts.secondsPerBlock ?? 12;
    this.suspiciousThreshold = opts.suspiciousThreshold ?? 60;
    this.now = opts.now ?? (() => new Date());
  }

  async lookup(chain: Chain, address: string, opts: LookupOptions = {}): Promise<ReputationSignal> {
    const fetchedAt = this.now().toISOString();
    if (!isPlausibleAddress(address, chain)) {
      return makeSignal(this.name, "unknown", { score: 50, tags: ["malformed_address"], fetchedAt });
    }
    try {
      const r = chain === "evm" ? await this.evmLookup(address as Hex, opts) : await this.solanaLookup(address, opts);
      const score = clampScore(r.score);
      const verdict: ReputationVerdict = score >= this.suspiciousThreshold ? "suspicious" : "unknown";
      return makeSignal(this.name, verdict, { score, tags: r.tags, evidence: r.evidence, fetchedAt });
    } catch (e) {
      if (e instanceof ReputationProviderError) throw e;
      throw new ReputationProviderError(`on-chain lookup failed: ${(e as Error)?.message ?? String(e)}`, this.name, "rpc", e);
    }
  }

  // ----------------------------------------------------------------- EVM

  private async evmLookup(address: Hex, opts: LookupOptions): Promise<Partial> {
    if (!this.evm) return { score: 50, tags: ["no_evm_client"], evidence: {} };
    const tags: string[] = [];
    const evidence: Record<string, unknown> = {};
    let score = 0;

    throwIfAborted(opts.signal, this.name);
    const code = (await this.evm.getCode({ address })) ?? "0x";
    const bytes = Math.max(0, (code.length - 2) / 2);
    evidence.bytecodeSize = bytes;

    if (bytes === 0) {
      tags.push("eoa", "no_code");
      // Sending to an EOA is usually a plain transfer; mildly uncertain, not suspicious.
      return { score: 10, tags, evidence };
    }
    tags.push("contract");
    if (bytes < 64) {
      tags.push("bytecode_tiny");
      score += 15;
    }
    const lower = code.toLowerCase();
    if (lower.includes("363d3d373d3d3d363d73") && bytes <= 60) {
      tags.push("eip1167_minimal_proxy");
      evidence.minimalProxy = true;
      score += 10;
    }
    if (lower.includes("ff") && bytes < 200 && !tags.includes("eip1167_minimal_proxy")) {
      // Small contracts containing SELFDESTRUCT (0xff) bytes: weak signal, could be data.
      evidence.mayContainSelfdestruct = true;
    }

    if (this.evm.getStorageAt) {
      throwIfAborted(opts.signal, this.name);
      const impl = await this.evm.getStorageAt({ address, slot: EIP1967_IMPLEMENTATION_SLOT });
      const implAddr = slotToAddress(impl);
      if (implAddr) {
        tags.push("eip1967_proxy", "upgradeable");
        evidence.implementation = implAddr;
        score += 15;
        const admin = slotToAddress(await this.evm.getStorageAt({ address, slot: EIP1967_ADMIN_SLOT }));
        if (admin) evidence.admin = admin;
      } else {
        const beacon = slotToAddress(await this.evm.getStorageAt({ address, slot: EIP1967_BEACON_SLOT }));
        if (beacon) {
          tags.push("eip1967_beacon_proxy", "upgradeable");
          evidence.beacon = beacon;
          score += 15;
        }
      }
    }

    // Age
    let ageSeconds: number | undefined;
    if (this.evm.getContractCreation) {
      throwIfAborted(opts.signal, this.name);
      const info = await this.evm.getContractCreation(address);
      if (info) {
        const nowSec = Math.floor(this.now().getTime() / 1000);
        if (typeof info.timestamp === "number" && Number.isFinite(info.timestamp)) {
          ageSeconds = Math.max(0, nowSec - info.timestamp);
          evidence.createdAt = new Date(info.timestamp * 1000).toISOString();
        } else if (typeof info.blockNumber === "bigint" && this.evm.getBlockNumber) {
          const head = await this.evm.getBlockNumber();
          const blocks = head > info.blockNumber ? head - info.blockNumber : 0n;
          ageSeconds = Number(blocks) * this.secondsPerBlock;
          evidence.createdAtBlock = info.blockNumber.toString();
          evidence.ageBlocks = blocks.toString();
        }
      }
    }
    if (ageSeconds === undefined) {
      tags.push("age_unknown");
      score += 10;
    } else {
      evidence.ageSeconds = ageSeconds;
      if (ageSeconds < DAY) {
        tags.push("age_lt_1d");
        score += 60; // new-today contracts are suspicious on their own
      } else if (ageSeconds < 7 * DAY) {
        tags.push("age_lt_7d");
        score += 30;
      } else if (ageSeconds < 30 * DAY) {
        tags.push("age_lt_30d");
        score += 15;
      } else {
        tags.push("age_gte_30d");
      }
    }
    return { score, tags, evidence };
  }

  // -------------------------------------------------------------- Solana

  private async solanaLookup(address: string, opts: LookupOptions): Promise<Partial> {
    if (!this.solana) return { score: 50, tags: ["no_solana_client"], evidence: {} };
    const tags: string[] = [];
    const evidence: Record<string, unknown> = {};
    let score = 0;

    throwIfAborted(opts.signal, this.name);
    const acct = await this.solana.getAccountInfo(address);
    if (!acct) {
      tags.push("account_not_found");
      evidence.exists = false;
      return { score: 20, tags, evidence };
    }
    evidence.owner = acct.owner;
    evidence.executable = acct.executable;
    evidence.dataLength = acct.data.length;

    if (!acct.executable) {
      if (acct.owner === SYSTEM_PROGRAM) tags.push("wallet", "system_owned");
      else tags.push("data_account");
      return { score: 10, tags, evidence };
    }

    tags.push("program");
    switch (acct.owner) {
      case NATIVE_LOADER:
        tags.push("native_program");
        break;
      case BPF_LOADER_1:
      case BPF_LOADER_2:
        tags.push("immutable_program");
        break;
      case BPF_LOADER_UPGRADEABLE: {
        tags.push("upgradeable_loader");
        const pd = parseProgramAccount(acct.data);
        if (!pd) {
          tags.push("program_account_malformed");
          score += 30;
          break;
        }
        evidence.programData = pd;
        throwIfAborted(opts.signal, this.name);
        const pdAcct = await this.solana.getAccountInfo(pd);
        const parsed = pdAcct ? parseProgramDataAccount(pdAcct.data) : null;
        if (!parsed) {
          tags.push("programdata_missing");
          score += 30;
          break;
        }
        evidence.lastDeploySlot = parsed.slot.toString();
        if (parsed.upgradeAuthority) {
          tags.push("upgradeable", "upgrade_authority_set");
          evidence.upgradeAuthority = parsed.upgradeAuthority;
          score += 25;
        } else {
          tags.push("upgrade_authority_revoked");
        }
        break;
      }
      default:
        tags.push("unknown_loader");
        score += 20;
    }
    return { score, tags, evidence };
  }
}

interface Partial {
  score: number;
  tags: string[];
  evidence: Record<string, unknown>;
}

function throwIfAborted(signal: AbortSignal | undefined, source: string) {
  if (signal?.aborted) throw new ReputationProviderError("lookup aborted", source, "aborted");
}

/** Extract the low 20 bytes of a 32-byte storage word as an address; undefined when zero/absent. */
export function slotToAddress(word: Hex | undefined): Hex | undefined {
  if (!word || !/^0x[0-9a-fA-F]*$/.test(word)) return undefined;
  const hex = word.slice(2).padStart(64, "0").slice(-40).toLowerCase();
  if (/^0+$/.test(hex)) return undefined;
  return `0x${hex}`;
}

// --- Solana upgradeable-loader layouts (little-endian u32 discriminators) ---
// Program:     [u32 = 2][pubkey programdata]
// ProgramData: [u32 = 3][u64 slot][u8 option][pubkey upgrade_authority?]

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Encode 32 raw bytes as base58 (no external deps). */
export function base58Encode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]!;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]!];
  return out;
}

export function parseProgramAccount(data: Uint8Array): string | null {
  if (data.length < 36) return null;
  const disc = readU32LE(data, 0);
  if (disc !== 2) return null;
  return base58Encode(data.subarray(4, 36));
}

export function parseProgramDataAccount(data: Uint8Array): { slot: bigint; upgradeAuthority: string | null } | null {
  if (data.length < 13) return null;
  const disc = readU32LE(data, 0);
  if (disc !== 3) return null;
  const slot = readU64LE(data, 4);
  const hasAuth = data[12];
  if (hasAuth === 0) return { slot, upgradeAuthority: null };
  if (hasAuth === 1 && data.length >= 45) return { slot, upgradeAuthority: base58Encode(data.subarray(13, 45)) };
  return null;
}

function readU32LE(d: Uint8Array, o: number): number {
  return (d[o]! | (d[o + 1]! << 8) | (d[o + 2]! << 16) | (d[o + 3]! << 24)) >>> 0;
}

function readU64LE(d: Uint8Array, o: number): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(d[o + i]!);
  return v;
}
