import { describe, expect, it } from "vitest";
import {
  BPF_LOADER_2,
  BPF_LOADER_UPGRADEABLE,
  EIP1967_IMPLEMENTATION_SLOT,
  OnChainHeuristicsProvider,
  ReputationProviderError,
  SYSTEM_PROGRAM,
  base58Encode,
  slotToAddress,
  type EvmClientLike,
  type Hex,
  type SolanaAccountLike,
  type SolanaClientLike,
} from "../src/index.js";
import { OTHER, SHADY } from "./helpers.js";

const NOW = new Date("2026-01-10T00:00:00Z");
const nowSec = Math.floor(NOW.getTime() / 1000);

function evmClient(over: Partial<EvmClientLike> & { code?: Record<string, Hex> } = {}): EvmClientLike {
  return {
    getCode: async ({ address }) => over.code?.[address.toLowerCase()] ?? "0x",
    ...over,
  };
}

const CODE_BIG = ("0x" + "60".repeat(500)) as Hex;

describe("OnChainHeuristicsProvider (EVM)", () => {
  it("EOA => eoa/no_code tags, low score", async () => {
    const p = new OnChainHeuristicsProvider({ evm: evmClient(), now: () => NOW });
    const s = await p.lookup("evm", SHADY);
    expect(s.verdict).toBe("unknown");
    expect(s.tags).toEqual(["eoa", "no_code"]);
    expect(s.score).toBe(10);
    expect(s.evidence?.bytecodeSize).toBe(0);
  });

  it("contract with unknown age => age_unknown", async () => {
    const p = new OnChainHeuristicsProvider({ evm: evmClient({ code: { [SHADY]: CODE_BIG } }), now: () => NOW });
    const s = await p.lookup("evm", SHADY);
    expect(s.tags).toContain("contract");
    expect(s.tags).toContain("age_unknown");
    expect(s.verdict).toBe("unknown");
    expect(s.evidence?.bytecodeSize).toBe(500);
  });

  it("brand-new contract => age_lt_1d and suspicious", async () => {
    const p = new OnChainHeuristicsProvider({
      evm: evmClient({ code: { [SHADY]: CODE_BIG }, getContractCreation: async () => ({ timestamp: nowSec - 3600 }) }),
      now: () => NOW,
    });
    const s = await p.lookup("evm", SHADY);
    expect(s.tags).toContain("age_lt_1d");
    expect(s.score).toBeGreaterThanOrEqual(45);
    expect(s.verdict).toBe("suspicious");
  });

  it("old contract => age_gte_30d, not suspicious", async () => {
    const p = new OnChainHeuristicsProvider({
      evm: evmClient({ code: { [SHADY]: CODE_BIG }, getContractCreation: async () => ({ timestamp: nowSec - 400 * 86400 }) }),
      now: () => NOW,
    });
    const s = await p.lookup("evm", SHADY);
    expect(s.tags).toContain("age_gte_30d");
    expect(s.verdict).toBe("unknown");
    expect(s.score).toBe(0);
  });

  it("age via block numbers when only blockNumber is known", async () => {
    const p = new OnChainHeuristicsProvider({
      evm: evmClient({
        code: { [SHADY]: CODE_BIG },
        getContractCreation: async () => ({ blockNumber: 1000n }),
        getBlockNumber: async () => 1000n + 7200n * 3n, // 3 days at 12s
      }),
      now: () => NOW,
    });
    const s = await p.lookup("evm", SHADY);
    expect(s.tags).toContain("age_lt_7d");
    expect(s.evidence?.ageBlocks).toBe("21600");
  });

  it("detects EIP-1967 proxies when getStorageAt is available", async () => {
    const impl = ("0x" + "00".repeat(12) + OTHER.slice(2)) as Hex;
    const p = new OnChainHeuristicsProvider({
      evm: evmClient({
        code: { [SHADY]: CODE_BIG },
        getStorageAt: async ({ slot }) => (slot === EIP1967_IMPLEMENTATION_SLOT ? impl : ("0x" + "00".repeat(32)) as Hex),
      }),
      now: () => NOW,
    });
    const s = await p.lookup("evm", SHADY);
    expect(s.tags).toContain("eip1967_proxy");
    expect(s.tags).toContain("upgradeable");
    expect(s.evidence?.implementation).toBe(OTHER.toLowerCase());
  });

  it("detects EIP-1167 minimal proxies / tiny bytecode", async () => {
    const code = ("0x363d3d373d3d3d363d73" + OTHER.slice(2) + "5af43d82803e903d91602b57fd5bf3") as Hex;
    const p = new OnChainHeuristicsProvider({ evm: evmClient({ code: { [SHADY]: code } }), now: () => NOW });
    const s = await p.lookup("evm", SHADY);
    expect(s.tags).toContain("eip1167_minimal_proxy");
    expect(s.tags).toContain("bytecode_tiny");
  });

  it("malformed address => unknown/malformed_address without calling the client", async () => {
    let called = false;
    const p = new OnChainHeuristicsProvider({ evm: { getCode: async () => { called = true; return "0x"; } } });
    const s = await p.lookup("evm", "not-an-address");
    expect(s.tags).toEqual(["malformed_address"]);
    expect(called).toBe(false);
  });

  it("RPC failure throws ReputationProviderError(rpc)", async () => {
    const p = new OnChainHeuristicsProvider({ evm: { getCode: async () => { throw new Error("rpc down"); } } });
    await expect(p.lookup("evm", SHADY)).rejects.toBeInstanceOf(ReputationProviderError);
    await expect(p.lookup("evm", SHADY)).rejects.toMatchObject({ code: "rpc" });
  });

  it("no client for chain => no_evm_client", async () => {
    const p = new OnChainHeuristicsProvider({});
    expect((await p.lookup("evm", SHADY)).tags).toEqual(["no_evm_client"]);
  });

  it("slotToAddress handles zero and short words", () => {
    expect(slotToAddress(("0x" + "00".repeat(32)) as Hex)).toBeUndefined();
    expect(slotToAddress("0x1")).toBe("0x0000000000000000000000000000000000000001");
    expect(slotToAddress(undefined)).toBeUndefined();
  });
});

// ---------------------------------------------------------------- Solana

const PROGRAM = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const PROGRAMDATA_BYTES = new Uint8Array(32).fill(7);
const PROGRAMDATA = base58Encode(PROGRAMDATA_BYTES);
const AUTH_BYTES = new Uint8Array(32).fill(9);

function u32(n: number) {
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
}

function programAccount(): SolanaAccountLike {
  return { executable: true, owner: BPF_LOADER_UPGRADEABLE, lamports: 1, data: new Uint8Array([...u32(2), ...PROGRAMDATA_BYTES]) };
}

function programDataAccount(auth: Uint8Array | null): SolanaAccountLike {
  const slot = [1, 0, 0, 0, 0, 0, 0, 0];
  const data = auth ? [...u32(3), ...slot, 1, ...auth] : [...u32(3), ...slot, 0];
  return { executable: false, owner: BPF_LOADER_UPGRADEABLE, lamports: 1, data: new Uint8Array(data) };
}

function solClient(accounts: Record<string, SolanaAccountLike | null>): SolanaClientLike {
  return { getAccountInfo: async (a) => accounts[a] ?? null };
}

describe("OnChainHeuristicsProvider (Solana)", () => {
  it("upgradeable program with authority set => upgradeable/upgrade_authority_set", async () => {
    const p = new OnChainHeuristicsProvider({ solana: solClient({ [PROGRAM]: programAccount(), [PROGRAMDATA]: programDataAccount(AUTH_BYTES) }) });
    const s = await p.lookup("solana", PROGRAM);
    expect(s.tags).toEqual(expect.arrayContaining(["program", "upgradeable_loader", "upgradeable", "upgrade_authority_set"]));
    expect(s.evidence?.upgradeAuthority).toBe(base58Encode(AUTH_BYTES));
    expect(s.evidence?.programData).toBe(PROGRAMDATA);
    expect(s.score).toBe(25);
  });

  it("upgrade authority revoked => upgrade_authority_revoked, score 0", async () => {
    const p = new OnChainHeuristicsProvider({ solana: solClient({ [PROGRAM]: programAccount(), [PROGRAMDATA]: programDataAccount(null) }) });
    const s = await p.lookup("solana", PROGRAM);
    expect(s.tags).toContain("upgrade_authority_revoked");
    expect(s.tags).not.toContain("upgradeable");
    expect(s.score).toBe(0);
  });

  it("missing ProgramData => programdata_missing", async () => {
    const p = new OnChainHeuristicsProvider({ solana: solClient({ [PROGRAM]: programAccount() }) });
    const s = await p.lookup("solana", PROGRAM);
    expect(s.tags).toContain("programdata_missing");
    expect(s.score).toBe(30);
  });

  it("immutable loader program", async () => {
    const p = new OnChainHeuristicsProvider({ solana: solClient({ [PROGRAM]: { executable: true, owner: BPF_LOADER_2, lamports: 1, data: new Uint8Array(0) } }) });
    const s = await p.lookup("solana", PROGRAM);
    expect(s.tags).toContain("immutable_program");
  });

  it("system-owned wallet and missing account", async () => {
    const p = new OnChainHeuristicsProvider({ solana: solClient({ [PROGRAM]: { executable: false, owner: SYSTEM_PROGRAM, lamports: 1, data: new Uint8Array(0) } }) });
    expect((await p.lookup("solana", PROGRAM)).tags).toEqual(["wallet", "system_owned"]);
    const p2 = new OnChainHeuristicsProvider({ solana: solClient({}) });
    expect((await p2.lookup("solana", PROGRAM)).tags).toEqual(["account_not_found"]);
  });

  it("base58Encode round-trips a known key", () => {
    expect(base58Encode(new Uint8Array(32))).toBe("11111111111111111111111111111111");
  });
});
