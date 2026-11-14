import { describe, it, expect } from "vitest";
import { encodeFunctionData, encodeErrorResult, encodeAbiParameters, type Hex } from "viem";
import { UINT256_MAX } from "@signhold/core";
import { EvmAdapter, ERC20_ABI, SWAP_ABI, type PublicClientLike, type CallArgs } from "../src/index.js";

const AGENT = "0x1111111111111111111111111111111111111111";
const BOB = "0x2222222222222222222222222222222222222222";
const TOKEN = "0x3333333333333333333333333333333333333333";
const ROUTER = "0x4444444444444444444444444444444444444444";
const SPENDER_EOA = "0x5555555555555555555555555555555555555555";
const TOKEN2 = "0x6666666666666666666666666666666666666666";

const SEL_DECIMALS = encodeFunctionData({ abi: ERC20_ABI, functionName: "decimals" });
const SEL_SYMBOL = encodeFunctionData({ abi: ERC20_ABI, functionName: "symbol" });
const SEL_ALLOWANCE = "0xdd62ed3e";

interface MockOpts {
  contracts?: string[];
  revert?: unknown;
  allowance?: bigint;
  traceCall?: PublicClientLike["traceCall"];
}

function mockClient(opts: MockOpts = {}): PublicClientLike & { calls: CallArgs[] } {
  const contracts = new Set((opts.contracts ?? [TOKEN, ROUTER, TOKEN2]).map((a) => a.toLowerCase()));
  const calls: CallArgs[] = [];
  const client: PublicClientLike & { calls: CallArgs[] } = {
    calls,
    async call(args) {
      const data = args.data ?? "0x";
      // metadata / view calls
      if (data === SEL_DECIMALS) return { data: encodeAbiParameters([{ type: "uint8" }], [6]) };
      if (data === SEL_SYMBOL) return { data: encodeAbiParameters([{ type: "string" }], ["USDC"]) };
      if (data.startsWith(SEL_ALLOWANCE)) return { data: encodeAbiParameters([{ type: "uint256" }], [opts.allowance ?? 0n]) };
      calls.push(args);
      if (opts.revert) throw opts.revert;
      return { data: "0x" };
    },
    async estimateGas() { return 21_000n; },
    async getCode({ address }) { return contracts.has(address.toLowerCase()) ? ("0x6001" as Hex) : ("0x" as Hex); },
  };
  if (opts.traceCall) client.traceCall = opts.traceCall;
  return client;
}

describe("EvmAdapter", () => {
  it("decodes a plain ERC-20 transfer into an outflow delta", async () => {
    const adapter = new EvmAdapter({ client: mockClient(), knownContracts: new Set([TOKEN]), priceOracle: async () => 1 });
    const data = encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [BOB, 1_000_000n] });
    const res = await adapter.simulate({ id: "1", chain: "evm", from: AGENT, to: TOKEN, data });
    expect(res.ok).toBe(true);
    expect(res.revertReason).toBeUndefined();
    expect(res.deltas).toEqual([{ asset: TOKEN, symbol: "USDC", decimals: 6, amount: -1_000_000n, usdValue: -1 }]);
    expect(res.approvals).toEqual([]);
    expect(res.contractsTouched).toEqual([TOKEN]);
    expect(res.newContracts).toEqual([]);
    expect(res.gasEstimate).toBe(21_000n);
    expect(res.warnings).toEqual([]);
  });

  it("records native value outflow and high-value warning", async () => {
    const adapter = new EvmAdapter({ client: mockClient() });
    const res = await adapter.simulate({ id: "2", chain: "evm", from: AGENT, to: BOB, value: 5n * 10n ** 18n });
    expect(res.ok).toBe(true);
    expect(res.deltas[0]).toMatchObject({ asset: "native", amount: -(5n * 10n ** 18n), decimals: 18 });
    expect(res.warnings.some((w) => w.startsWith("high value"))).toBe(true);
  });

  it("flags an unlimited approve to an EOA", async () => {
    const adapter = new EvmAdapter({ client: mockClient({ allowance: 5n }), knownContracts: new Set([TOKEN]) });
    const data = encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [SPENDER_EOA, UINT256_MAX] });
    const res = await adapter.simulate({ id: "3", chain: "evm", from: AGENT, to: TOKEN, data });
    expect(res.ok).toBe(true);
    expect(res.approvals).toEqual([{ token: TOKEN, spender: SPENDER_EOA, previous: 5n, next: UINT256_MAX, unlimited: true, spenderIsContract: false }]);
    expect(res.warnings).toContain(`unlimited approval of ${TOKEN} to ${SPENDER_EOA}`);
    expect(res.warnings).toContain(`approval to EOA ${SPENDER_EOA}`);
  });

  it("does not flag a bounded approve to a contract", async () => {
    const adapter = new EvmAdapter({ client: mockClient() });
    const data = encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [ROUTER, 100n] });
    const res = await adapter.simulate({ id: "4", chain: "evm", from: AGENT, to: TOKEN, data });
    expect(res.approvals[0]).toMatchObject({ spender: ROUTER, next: 100n, unlimited: false });
    expect(res.warnings).toEqual([]);
  });

  it("returns ok=false with a parsed reason on revert instead of throwing", async () => {
    const revertData = encodeErrorResult({
      abi: [{ type: "error", name: "Error", inputs: [{ name: "m", type: "string" }] }],
      errorName: "Error", args: ["ERC20: transfer amount exceeds balance"],
    });
    const err = Object.assign(new Error("execution reverted"), { cause: { data: revertData } });
    const adapter = new EvmAdapter({ client: mockClient({ revert: err }) });
    const data = encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [BOB, 1n] });
    const res = await adapter.simulate({ id: "5", chain: "evm", from: AGENT, to: TOKEN, data });
    expect(res.ok).toBe(false);
    expect(res.revertReason).toBe("ERC20: transfer amount exceeds balance");
    expect(res.gasEstimate).toBeUndefined();
  });

  it("falls back to the error message when revert data is absent", async () => {
    const adapter = new EvmAdapter({ client: mockClient({ revert: new Error("execution reverted: nope") }) });
    const res = await adapter.simulate({ id: "6", chain: "evm", from: AGENT, to: TOKEN, data: "0xa9059cbb" });
    expect(res.ok).toBe(false);
    expect(res.revertReason).toContain("nope");
  });

  it("warns on an unknown selector and reports an unknown contract", async () => {
    const adapter = new EvmAdapter({ client: mockClient(), knownContracts: new Set([TOKEN]) });
    const res = await adapter.simulate({ id: "7", chain: "evm", from: AGENT, to: ROUTER, data: "0xdeadbeef00000000" });
    expect(res.ok).toBe(true);
    expect(res.warnings).toContain("unknown function selector 0xdeadbeef");
    expect(res.newContracts).toEqual([ROUTER]);
  });

  it("warns when calldata targets an address with no code", async () => {
    const adapter = new EvmAdapter({ client: mockClient() });
    const res = await adapter.simulate({ id: "8", chain: "evm", from: AGENT, to: SPENDER_EOA, data: "0xdeadbeef" });
    expect(res.warnings.some((w) => w.includes("has no code"))).toBe(true);
  });

  it("decodes a Uniswap V2 swap into in/out deltas and touches path tokens", async () => {
    const adapter = new EvmAdapter({ client: mockClient() });
    const data = encodeFunctionData({
      abi: SWAP_ABI, functionName: "swapExactTokensForTokens",
      args: [1000n, 0n, [TOKEN, TOKEN2], AGENT, 9999999999n],
    });
    const res = await adapter.simulate({ id: "9", chain: "evm", from: AGENT, to: ROUTER, data });
    expect(res.deltas).toEqual([expect.objectContaining({ asset: TOKEN, amount: -1000n })]);
    expect(res.contractsTouched).toEqual(expect.arrayContaining([ROUTER, TOKEN, TOKEN2]));
    expect(res.warnings.some((w) => w.includes("zero minimum output"))).toBe(true);
  });

  it("prefers Transfer-event deltas from traceCall when available", async () => {
    const transferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    const pad = (a: string) => ("0x" + a.slice(2).padStart(64, "0")) as Hex;
    const client = mockClient({
      traceCall: async () => ({
        logs: [
          { address: TOKEN, topics: [transferTopic, pad(AGENT), pad(ROUTER)], data: encodeAbiParameters([{ type: "uint256" }], [1000n]) },
          { address: TOKEN2, topics: [transferTopic, pad(ROUTER), pad(AGENT)], data: encodeAbiParameters([{ type: "uint256" }], [900n]) },
        ],
        calls: [{ to: ROUTER, type: "CALL", calls: [{ to: TOKEN, type: "CALL" }, { to: TOKEN2, type: "SELFDESTRUCT" }] }],
      }),
    });
    const adapter = new EvmAdapter({ client });
    const data = encodeFunctionData({ abi: SWAP_ABI, functionName: "swapExactTokensForTokens", args: [1000n, 1n, [TOKEN, TOKEN2], AGENT, 1n] });
    const res = await adapter.simulate({ id: "10", chain: "evm", from: AGENT, to: ROUTER, data });
    expect(res.deltas).toEqual([
      expect.objectContaining({ asset: TOKEN, amount: -1000n }),
      expect.objectContaining({ asset: TOKEN2, amount: 900n }),
    ]);
    expect(res.warnings).toContain(`selfdestruct in call to ${TOKEN2}`);
  });

  it("flags ERC-721 setApprovalForAll as an unlimited approval", async () => {
    const adapter = new EvmAdapter({ client: mockClient() });
    const data = encodeFunctionData({
      abi: [{ type: "function", name: "setApprovalForAll", stateMutability: "nonpayable",
        inputs: [{ name: "o", type: "address" }, { name: "a", type: "bool" }], outputs: [] }],
      functionName: "setApprovalForAll", args: [ROUTER, true],
    });
    const res = await adapter.simulate({ id: "11", chain: "evm", from: AGENT, to: TOKEN, data });
    expect(res.approvals[0]).toMatchObject({ token: TOKEN, spender: ROUTER, unlimited: true });
  });

  it("never throws even when the client itself blows up", async () => {
    const broken = { call: async () => { throw new TypeError("boom"); }, estimateGas: async () => 0n, getCode: async () => { throw new Error("rpc down"); } };
    const adapter = new EvmAdapter({ client: broken });
    const res = await adapter.simulate({ id: "12", chain: "evm", from: AGENT, to: BOB, value: 1n });
    expect(res.ok).toBe(false);
    expect(res.revertReason).toContain("boom");
  });
});
