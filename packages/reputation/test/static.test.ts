import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { StaticListProvider, bundledTrustedSeed, parseListFile } from "../src/index.js";
import { ROUTER, SHADY, USDC } from "./helpers.js";

describe("StaticListProvider", () => {
  it("bundled seed includes well-known contracts and programs", async () => {
    const seed = bundledTrustedSeed();
    expect(seed.length).toBeGreaterThan(15);
    const p = new StaticListProvider();
    expect((await p.lookup("evm", USDC, { chainId: 1 })).verdict).toBe("trusted");
    expect((await p.lookup("evm", ROUTER, { chainId: 1 })).verdict).toBe("trusted");
    expect((await p.lookup("evm", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", { chainId: 8453 })).verdict).toBe("trusted");
    expect((await p.lookup("solana", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")).verdict).toBe("trusted");
    expect((await p.lookup("solana", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")).verdict).toBe("trusted");
    expect((await p.lookup("solana", "11111111111111111111111111111111")).verdict).toBe("trusted");
    expect((await p.lookup("solana", "ComputeBudget111111111111111111111111111111")).verdict).toBe("trusted");
  });

  it("is case-insensitive on EVM, case-sensitive on Solana", async () => {
    const p = new StaticListProvider();
    expect((await p.lookup("evm", USDC.toLowerCase(), { chainId: 1 })).verdict).toBe("trusted");
    expect((await p.lookup("solana", "tokenkegqfezyinwajbnbgkpfxcwubvf9ss623vq5da")).verdict).toBe("unknown");
  });

  it("seed entries are scoped by chainId; USDC mainnet is not trusted on chain 8453 or without chainId", async () => {
    const p = new StaticListProvider();
    expect((await p.lookup("evm", USDC, { chainId: 8453 })).verdict).toBe("unknown");
    expect((await p.lookup("evm", USDC)).verdict).toBe("unknown");
  });

  it("deny wins over allow and carries tags", async () => {
    const p = new StaticListProvider({ includeSeed: false, allow: [{ chain: "evm", address: SHADY }], deny: [{ chain: "evm", address: SHADY, tags: ["drainer"] }] });
    const s = await p.lookup("evm", SHADY, { chainId: 1 });
    expect(s.verdict).toBe("malicious");
    expect(s.score).toBe(100);
    expect(s.tags).toEqual(["denylisted", "drainer"]);
    expect(s.source).toBe("static");
  });

  it("unlisted => unknown/not_listed with score 50", async () => {
    const p = new StaticListProvider({ includeSeed: false });
    const s = await p.lookup("evm", SHADY);
    expect(s).toMatchObject({ verdict: "unknown", score: 50, tags: ["not_listed"] });
  });

  it("loads from files and rejects malformed files", () => {
    const dir = mkdtempSync(join(tmpdir(), "rep-"));
    const good = join(dir, "deny.json");
    writeFileSync(good, JSON.stringify({ entries: [{ chain: "evm", address: SHADY, tags: ["X".repeat(70), "ok-tag", "Bad Tag"] }] }));
    const p = StaticListProvider.fromFiles({ denyFiles: [good], includeSeed: false });
    expect(p.sizes).toEqual({ allow: 0, deny: 1 });
    const bad = join(dir, "bad.json");
    writeFileSync(bad, JSON.stringify({ entries: [{ chain: "btc", address: "x" }] }));
    expect(() => StaticListProvider.fromFiles({ denyFiles: [bad] })).toThrow(/invalid chain/);
    writeFileSync(bad, "{not json");
    expect(() => StaticListProvider.fromFiles({ denyFiles: [bad] })).toThrow(/invalid JSON/);
  });

  it("sanitizes tags from list files", async () => {
    const entries = parseListFile({ entries: [{ chain: "evm", address: SHADY, tags: ["X".repeat(70), "OK-Tag", "bad tag", 5] }] });
    expect(entries[0]?.tags).toEqual(["ok-tag"]);
    expect(() => parseListFile({ entries: "nope" })).toThrow();
    expect(() => parseListFile([])).toThrow();
  });
});
