import { InMemoryAuditStore, JsonlAuditStore } from "./audit.js";
import { bootstrap } from "./bootstrap.js";
import { createServer } from "./server.js";
import type { AuditStore } from "./types.js";

function envInt(name: string, fallback: number): number {
  const v = process.env[name];
  if (!v) return fallback;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) throw new Error(`${name} must be an integer, got '${v}'`);
  return n;
}

/** Comma-separated list; undefined when unset so adapters skip new-contract detection. */
function envList(name: string): string[] | undefined {
  const v = process.env[name];
  if (v === undefined) return undefined;
  return v.split(",").map((s) => s.trim()).filter(Boolean);
}

async function main(): Promise<void> {
  const env = process.env;
  const port = envInt("PORT", 8787);
  const host = env.HOST ?? "0.0.0.0";

  const apiKeys = (env.AGENTGUARD_API_KEYS ?? "").split(",").map((s) => s.trim()).filter(Boolean);

  const audit: AuditStore = env.AGENTGUARD_AUDIT_FILE
    ? new JsonlAuditStore(env.AGENTGUARD_AUDIT_FILE)
    : new InMemoryAuditStore();

  const wiring = await bootstrap({
    policyPath: env.AGENTGUARD_POLICY_FILE,
    evmRpcUrl: env.AGENTGUARD_EVM_RPC_URL,
    solanaRpcUrl: env.AGENTGUARD_SOLANA_RPC_URL,
    knownEvmContracts: envList("AGENTGUARD_KNOWN_EVM_CONTRACTS"),
    knownSolanaPrograms: envList("AGENTGUARD_KNOWN_SOLANA_PROGRAMS"),
  });

  const rateMax = envInt("AGENTGUARD_RATE_LIMIT_MAX", 0);
  const app = await createServer({
    ...wiring,
    audit,
    apiKeys,
    rateLimit: rateMax > 0 ? { max: rateMax, timeWindowMs: envInt("AGENTGUARD_RATE_LIMIT_WINDOW_MS", 60_000) } : undefined,
    logger: { level: env.LOG_LEVEL ?? "info" },
  });

  const shutdown = async (signal: string) => {
    app.log.info({ signal }, "shutting down");
    await app.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));

  await app.listen({ port, host });
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
