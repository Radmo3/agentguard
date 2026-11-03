import { InMemoryAuditStore, JsonlAuditStore } from "./audit.js";
import { parseApiKeysEnv } from "./auth.js";
import { bootstrap } from "./bootstrap.js";
import { createEd25519Signer, generateEphemeralSigner, loadEd25519PrivateKey, loadEd25519PublicKey, keyIdOf, type AuditSigner } from "./integrity.js";
import { createServer } from "./server.js";
import type { AuditStore } from "./types.js";

function envInt(name: string, fallback: number): number {
  const v = process.env[name];
  if (!v) return fallback;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) throw new Error(`${name} must be an integer, got '${v}'`);
  return n;
}

function envBool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  return ["1", "true", "yes", "on"].includes(v.toLowerCase());
}

/** Comma-separated list; undefined when unset so adapters skip new-contract detection. */
function envList(name: string): string[] | undefined {
  const v = process.env[name];
  if (v === undefined) return undefined;
  return v.split(",").map((s) => s.trim()).filter(Boolean);
}

async function main(): Promise<void> {
  const env = process.env;
  const nodeEnv = env.NODE_ENV ?? "development";
  const isProd = nodeEnv === "production";
  const port = envInt("PORT", 8787);
  const host = env.HOST ?? "0.0.0.0";

  const apiKeys = parseApiKeysEnv(env.AGENTGUARD_API_KEYS);
  if (apiKeys.length === 0 && isProd) {
    throw new Error("AGENTGUARD_API_KEYS must be set when NODE_ENV=production");
  }

  // ---- Audit signing key ----
  let signer: AuditSigner | undefined;
  if (env.AGENTGUARD_AUDIT_SIGNING_KEY) {
    signer = createEd25519Signer(loadEd25519PrivateKey(env.AGENTGUARD_AUDIT_SIGNING_KEY));
  } else if (isProd) {
    throw new Error("AGENTGUARD_AUDIT_SIGNING_KEY must be set when NODE_ENV=production (Ed25519 seed or PKCS#8 PEM)");
  } else if (envBool("AGENTGUARD_AUDIT_SIGNING", true)) {
    signer = generateEphemeralSigner();
    console.warn(`[agentguard] AGENTGUARD_AUDIT_SIGNING_KEY not set: generated an EPHEMERAL Ed25519 audit signing key (keyId ${signer.keyId}). Records signed with it cannot be verified after restart.`);
  }

  const auditPublicKeys = new Map<string, import("node:crypto").KeyObject>();
  if (signer) {
    const pk = loadEd25519PublicKey(signer.publicKeyPem);
    auditPublicKeys.set(keyIdOf(pk), pk);
  }
  for (const extra of envList("AGENTGUARD_AUDIT_PUBLIC_KEYS") ?? []) {
    const pk = loadEd25519PublicKey(extra);
    auditPublicKeys.set(keyIdOf(pk), pk);
  }

  const audit: AuditStore = env.AGENTGUARD_AUDIT_FILE
    ? new JsonlAuditStore(env.AGENTGUARD_AUDIT_FILE, { signer })
    : new InMemoryAuditStore({ signer });

  const wiring = await bootstrap({
    policyPath: env.AGENTGUARD_POLICY_FILE,
    evmRpcUrl: env.AGENTGUARD_EVM_RPC_URL,
    solanaRpcUrl: env.AGENTGUARD_SOLANA_RPC_URL,
    knownEvmContracts: envList("AGENTGUARD_KNOWN_EVM_CONTRACTS"),
    knownSolanaPrograms: envList("AGENTGUARD_KNOWN_SOLANA_PROGRAMS"),
    profilePath: envBool("AGENTGUARD_BEHAVIOR", true) ? env.AGENTGUARD_PROFILE_FILE : false,
    reputation: envBool("AGENTGUARD_REPUTATION", true),
    reputationAllowlistFiles: envList("AGENTGUARD_REPUTATION_ALLOWLIST"),
    reputationDenylistFiles: envList("AGENTGUARD_REPUTATION_DENYLIST"),
    reputationHttpUrl: env.AGENTGUARD_REPUTATION_HTTP_URL,
  });

  const rateMax = envInt("AGENTGUARD_RATE_LIMIT_MAX", 120);
  const corsOrigins = envList("AGENTGUARD_CORS_ORIGINS");
  const trustProxyRaw = env.AGENTGUARD_TRUST_PROXY;
  const trustProxy: boolean | string | number =
    trustProxyRaw === undefined || trustProxyRaw === "" ? false
    : trustProxyRaw === "true" ? true
    : trustProxyRaw === "false" ? false
    : /^\d+$/.test(trustProxyRaw) ? Number(trustProxyRaw)
    : trustProxyRaw; // CIDR list

  const app = await createServer({
    ...wiring,
    audit,
    apiKeys,
    env: nodeEnv,
    signing: {
      required: envBool("AGENTGUARD_REQUIRE_SIGNED_REQUESTS", false),
      windowMs: envInt("AGENTGUARD_SIGNING_WINDOW_MS", 5 * 60_000),
    },
    rateLimit: rateMax > 0 ? { max: rateMax, timeWindowMs: envInt("AGENTGUARD_RATE_LIMIT_WINDOW_MS", 60_000) } : false,
    bodyLimit: envInt("AGENTGUARD_BODY_LIMIT_BYTES", 64 * 1024),
    trustProxy,
    cors: corsOrigins && corsOrigins.length > 0 ? { origins: corsOrigins } : false,
    circuitBreaker: {
      failureThreshold: envInt("AGENTGUARD_ADAPTER_FAILURE_THRESHOLD", 5),
      resetTimeoutMs: envInt("AGENTGUARD_ADAPTER_RESET_MS", 30_000),
      callTimeoutMs: envInt("AGENTGUARD_ADAPTER_TIMEOUT_MS", 15_000),
    },
    auditPublicKeys,
    logger: { level: env.LOG_LEVEL ?? "info" },
    shutdownGraceMs: envInt("AGENTGUARD_SHUTDOWN_GRACE_MS", 10_000),
  });

  if (signer) app.log.info({ keyId: signer.keyId }, "audit records are Ed25519-signed");
  else app.log.warn("audit record signing is DISABLED (hash chain only)");
  app.log.info({ apiKeyIds: apiKeys.map((k) => k.id) }, "api keys loaded");

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    app.log.info({ signal }, "shutting down; draining in-flight requests");
    const hardStop = setTimeout(() => process.exit(1), envInt("AGENTGUARD_SHUTDOWN_GRACE_MS", 10_000) + 5_000);
    hardStop.unref();
    await app.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));

  await app.listen({ port, host });
}

main().catch((err) => {
  // Startup errors are operator-facing; never include secrets in them.
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
