// Wiring for the real engine + adapters. These packages are built by separate
// workspaces and may be absent; everything is loaded dynamically so that this
// package typechecks on its own.
import { readFile } from "node:fs/promises";
import type { Chain, ChainAdapter, PolicySet } from "@agentguard/core";
import type { PolicyEngineLike } from "./types.js";

export interface BootstrapResult {
  engine: PolicyEngineLike;
  adapters: Partial<Record<Chain, ChainAdapter>>;
  policies: Map<string, PolicySet>;
  defaultPolicyId: string;
}

export interface BootstrapEnv {
  /** Path to a policy JSON file validated by `@agentguard/policy`'s `loadPolicy`; falls back to the conservative default. */
  policyPath?: string;
  evmRpcUrl?: string;
  solanaRpcUrl?: string;
  /**
   * Addresses / program ids the operator already trusts. When set, the adapters report
   * anything else they touch in `SimulationResult.newContracts`.
   */
  knownEvmContracts?: string[];
  knownSolanaPrograms?: string[];
  log?: { warn(msg: string): void; info(msg: string): void };
}

// Shapes of the modules we load dynamically. Kept structural so the API package
// never has a compile-time dependency on the adapters or their RPC libraries.
interface PolicyModule {
  PolicyEngine: new (opts?: Record<string, unknown>) => PolicyEngineLike;
  conservativeDefaultPolicy: PolicySet;
  loadPolicy: (json: unknown) => PolicySet;
}
interface EvmModule {
  EvmAdapter: new (opts: { client: unknown; knownContracts?: Set<string> }) => ChainAdapter;
}
interface ViemModule {
  createPublicClient: (opts: { transport: unknown }) => unknown;
  http: (url: string) => unknown;
}
interface SolanaModule {
  SolanaAdapter: new (opts: { connection: unknown; knownPrograms?: Set<string> }) => ChainAdapter;
}
interface Web3Module {
  Connection: new (url: string, commitment?: string) => unknown;
}

async function tryImport<T>(specifier: string): Promise<T | undefined> {
  try {
    // Indirection keeps TypeScript from resolving the module at typecheck time.
    const dynamicImport = new Function("s", "return import(s)") as (s: string) => Promise<T>;
    return await dynamicImport(specifier);
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === "ERR_MODULE_NOT_FOUND" || code === "MODULE_NOT_FOUND") return undefined;
    throw err;
  }
}

function missing(pkg: string, hint: string): never {
  throw new Error(
    `AgentGuard bootstrap: package '${pkg}' is not installed or not built. ${hint} ` +
      `(run \`npm run build\` from the repo root, or inject your own implementation via createServer()).`,
  );
}

export async function bootstrap(env: BootstrapEnv = {}): Promise<BootstrapResult> {
  const log = env.log ?? console;

  const policyMod = await tryImport<PolicyModule>("@agentguard/policy");
  if (!policyMod) missing("@agentguard/policy", "It provides the PolicyEngine required to evaluate checks.");

  const defaultPolicy = policyMod.conservativeDefaultPolicy;
  const policies = new Map<string, PolicySet>([[defaultPolicy.id, defaultPolicy]]);
  let defaultPolicyId = defaultPolicy.id;
  if (env.policyPath) {
    const loaded = policyMod.loadPolicy(await readFile(env.policyPath, "utf8"));
    policies.set(loaded.id, loaded);
    defaultPolicyId = loaded.id;
    log.info(`loaded policy '${loaded.id}' v${loaded.version} from ${env.policyPath}`);
  }

  const engine = new policyMod.PolicyEngine();

  const adapters: Partial<Record<Chain, ChainAdapter>> = {};

  if (env.evmRpcUrl) {
    const evm = await tryImport<EvmModule>("@agentguard/sim-evm");
    if (!evm) missing("@agentguard/sim-evm", "AGENTGUARD_EVM_RPC_URL is set but the EVM adapter is unavailable.");
    const viem = await tryImport<ViemModule>("viem");
    if (!viem) missing("viem", "It is required to build the EVM RPC client.");
    const client = viem.createPublicClient({ transport: viem.http(env.evmRpcUrl) });
    adapters.evm = new evm.EvmAdapter({
      client,
      knownContracts: env.knownEvmContracts ? new Set(env.knownEvmContracts) : undefined,
    });
  } else {
    log.warn("AGENTGUARD_EVM_RPC_URL not set: EVM checks disabled");
  }

  if (env.solanaRpcUrl) {
    const sol = await tryImport<SolanaModule>("@agentguard/sim-solana");
    if (!sol) missing("@agentguard/sim-solana", "AGENTGUARD_SOLANA_RPC_URL is set but the Solana adapter is unavailable.");
    const web3 = await tryImport<Web3Module>("@solana/web3.js");
    if (!web3) missing("@solana/web3.js", "It is required to build the Solana RPC connection.");
    const connection = new web3.Connection(env.solanaRpcUrl, "confirmed");
    adapters.solana = new sol.SolanaAdapter({
      connection,
      knownPrograms: env.knownSolanaPrograms ? new Set(env.knownSolanaPrograms) : undefined,
    });
  } else {
    log.warn("AGENTGUARD_SOLANA_RPC_URL not set: Solana checks disabled");
  }

  if (Object.keys(adapters).length === 0) {
    throw new Error("AgentGuard bootstrap: no chain adapters configured (set AGENTGUARD_EVM_RPC_URL and/or AGENTGUARD_SOLANA_RPC_URL)");
  }

  return { engine, adapters, policies, defaultPolicyId };
}
