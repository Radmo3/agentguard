// Wiring for the real engine + adapters. These packages are built by separate
// workspaces and may be absent; everything is loaded dynamically so that this
// package typechecks on its own.
import { readFile } from "node:fs/promises";
import type { Chain, ChainAdapter, PolicyRule, PolicySet } from "@signhold/core";
import type { BehaviorIntegration, BehaviorModuleLike, CustomRuleLike, PolicyEngineLike, ReputationServiceLike } from "./types.js";

export interface BootstrapResult {
  engine: PolicyEngineLike;
  adapters: Partial<Record<Chain, ChainAdapter>>;
  policies: Map<string, PolicySet>;
  defaultPolicyId: string;
  /** Present when a behavior package (`@signhold/behavior`, separately licensed) is installed. */
  behavior?: BehaviorIntegration;
  /** Present when `@signhold/reputation` is installed. */
  reputation?: ReputationServiceLike;
}

export interface BootstrapEnv {
  /** Path to a policy JSON file validated by `@signhold/policy`'s `loadPolicy`; falls back to the conservative default. */
  policyPath?: string;
  evmRpcUrl?: string;
  solanaRpcUrl?: string;
  /**
   * Addresses / program ids the operator already trusts. When set, the adapters report
   * anything else they touch in `SimulationResult.newContracts`.
   */
  knownEvmContracts?: string[];
  knownSolanaPrograms?: string[];
  /**
   * JSONL file for behavioral profiles (`@signhold/behavior`, an optional package that
   * is not part of this repository). Unset => in-memory profiles (lost on restart).
   * Set to `false` to disable the behavior layer entirely.
   */
  profilePath?: string | false;
  /**
   * Module specifier of the behavior package to load. Defaults to `@signhold/behavior`.
   * The module must export `createBehaviorIntegration` (see `BehaviorModuleLike`).
   */
  behaviorModule?: string;
  /** Allow/deny list files for `@signhold/reputation`'s StaticListProvider. */
  reputationAllowlistFiles?: string[];
  reputationDenylistFiles?: string[];
  /**
   * Optional external intel endpoint. `{address}`, `{chain}` and `{chainId}` in the URL
   * are substituted; the response must be JSON `{ verdict, score?, tags? }`.
   */
  reputationHttpUrl?: string;
  /** Set to `false` to disable the reputation layer entirely. */
  reputation?: boolean;
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
interface ReputationModule {
  ReputationService: new (opts: { providers: unknown[]; failMode?: "closed" | "open" }) => ReputationServiceLike & { providers: readonly { name: string }[] };
  StaticListProvider: { fromFiles(opts: { allowFiles?: string[]; denyFiles?: string[]; includeSeed?: boolean; name?: string }): unknown };
  HttpProvider: new (opts: Record<string, unknown>) => unknown;
  createReputationRule: (service: unknown, opts?: Record<string, unknown>) => CustomRuleLike;
}

/** Default module specifier of the (optional, separately licensed) behavior package. */
export const BEHAVIOR_PACKAGE = "@signhold/behavior";

/** Rules appended to the default policy when the corresponding layer is active. */
export const BEHAVIOR_RULE: PolicyRule = {
  id: "behavior",
  kind: "custom",
  onViolation: "escalate",
  params: { fn: "behavior" },
  description: "Escalate (>=50) or block (>=85) transactions that are out of character for this agent's learned baseline.",
};
export const REPUTATION_RULE: PolicyRule = {
  id: "reputation",
  kind: "custom",
  onViolation: "escalate",
  params: { fn: "reputation" },
  description: "Block denylisted/malicious counterparties; escalate suspicious ones or reputation-provider outages.",
};

/** Copy of a policy with the given rules appended (ids must not already exist). */
export function withCustomRules(policy: PolicySet, rules: PolicyRule[]): PolicySet {
  const seen = new Set(policy.rules.map((r) => r.id));
  const added: PolicyRule[] = [];
  for (const r of rules) {
    if (seen.has(r.id)) continue;
    seen.add(r.id);
    added.push(r);
  }
  return { ...policy, rules: [...policy.rules, ...added] };
}

/** Map `{address}` / `{chain}` / `{chainId}` placeholders into a URL, percent-encoded. */
export function buildReputationUrl(template: string, chain: string, address: string, chainId?: number | string): string {
  return template
    .replace(/\{address\}/g, encodeURIComponent(address))
    .replace(/\{chain\}/g, encodeURIComponent(chain))
    .replace(/\{chainId\}/g, encodeURIComponent(chainId === undefined ? "" : String(chainId)));
}

async function tryImport<T>(specifier: string): Promise<T | undefined> {
  try {
    // A computed specifier keeps TypeScript from resolving the module at typecheck
    // time (this package has no compile-time dependency on the optional packages),
    // while remaining a real `import()` that bundlers, vitest and node all honour.
    const name: string = specifier;
    return (await import(name)) as T;
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === "ERR_MODULE_NOT_FOUND" || code === "MODULE_NOT_FOUND") return undefined;
    throw err;
  }
}

function missing(pkg: string, hint: string): never {
  throw new Error(
    `Signhold bootstrap: package '${pkg}' is not installed or not built. ${hint} ` +
      `(run \`npm run build\` from the repo root, or inject your own implementation via createServer()).`,
  );
}

export async function bootstrap(env: BootstrapEnv = {}): Promise<BootstrapResult> {
  const log = env.log ?? console;

  const policyMod = await tryImport<PolicyModule>("@signhold/policy");
  if (!policyMod) missing("@signhold/policy", "It provides the PolicyEngine required to evaluate checks.");

  // ---- Behavioral anomaly layer (optional, separately licensed package) ----
  // Loaded by name so this repository never depends on it. The package must export
  // `createBehaviorIntegration(options)` (see `BehaviorModuleLike` in types.ts). When it
  // is absent the layer is simply off: no `behavior` rule is added to the default
  // policy, so a policy that references it would escalate with `engine_error`.
  const customRules: Record<string, CustomRuleLike> = {};
  const extraRules: PolicyRule[] = [];
  let behavior: BehaviorIntegration | undefined;
  if (env.profilePath !== false) {
    const specifier = env.behaviorModule ?? BEHAVIOR_PACKAGE;
    const beh = await tryImport<Partial<BehaviorModuleLike>>(specifier);
    if (!beh) {
      log.warn(`${specifier} not installed: behavioral anomaly detection disabled`);
    } else if (typeof beh.createBehaviorIntegration !== "function") {
      throw new Error(`Signhold bootstrap: '${specifier}' does not export createBehaviorIntegration(); refusing to start with a half-wired behavior layer`);
    } else {
      const integration = beh.createBehaviorIntegration({ profilePath: env.profilePath || undefined });
      if (!integration || typeof integration.rule !== "function" || !integration.store || typeof integration.store.get !== "function" || typeof integration.persist !== "function") {
        throw new Error(`Signhold bootstrap: '${specifier}' returned an invalid behavior integration (expected { store, rule, persist })`);
      }
      customRules.behavior = integration.rule;
      extraRules.push(BEHAVIOR_RULE);
      behavior = { store: integration.store, persist: integration.persist };
      log.info(env.profilePath ? `behavior profiles persisted to ${env.profilePath}` : "behavior profiles are in-memory (set SIGNHOLD_PROFILE_FILE to persist)");
    }
  }

  // ---- Contract reputation layer (optional package) ----
  let reputation: ReputationServiceLike | undefined;
  if (env.reputation !== false) {
    const rep = await tryImport<ReputationModule>("@signhold/reputation");
    if (!rep) {
      log.warn("@signhold/reputation not installed: contract reputation checks disabled");
    } else {
      const providers: unknown[] = [
        rep.StaticListProvider.fromFiles({
          allowFiles: env.reputationAllowlistFiles ?? [],
          denyFiles: env.reputationDenylistFiles ?? [],
        }),
      ];
      if (env.reputationHttpUrl) {
        const template = env.reputationHttpUrl;
        if (!/^https?:\/\//.test(template)) throw new Error("SIGNHOLD_REPUTATION_HTTP_URL must be an http(s) URL");
        providers.push(
          new rep.HttpProvider({
            name: "http-intel",
            buildRequest: (chain: string, address: string, chainId?: number | string) => ({ url: buildReputationUrl(template, chain, address, chainId) }),
            mapResponse: (json: unknown) => {
              const j = json as { verdict?: unknown; score?: unknown; tags?: unknown };
              if (!j || typeof j !== "object" || typeof j.verdict !== "string") return null;
              return { verdict: j.verdict, score: typeof j.score === "number" ? j.score : undefined, tags: Array.isArray(j.tags) ? j.tags : undefined };
            },
          }),
        );
      }
      const service = new rep.ReputationService({ providers, failMode: "closed" });
      customRules.reputation = rep.createReputationRule(service, { onCacheMiss: "escalate" });
      extraRules.push(REPUTATION_RULE);
      reputation = service;
      log.info(`reputation providers: ${service.providers.map((p) => p.name).join(", ")}`);
    }
  }

  // The default policy gains the behavior/reputation rules when those layers are
  // active. A policy loaded from disk is used verbatim: operators opt in by adding
  // `{ kind: "custom", params: { fn: "behavior" | "reputation" } }` themselves.
  const defaultPolicy = withCustomRules(policyMod.conservativeDefaultPolicy, extraRules);
  const policies = new Map<string, PolicySet>([[defaultPolicy.id, defaultPolicy]]);
  let defaultPolicyId = defaultPolicy.id;
  if (env.policyPath) {
    const loaded = policyMod.loadPolicy(await readFile(env.policyPath, "utf8"));
    policies.set(loaded.id, loaded);
    defaultPolicyId = loaded.id;
    log.info(`loaded policy '${loaded.id}' v${loaded.version} from ${env.policyPath}`);
    const uses = new Set(loaded.rules.filter((r) => r.kind === "custom").map((r) => String(r.params?.fn)));
    for (const name of Object.keys(customRules)) {
      if (!uses.has(name)) log.warn(`policy '${loaded.id}' does not reference custom rule '${name}'; that layer will not affect verdicts under it`);
    }
  }

  const engine = new policyMod.PolicyEngine({ customRules });

  const adapters: Partial<Record<Chain, ChainAdapter>> = {};

  if (env.evmRpcUrl) {
    const evm = await tryImport<EvmModule>("@signhold/sim-evm");
    if (!evm) missing("@signhold/sim-evm", "SIGNHOLD_EVM_RPC_URL is set but the EVM adapter is unavailable.");
    const viem = await tryImport<ViemModule>("viem");
    if (!viem) missing("viem", "It is required to build the EVM RPC client.");
    const client = viem.createPublicClient({ transport: viem.http(env.evmRpcUrl) });
    adapters.evm = new evm.EvmAdapter({
      client,
      knownContracts: env.knownEvmContracts ? new Set(env.knownEvmContracts) : undefined,
    });
  } else {
    log.warn("SIGNHOLD_EVM_RPC_URL not set: EVM checks disabled");
  }

  if (env.solanaRpcUrl) {
    const sol = await tryImport<SolanaModule>("@signhold/sim-solana");
    if (!sol) missing("@signhold/sim-solana", "SIGNHOLD_SOLANA_RPC_URL is set but the Solana adapter is unavailable.");
    const web3 = await tryImport<Web3Module>("@solana/web3.js");
    if (!web3) missing("@solana/web3.js", "It is required to build the Solana RPC connection.");
    const connection = new web3.Connection(env.solanaRpcUrl, "confirmed");
    adapters.solana = new sol.SolanaAdapter({
      connection,
      knownPrograms: env.knownSolanaPrograms ? new Set(env.knownSolanaPrograms) : undefined,
    });
  } else {
    log.warn("SIGNHOLD_SOLANA_RPC_URL not set: Solana checks disabled");
  }

  if (Object.keys(adapters).length === 0) {
    throw new Error("Signhold bootstrap: no chain adapters configured (set SIGNHOLD_EVM_RPC_URL and/or SIGNHOLD_SOLANA_RPC_URL)");
  }

  return { engine, adapters, policies, defaultPolicyId, behavior, reputation };
}
