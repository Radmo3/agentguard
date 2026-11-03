import type {
  AgentContext,
  AuditRecord,
  Chain,
  ChainAdapter,
  Decision,
  PolicySet,
  SimulationResult,
  TransactionIntent,
} from "@agentguard/core";

/**
 * Input to the policy engine, mirroring ARCHITECTURE.md's request flow.
 * Structurally identical to `@agentguard/policy`'s `EvaluateInput` (policy is required:
 * the server always resolves a policy before calling the engine).
 */
export interface EvaluateInput {
  intent: TransactionIntent;
  simulation: SimulationResult;
  context: AgentContext;
  policy: PolicySet;
}

/**
 * Minimal structural interface for `@agentguard/policy`'s `PolicyEngine`.
 * Defined locally so the API does not import the policy package directly.
 */
export interface PolicyEngineLike {
  evaluate(input: EvaluateInput): Promise<Decision>;
}

export interface AuditListQuery {
  agentId?: string;
  limit: number;
  /** Opaque cursor returned by a previous call. */
  cursor?: string;
}

export interface AuditPage {
  items: AuditRecord[];
  nextCursor?: string;
}

export interface AuditStore {
  record(rec: AuditRecord): Promise<void>;
  get(id: string): Promise<AuditRecord | undefined>;
  /** Newest records first. */
  list(query: AuditListQuery): Promise<AuditPage>;
}

export interface ServerOptions {
  engine: PolicyEngineLike;
  adapters: Partial<Record<Chain, ChainAdapter>>;
  policies: Map<string, PolicySet>;
  audit: AuditStore;
  /** Policy used when a request carries no `policyId`. Defaults to the first entry in `policies`. */
  defaultPolicyId?: string;
  /** Accepted `x-api-key` values. Empty/undefined disables auth (a warning is logged). */
  apiKeys?: string[];
  /** Optional rate limiting; omitted = disabled. */
  rateLimit?: { max: number; timeWindowMs: number };
  /** Fastify logger option. */
  logger?: boolean | object;
}
