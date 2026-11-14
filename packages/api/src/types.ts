import type {
  AgentContext,
  AuditIntegrity,
  AuditRecord,
  Chain,
  ChainAdapter,
  Decision,
  PolicySet,
  SimulationResult,
  TransactionIntent,
} from "@signhold/core";
import type { KeyObject } from "node:crypto";
import type { ApproverKeyConfig } from "./approvals.js";
import type { ApiKeyConfig } from "./auth.js";
import type { CircuitBreakerOptions } from "./breaker.js";

/**
 * Input to the policy engine, mirroring ARCHITECTURE.md's request flow.
 * Structurally identical to `@signhold/policy`'s `EvaluateInput` (policy is required:
 * the server always resolves a policy before calling the engine).
 */
export interface EvaluateInput {
  intent: TransactionIntent;
  simulation: SimulationResult;
  context: AgentContext;
  policy: PolicySet;
}

/**
 * Minimal structural interface for `@signhold/policy`'s `PolicyEngine`.
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
  /** Seals (hash-chains, optionally signs) and persists; resolves with the sealed record. */
  record(rec: AuditRecord): Promise<AuditRecord>;
  get(id: string): Promise<AuditRecord | undefined>;
  /** Newest records first. */
  list(query: AuditListQuery): Promise<AuditPage>;
  /** Records with `integrity.seq` in [fromSeq, toSeq], in chain order. */
  range(fromSeq: number, toSeq: number): Promise<AuditRecord[]>;
  /** Integrity envelope of the latest record, if any. */
  headIntegrity(): Promise<AuditIntegrity | undefined>;
}

export interface RequestSigningOptions {
  /** Reject unsigned requests on mutating routes. Default false (signatures verified when present). */
  required?: boolean;
  /** Accepted clock skew / replay window. Default 5 minutes. */
  windowMs?: number;
  /** Max nonces retained for replay detection. Default 100k. */
  nonceCacheSize?: number;
}

/**
 * Structural interface for a behavioral profile store (the optional, separately
 * licensed `@signhold/behavior` package ships one; any object with this shape works).
 * Only `get` is needed by the server (to warm the synchronous `peek` the policy rule
 * reads); the integration's `persist` receives the whole object.
 */
export interface BehaviorStoreLike {
  get(agentId: string): Promise<unknown>;
  peek?(agentId: string): unknown;
}

/**
 * Behavioral anomaly layer, injected and duck-typed so the API never imports the
 * package that implements it. The server awaits `store.get(agentId)` before
 * `engine.evaluate` (a failure escalates, never allows) and awaits `persist` after the
 * audit record is sealed, logging (never propagating) failures.
 */
export interface BehaviorIntegration {
  /** Profile store; `get(agentId)` is awaited before `engine.evaluate` to warm `peek`. */
  store: BehaviorStoreLike;
  /** Fold the decision into the agent's baseline. Failure must not change the verdict. */
  persist: (agentId: string, intent: TransactionIntent, simulation: SimulationResult, decision: Decision, opts: { at?: Date }) => Promise<unknown>;
}

/**
 * Synchronous custom rule, structurally identical to `@signhold/policy`'s
 * `CustomRuleFn`. Declared loosely here because the API only forwards it to the engine.
 */
export type CustomRuleLike = (input: unknown) => unknown;

/**
 * Contract a behavior package must satisfy for `bootstrap` to load it dynamically:
 * a single factory export, `createBehaviorIntegration(options)`, returning the store,
 * the synchronous `behavior` custom rule and the `persist` hook.
 */
export interface BehaviorModuleLike {
  createBehaviorIntegration(options: BehaviorIntegrationOptions): BehaviorIntegration & { rule: CustomRuleLike };
}

export interface BehaviorIntegrationOptions {
  /** JSONL file for profiles; undefined => in-memory (lost on restart). */
  profilePath?: string;
}

/** Structural subset of `@signhold/reputation`'s `ReputationService`. */
export interface ReputationServiceLike {
  /** Warm the cache for every address the reputation rule will consult. Awaited before `engine.evaluate`. */
  prefetch(intent: TransactionIntent, simulation?: SimulationResult): Promise<unknown>;
}

export interface ServerOptions {
  engine: PolicyEngineLike;
  adapters: Partial<Record<Chain, ChainAdapter>>;
  policies: Map<string, PolicySet>;
  audit: AuditStore;
  /** Behavioral anomaly layer (see `BehaviorIntegration`). Optional; the policy's `behavior` custom rule must be registered on the engine. */
  behavior?: BehaviorIntegration;
  /** Contract reputation service (see `ReputationServiceLike`). Optional; the policy's `reputation` custom rule must be registered on the engine. */
  reputation?: ReputationServiceLike;
  /** Policy used when a request carries no `policyId`. Defaults to the first entry in `policies`. */
  defaultPolicyId?: string;
  /**
   * Accepted API keys: raw strings (id derived from fingerprint) or `{ id, key }`.
   * Keys are hashed on construction and never retained. Empty disables auth,
   * which is refused when `env` is "production".
   */
  apiKeys?: ReadonlyArray<string | ApiKeyConfig>;
  /** Deployment environment; defaults to process.env.NODE_ENV. "production" enforces hardening. */
  env?: string;
  /** HMAC request signing (`x-signhold-signature`). */
  signing?: RequestSigningOptions;
  /**
   * Rate limiting, per API key (falls back to client IP when unauthenticated).
   * ON by default (120 req / 60 s). Pass `false` to disable.
   */
  rateLimit?: { max: number; timeWindowMs: number } | false;
  /** Max accepted request body in bytes. Default 64 KiB. */
  bodyLimit?: number;
  /** Fastify `trustProxy`. Default false. */
  trustProxy?: boolean | string | string[] | number;
  /** CORS allowed origins. Default: CORS disabled (no headers emitted). */
  cors?: { origins: string[] } | false;
  /** Circuit breaker applied to every adapter. Pass `false` to disable. */
  circuitBreaker?: CircuitBreakerOptions | false;
  /** Public keys (by keyId) used by GET /v1/audit/verify to check signatures. */
  auditPublicKeys?: ReadonlyMap<string, KeyObject>;
  /**
   * Registered human-approver public keys (Ed25519). An `escalate` decision can
   * only be turned into an approval by a signature from one of these keys,
   * verified server-side (`POST /v1/approvals`). They are separate from API keys
   * (transport auth) and from the audit signing key (server-held); registering a
   * server-held key here is refused. Empty => escalations carry no challenge and
   * cannot be approved through the API.
   */
  approvers?: ReadonlyArray<ApproverKeyConfig>;
  /** Approval window and bookkeeping. */
  approvals?: {
    /** How long an issued challenge stays approvable. Default 15 minutes. */
    ttlMs?: number;
    /** Tolerated difference between the device's `approvedAt` and the server clock. Default 60 s. */
    clockSkewMs?: number;
    /** Upper bound on pending approvals held in memory. Default 10k. */
    maxPending?: number;
    /** Clock (tests). */
    now?: () => number;
  };
  /** Pino logger options (`{ level, stream }`), `false` to silence. Defaults to info level. */
  logger?: boolean | { level?: string; stream?: { write(s: string): unknown }; redactKeys?: readonly string[] };
  /** Grace period for in-flight requests on close. Default 10 s. */
  shutdownGraceMs?: number;
}
