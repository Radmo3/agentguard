export { AgentGuardClient } from "./client.js";
export type { AgentGuardClientOptions, AuditPage, CheckOptions, FetchLike } from "./client.js";
export { guard } from "./guard.js";
export type { EscalationInfo, GuardOptions, Guarded, IntentInput, SignerLike } from "./guard.js";
export * from "./errors.js";
export * from "./serialization.js";
export type {
  AgentContext,
  AuditRecord,
  CheckRequest,
  CheckResponse,
  Decision,
  TransactionIntent,
  Verdict,
} from "@agentguard/core";
