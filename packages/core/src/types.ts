// Shared contracts for AgentGuard. All packages import from here; never redefine.

export type Chain = "evm" | "solana";

export type Verdict = "allow" | "block" | "escalate";

/** What an agent proposes to do. Chain-specific payload lives in `raw`. */
export interface TransactionIntent {
  id: string;                 // client-generated UUID
  chain: Chain;
  chainId?: number | string;  // EVM chainId (1, 8453) or Solana cluster ("mainnet-beta")
  from: string;               // agent wallet address
  to?: string;                // EVM: target contract/EOA. Solana: primary program or recipient if known
  value?: bigint;             // native value in base units (wei / lamports)
  data?: `0x${string}`;       // EVM calldata
  raw?: string;               // Solana: base64 serialized (versioned) transaction
  description?: string;       // agent's stated purpose, free text
  metadata?: Record<string, unknown>;
}

export interface AssetDelta {
  asset: string;              // "native" | token mint/contract address
  symbol?: string;
  decimals: number;
  amount: bigint;             // signed: negative = outflow from `from`
  usdValue?: number;          // signed, best-effort
}

export interface ApprovalChange {
  token: string;
  spender: string;
  previous: bigint;
  next: bigint;               // 2^256-1 or u64::MAX => unlimited
  unlimited: boolean;
  /** Whether the spender has code (EVM) / is executable. `undefined` = unknown; `false` = EOA. */
  spenderIsContract?: boolean;
}

export interface SimulationResult {
  ok: boolean;                // simulation executed without revert
  revertReason?: string;
  deltas: AssetDelta[];       // net asset changes for `from`
  approvals: ApprovalChange[];
  contractsTouched: string[]; // addresses / program ids invoked
  /**
   * Addresses that receive assets from `from` as decoded by the adapter: ERC-20
   * transfer/transferFrom `to`, swap recipients, SPL transfer destinations (and their
   * owners when known), native transfer targets. Policy/behavior/reputation treat
   * these as counterparties alongside `to` and `contractsTouched`. Optional: older
   * adapters may omit it.
   */
  recipients?: string[];
  newContracts: string[];     // contracts/programs with no prior history (if known)
  gasEstimate?: bigint;
  warnings: string[];         // adapter-level heuristics, e.g. "selfdestruct opcode"
  rawTrace?: unknown;
}

export interface AgentContext {
  agentId: string;
  tenantId?: string;
  /** rolling spend already committed in the current window, USD */
  spentUsdInWindow?: number;
  windowSeconds?: number;
  /** trusted address lists supplied by the operator */
  allowlist?: string[];
  denylist?: string[];
  now?: Date;
}

export type RuleKind =
  | "max_tx_usd"
  | "max_window_usd"
  | "allowlist_only"
  | "denylist"
  | "no_unlimited_approvals"
  | "no_eoa_approvals"
  | "max_slippage_bps"
  | "no_new_contracts"
  | "require_simulation_ok"
  | "max_native_value"
  | "custom";

export interface PolicyRule {
  id: string;
  kind: RuleKind;
  /** verdict when the rule fires; default "block" */
  onViolation?: Exclude<Verdict, "allow">;
  params?: Record<string, unknown>;
  description?: string;
}

export interface PolicySet {
  id: string;
  version: number;
  rules: PolicyRule[];
}

export interface RuleFinding {
  ruleId: string;
  kind: RuleKind;
  verdict: Exclude<Verdict, "allow">;
  message: string;            // human-readable, safe to show operators
  evidence?: Record<string, unknown>;
}

export interface Decision {
  intentId: string;
  verdict: Verdict;
  findings: RuleFinding[];
  riskScore: number;          // 0..100
  explanation: string;        // one paragraph summarising why
  simulation?: SimulationResult;
  policyId: string;
  policyVersion: number;
  evaluatedAt: string;        // ISO timestamp
}

export interface ChainAdapter {
  readonly chain: Chain;
  /** Decode + simulate. Must not throw for ordinary reverts; set ok=false instead. */
  simulate(intent: TransactionIntent): Promise<SimulationResult>;
}

export interface AuditRecord {
  id: string;
  intent: TransactionIntent;
  decision: Decision;
  context: AgentContext;
  recordedAt: string;
  /** Who submitted the request (API key identity, correlation id). Optional for legacy records. */
  principal?: AuditPrincipal;
  /** Hash-chain + signature metadata. Absent on legacy/unsealed records. */
  integrity?: AuditIntegrity;
}

export interface CheckRequest {
  intent: TransactionIntent;
  context: AgentContext;
  policyId?: string;
}

export interface CheckResponse {
  decision: Decision;
  auditId: string;
}

// ---- Tamper-evident audit (additive; records without `integrity` are legacy/unsealed) ----

/** Hash-chain + optional signature metadata attached to every sealed audit record. */
export interface AuditIntegrity {
  /** 0-based position in the chain. */
  seq: number;
  /** `hash` of the previous record, or 64 zero hex chars for the genesis record. */
  prevHash: string;
  /** sha256 (hex) of the canonical JSON of the record body + `{seq, prevHash}`. */
  hash: string;
  /** Algorithm identifier, currently "sha256-v1". */
  alg: string;
  /** base64 Ed25519 signature over the hex `hash` (UTF-8), when signing is enabled. */
  signature?: string;
  /** Fingerprint (sha256 hex, truncated) of the signing public key. */
  keyId?: string;
}

/** Who submitted the request that produced an audit record. */
export interface AuditPrincipal {
  /** Identity of the API key (never the key itself). */
  apiKeyId?: string;
  /** Server-generated correlation id for the request. */
  requestId?: string;
  /** Whether the request carried a valid HMAC signature. */
  signed?: boolean;
}
