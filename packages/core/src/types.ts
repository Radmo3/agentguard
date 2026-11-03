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
}

export interface SimulationResult {
  ok: boolean;                // simulation executed without revert
  revertReason?: string;
  deltas: AssetDelta[];       // net asset changes for `from`
  approvals: ApprovalChange[];
  contractsTouched: string[]; // addresses / program ids invoked
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
