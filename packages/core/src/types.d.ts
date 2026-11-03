export type Chain = "evm" | "solana";
export type Verdict = "allow" | "block" | "escalate";
/** What an agent proposes to do. Chain-specific payload lives in `raw`. */
export interface TransactionIntent {
    id: string;
    chain: Chain;
    chainId?: number | string;
    from: string;
    to?: string;
    value?: bigint;
    data?: `0x${string}`;
    raw?: string;
    description?: string;
    metadata?: Record<string, unknown>;
}
export interface AssetDelta {
    asset: string;
    symbol?: string;
    decimals: number;
    amount: bigint;
    usdValue?: number;
}
export interface ApprovalChange {
    token: string;
    spender: string;
    previous: bigint;
    next: bigint;
    unlimited: boolean;
}
export interface SimulationResult {
    ok: boolean;
    revertReason?: string;
    deltas: AssetDelta[];
    approvals: ApprovalChange[];
    contractsTouched: string[];
    newContracts: string[];
    gasEstimate?: bigint;
    warnings: string[];
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
export type RuleKind = "max_tx_usd" | "max_window_usd" | "allowlist_only" | "denylist" | "no_unlimited_approvals" | "max_slippage_bps" | "no_new_contracts" | "require_simulation_ok" | "max_native_value" | "custom";
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
    message: string;
    evidence?: Record<string, unknown>;
}
export interface Decision {
    intentId: string;
    verdict: Verdict;
    findings: RuleFinding[];
    riskScore: number;
    explanation: string;
    simulation?: SimulationResult;
    policyId: string;
    policyVersion: number;
    evaluatedAt: string;
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
