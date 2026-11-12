import type { ApprovalStatus, Decision } from "@agentguard/core";

export class AgentGuardClientError extends Error {
  constructor(message: string, public readonly code: string, public readonly cause?: unknown) {
    super(message);
    this.name = "AgentGuardClientError";
  }
}

/** Server replied with a non-2xx status. */
export class AgentGuardHttpError extends AgentGuardClientError {
  constructor(
    public readonly status: number,
    public readonly body: unknown,
    message = `AgentGuard API responded with HTTP ${status}`,
  ) {
    super(
      message,
      status === 401 ? "unauthorized"
      : status === 400 ? "bad_request"
      : status === 413 ? "payload_too_large"
      : status === 429 ? "rate_limited"
      : status >= 500 ? "server_error"
      : "http_error",
    );
    this.name = "AgentGuardHttpError";
  }
}

/** Request timed out or could not reach the server after all retries. */
export class AgentGuardNetworkError extends AgentGuardClientError {
  constructor(message: string, cause?: unknown) {
    super(message, "network_error", cause);
    this.name = "AgentGuardNetworkError";
  }
}

export class AgentGuardTimeoutError extends AgentGuardNetworkError {
  constructor(timeoutMs: number) {
    super(`AgentGuard request timed out after ${timeoutMs}ms`);
    this.name = "AgentGuardTimeoutError";
    (this as { code: string }).code = "timeout";
  }
}

/** Server replied 2xx but the body is not a well-formed AgentGuard response. Treated as a failed check. */
export class AgentGuardProtocolError extends AgentGuardClientError {
  constructor(message: string) {
    super(message, "protocol_error");
    this.name = "AgentGuardProtocolError";
  }
}

/** Thrown by `guard()` when the policy decision is `block`. */
export class GuardBlockedError extends AgentGuardClientError {
  constructor(public readonly decision: Decision, public readonly auditId: string) {
    super(`Transaction ${decision.intentId} blocked by AgentGuard: ${decision.explanation}`, "blocked");
    this.name = "GuardBlockedError";
  }
}

/**
 * Thrown by `guard()` when the decision is `escalate` and no server-verified
 * approval was obtained. Carries what a human needs to approve it out of band:
 * `auditId` (to look the decision up) and `challenge` (what a registered approver
 * device signs). The agent process cannot act on either.
 */
export class GuardEscalatedError extends AgentGuardClientError {
  readonly challenge: string | undefined;
  readonly approvalExpiresAt: string | undefined;
  constructor(
    public readonly decision: Decision,
    public readonly auditId: string,
    approval?: { challenge: string; expiresAt: string },
    detail?: string,
  ) {
    super(`Transaction ${decision.intentId} requires human approval${detail ? ` (${detail})` : ""}: ${decision.explanation}`, "escalated");
    this.name = "GuardEscalatedError";
    this.challenge = approval?.challenge;
    this.approvalExpiresAt = approval?.expiresAt;
  }
}

/** `waitForApproval` gave up before the server reported `approved`. The transaction must not proceed. */
export class ApprovalTimeoutError extends AgentGuardClientError {
  constructor(public readonly auditId: string, public readonly timeoutMs: number, public readonly lastStatus: ApprovalStatus | undefined) {
    super(`approval for audit ${auditId} not granted within ${timeoutMs}ms (last status: ${lastStatus ?? "none"})`, "approval_timeout");
    this.name = "ApprovalTimeoutError";
  }
}

/** The server reported a terminal non-approved status (`expired`, `rejected`, `unknown`). A fresh check is required. */
export class ApprovalDeniedError extends AgentGuardClientError {
  constructor(public readonly auditId: string, public readonly status: ApprovalStatus) {
    super(`approval for audit ${auditId} is ${status}; a new check is required`, "approval_denied");
    this.name = "ApprovalDeniedError";
  }
}
