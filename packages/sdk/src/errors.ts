import type { ApprovalStatus, Decision } from "@signhold/core";

export class SignholdClientError extends Error {
  constructor(message: string, public readonly code: string, public readonly cause?: unknown) {
    super(message);
    this.name = "SignholdClientError";
  }
}

/** Server replied with a non-2xx status. */
export class SignholdHttpError extends SignholdClientError {
  constructor(
    public readonly status: number,
    public readonly body: unknown,
    message = `Signhold API responded with HTTP ${status}`,
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
    this.name = "SignholdHttpError";
  }
}

/** Request timed out or could not reach the server after all retries. */
export class SignholdNetworkError extends SignholdClientError {
  constructor(message: string, cause?: unknown) {
    super(message, "network_error", cause);
    this.name = "SignholdNetworkError";
  }
}

export class SignholdTimeoutError extends SignholdNetworkError {
  constructor(timeoutMs: number) {
    super(`Signhold request timed out after ${timeoutMs}ms`);
    this.name = "SignholdTimeoutError";
    (this as { code: string }).code = "timeout";
  }
}

/** Server replied 2xx but the body is not a well-formed Signhold response. Treated as a failed check. */
export class SignholdProtocolError extends SignholdClientError {
  constructor(message: string) {
    super(message, "protocol_error");
    this.name = "SignholdProtocolError";
  }
}

/** Thrown by `guard()` when the policy decision is `block`. */
export class GuardBlockedError extends SignholdClientError {
  constructor(public readonly decision: Decision, public readonly auditId: string) {
    super(`Transaction ${decision.intentId} blocked by Signhold: ${decision.explanation}`, "blocked");
    this.name = "GuardBlockedError";
  }
}

/**
 * Thrown by `guard()` when the decision is `escalate` and no server-verified
 * approval was obtained. Carries what a human needs to approve it out of band:
 * `auditId` (to look the decision up) and `challenge` (what a registered approver
 * device signs). The agent process cannot act on either.
 */
export class GuardEscalatedError extends SignholdClientError {
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
export class ApprovalTimeoutError extends SignholdClientError {
  constructor(public readonly auditId: string, public readonly timeoutMs: number, public readonly lastStatus: ApprovalStatus | undefined) {
    super(`approval for audit ${auditId} not granted within ${timeoutMs}ms (last status: ${lastStatus ?? "none"})`, "approval_timeout");
    this.name = "ApprovalTimeoutError";
  }
}

/** The server reported a terminal non-approved status (`expired`, `rejected`, `unknown`). A fresh check is required. */
export class ApprovalDeniedError extends SignholdClientError {
  constructor(public readonly auditId: string, public readonly status: ApprovalStatus) {
    super(`approval for audit ${auditId} is ${status}; a new check is required`, "approval_denied");
    this.name = "ApprovalDeniedError";
  }
}
