// Human approval challenge (I-HITL, arXiv:2610.35835).
//
// An `escalate` decision is approvable only by a signature from a registered
// approver key over a single value, the challenge, that commits to everything the
// human is approving: the audit record, the exact intent, the decision (minus the
// raw simulation trace, which is bulky and implementation-defined), the policy,
// the agent and the issue time. The challenge is computed server-side and stored
// with the audit record; the agent process can neither forge a challenge for a
// different intent nor produce a signature, because it never holds an approver key.
import { canonicalJson, sha256Hex } from "./canonical.js";
import type { Decision, TransactionIntent } from "./types.js";

export const APPROVAL_CHALLENGE_VERSION = 1 as const;

export interface ApprovalChallengeInput {
  auditId: string;
  intent: TransactionIntent;
  decision: Decision;
  policyId: string;
  policyVersion: number;
  agentId: string;
  /** ISO timestamp at which the server issued the challenge. */
  issuedAt: string;
}

/** `decision` with `simulation.rawTrace` dropped (it is not part of what a human approves). */
export function decisionForChallenge(decision: Decision): Decision {
  if (!decision.simulation) return decision;
  const { rawTrace: _drop, ...simulation } = decision.simulation;
  return { ...decision, simulation };
}

/** sha256(canonicalJson(intent)) */
export function intentHash(intent: TransactionIntent): string {
  return sha256Hex(canonicalJson(intent));
}

/** sha256(canonicalJson(decision minus simulation.rawTrace)) */
export function decisionHash(decision: Decision): string {
  return sha256Hex(canonicalJson(decisionForChallenge(decision)));
}

/**
 * challenge = sha256(canonicalJson({ v, auditId, intentHash, decisionHash, policyId, policyVersion, agentId, issuedAt }))
 *
 * Deterministic: anyone holding the sealed check record can recompute it and
 * confirm that the value a device is asked to sign is bound to that record.
 */
export function computeApprovalChallenge(input: ApprovalChallengeInput): string {
  return sha256Hex(
    canonicalJson({
      v: APPROVAL_CHALLENGE_VERSION,
      auditId: input.auditId,
      intentHash: intentHash(input.intent),
      decisionHash: decisionHash(input.decision),
      policyId: input.policyId,
      policyVersion: input.policyVersion,
      agentId: input.agentId,
      issuedAt: input.issuedAt,
    }),
  );
}

/** The exact bytes an approver device signs: the hex challenge as UTF-8. */
export function approvalMessageBytes(challenge: string): Uint8Array {
  return new TextEncoder().encode(challenge);
}

export const CHALLENGE_RE = /^[0-9a-f]{64}$/;
