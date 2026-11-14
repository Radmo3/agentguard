/**
 * Server-side human approval of escalated transactions (I-HITL, arXiv:2610.35835).
 *
 * Trust model in one paragraph: the agent process holds an API key and nothing
 * else. Approver keys are Ed25519 key pairs whose private half lives on a device
 * the agent cannot reach (phone, HSM, hardware key, or the `approve.ts` CLI on an
 * operator laptop). The server issues a challenge bound to the sealed audit
 * record of an `escalate` decision, the device signs that challenge, and the
 * server verifies the signature against its registry of approver public keys.
 * Nothing the agent can send turns `escalate` into `allow`: a valid signature
 * from a registered key is the only path, and it is single-use and time-boxed.
 */
import { generateKeyPairSync, randomUUID, timingSafeEqual, verify as edVerify, type KeyObject } from "node:crypto";
import type { ApprovalAuditData, ApprovalStatus, AuditRecord } from "@signhold/core";
import { CHALLENGE_RE, approvalMessageBytes, computeApprovalChallenge } from "@signhold/core";
import { keyIdOf, loadEd25519PublicKey } from "./integrity.js";

export const APPROVER_KEY_ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;
export const DEFAULT_APPROVAL_TTL_MS = 15 * 60_000;
export const DEFAULT_APPROVAL_CLOCK_SKEW_MS = 60_000;
export const DEFAULT_MAX_PENDING_APPROVALS = 10_000;

export interface ApproverKeyConfig {
  /** Stable identity recorded in audit records. Never secret. */
  keyId: string;
  /** Ed25519 public key: 32 raw bytes as base64 or hex, or SPKI PEM. */
  publicKey: string | KeyObject;
}

/**
 * Parse `SIGNHOLD_APPROVER_KEYS`: comma-separated `id:base64pub` entries
 * (hex and PEM-less SPKI base64 are accepted as well). Malformed entries abort
 * startup: an approval registry that silently drops a key is worse than none.
 */
export function parseApproverKeysEnv(raw: string | undefined): ApproverKeyConfig[] {
  if (!raw || !raw.trim()) return [];
  const out: ApproverKeyConfig[] = [];
  for (const entry of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    const idx = entry.indexOf(":");
    if (idx <= 0 || idx === entry.length - 1) throw new Error(`SIGNHOLD_APPROVER_KEYS: entry must be '<keyId>:<base64 public key>'`);
    const keyId = entry.slice(0, idx);
    if (!APPROVER_KEY_ID_RE.test(keyId)) throw new Error(`SIGNHOLD_APPROVER_KEYS: invalid key id '${keyId}' (must match ${APPROVER_KEY_ID_RE})`);
    out.push({ keyId, publicKey: entry.slice(idx + 1) });
  }
  return out;
}

/**
 * Registry of approver public keys. Verification always performs exactly one
 * Ed25519 verify, against a throwaway key when `keyId` is unknown, so the
 * response time does not reveal which key ids are registered.
 */
export class ApproverRegistry {
  private readonly keys = new Map<string, KeyObject>();
  private readonly decoy: KeyObject;

  constructor(configs: ReadonlyArray<ApproverKeyConfig>, opts: { forbiddenKeyIds?: Iterable<string> } = {}) {
    const forbidden = new Set(opts.forbiddenKeyIds ?? []);
    for (const c of configs) {
      if (!APPROVER_KEY_ID_RE.test(c.keyId)) throw new Error(`invalid approver key id '${c.keyId}'`);
      if (this.keys.has(c.keyId)) throw new Error(`duplicate approver key id '${c.keyId}'`);
      const pk = typeof c.publicKey === "string" ? loadEd25519PublicKey(c.publicKey) : c.publicKey;
      if (pk.asymmetricKeyType !== "ed25519") throw new Error(`approver key '${c.keyId}' is not Ed25519`);
      // Key separation: an approver key must never be the audit signing key (or any
      // other key the server itself holds), otherwise the service could mint approvals.
      if (forbidden.has(keyIdOf(pk))) throw new Error(`approver key '${c.keyId}' is also a server-held key; approver keys must be separate`);
      for (const [otherId, other] of this.keys) {
        if (keyIdOf(other) === keyIdOf(pk)) throw new Error(`approver keys '${otherId}' and '${c.keyId}' are the same key`);
      }
      this.keys.set(c.keyId, pk);
    }
    this.decoy = generateKeyPairSync("ed25519").publicKey;
  }

  get size(): number {
    return this.keys.size;
  }

  get ids(): string[] {
    return [...this.keys.keys()];
  }

  has(keyId: string): boolean {
    return this.keys.has(keyId);
  }

  /**
   * True only when `keyId` is registered AND `signatureB64` is a valid Ed25519
   * signature by that key over the UTF-8 bytes of `challenge`. Never throws.
   */
  verify(keyId: string, challenge: string, signatureB64: string): boolean {
    const registered = this.keys.get(keyId);
    const pk = registered ?? this.decoy;
    let sig: Buffer;
    try {
      sig = Buffer.from(signatureB64, "base64");
    } catch {
      sig = Buffer.alloc(64);
    }
    if (sig.length !== 64) sig = Buffer.alloc(64);
    let ok = false;
    try {
      ok = edVerify(null, approvalMessageBytes(challenge), pk, sig);
    } catch {
      ok = false;
    }
    // Both conditions are combined without short-circuit so timing does not depend on registration.
    const isRegistered = registered !== undefined;
    return ok && isRegistered;
  }
}

export interface PendingApproval {
  auditId: string;
  challenge: string;
  issuedAt: string;
  expiresAt: string;
  agentId: string;
  status: "pending" | "approved" | "rejected";
  used: boolean;
  approvedBy?: string;
  approvedAt?: string;
  approvalId?: string;
}

export interface PendingApprovalStoreOptions {
  ttlMs?: number;
  maxPending?: number;
  now?: () => number;
}

/**
 * In-memory, bounded store of pending approvals keyed by audit id. Restarting
 * the server forgets every pending approval; their status becomes `unknown` and
 * a fresh check is required (fail closed, documented in SECURITY.md).
 */
export class PendingApprovalStore {
  private readonly items = new Map<string, PendingApproval>();
  readonly ttlMs: number;
  private readonly maxPending: number;
  private readonly now: () => number;

  constructor(opts: PendingApprovalStoreOptions = {}) {
    this.ttlMs = opts.ttlMs ?? DEFAULT_APPROVAL_TTL_MS;
    if (!Number.isFinite(this.ttlMs) || this.ttlMs <= 0) throw new Error("approval ttlMs must be a positive number");
    this.maxPending = opts.maxPending ?? DEFAULT_MAX_PENDING_APPROVALS;
    this.now = opts.now ?? Date.now;
  }

  get size(): number {
    return this.items.size;
  }

  /** Register a freshly issued challenge for `auditId`. Overwriting an existing entry is refused. */
  issue(p: Omit<PendingApproval, "status" | "used">): PendingApproval {
    if (this.items.has(p.auditId)) throw new Error("approval already issued for this audit id");
    this.prune();
    const entry: PendingApproval = { ...p, status: "pending", used: false };
    this.items.set(p.auditId, entry);
    return entry;
  }

  get(auditId: string): PendingApproval | undefined {
    return this.items.get(auditId);
  }

  isExpired(p: PendingApproval, at: number = this.now()): boolean {
    return at > Date.parse(p.expiresAt);
  }

  /** Effective status as seen by the status endpoint. */
  status(auditId: string): { status: ApprovalStatus; entry?: PendingApproval } {
    const p = this.items.get(auditId);
    if (!p) return { status: "unknown" };
    if (p.status === "pending" && this.isExpired(p)) return { status: "expired", entry: p };
    return { status: p.status, entry: p };
  }

  /** Burn a pending entry (fail closed): it can never be approved afterwards. */
  reject(auditId: string): void {
    const p = this.items.get(auditId);
    if (p && p.status === "pending") {
      p.status = "rejected";
      p.used = true;
    }
  }

  /** Force an entry (even a claimed one) into `rejected`: used when the approval could not be audited. */
  invalidate(auditId: string): void {
    const p = this.items.get(auditId);
    if (p) {
      p.status = "rejected";
      p.used = true;
      delete p.approvedBy;
      delete p.approvalId;
      delete p.approvedAt;
    }
  }

  /**
   * Atomically (synchronously) claim the entry for approval. Returns false when it
   * is not pending, already used or expired, so two concurrent valid submissions
   * cannot both succeed.
   */
  claim(auditId: string, by: { keyId: string; approvedAt: string }): PendingApproval | undefined {
    const p = this.items.get(auditId);
    if (!p || p.used || p.status !== "pending" || this.isExpired(p)) return undefined;
    p.used = true;
    p.status = "approved";
    p.approvedBy = by.keyId;
    p.approvedAt = by.approvedAt;
    p.approvalId = randomUUID();
    return p;
  }

  private prune(): void {
    if (this.items.size < this.maxPending) return;
    const t = this.now();
    for (const [k, p] of this.items) {
      if (p.used || this.isExpired(p, t)) this.items.delete(k);
      if (this.items.size < this.maxPending) return;
    }
    // Still full: drop the oldest insertions. They were issued longest ago and are
    // closest to expiry; losing them only forces a fresh check (never an allow).
    for (const k of this.items.keys()) {
      this.items.delete(k);
      if (this.items.size < this.maxPending) return;
    }
  }
}

export type ApprovalRejectionReason =
  | "unknown_audit"
  | "not_escalate"
  | "already_used"
  | "expired"
  | "unregistered_key"
  | "bad_signature"
  | "approved_at_outside_window"
  | "record_mismatch";

export interface ApprovalVerifyInput {
  auditId: string;
  keyId: string;
  signature: string;
  approvedAt: string;
}

/**
 * Evaluate every check for an approval submission and return the full list of
 * failures (empty = valid). All checks always run, in the same order, so the
 * work done does not depend on which one fails; the caller reports a single
 * generic error and logs the reasons.
 */
export function verifyApprovalSubmission(
  input: ApprovalVerifyInput,
  deps: { pending: PendingApproval | undefined; record: AuditRecord | undefined; registry: ApproverRegistry; now: number; clockSkewMs: number },
): ApprovalRejectionReason[] {
  const reasons: ApprovalRejectionReason[] = [];
  const { pending, record, registry } = deps;

  if (!pending) reasons.push("unknown_audit");
  if (pending?.used) reasons.push("already_used");
  if (pending && deps.now > Date.parse(pending.expiresAt)) reasons.push("expired");

  // The pending entry must still match the sealed audit record it was issued for:
  // the record must exist, be an `escalate` check, and recompute to the same challenge.
  let recordChallenge: string | undefined;
  if (!record || (record.type ?? "check") !== "check" || record.decision.verdict !== "escalate") {
    reasons.push("not_escalate");
  } else {
    recordChallenge = pending
      ? computeApprovalChallenge({
          auditId: record.id,
          intent: record.intent,
          decision: record.decision,
          policyId: record.decision.policyId,
          policyVersion: record.decision.policyVersion,
          agentId: record.context.agentId,
          issuedAt: pending.issuedAt,
        })
      : undefined;
  }
  const challenge = pending?.challenge ?? "0".repeat(64);
  if (!recordChallenge || !safeEqualHex(recordChallenge, challenge) || !safeEqualHex(record?.approvalRequest?.challenge ?? "", challenge)) {
    reasons.push("record_mismatch");
  }

  if (!registry.has(input.keyId)) reasons.push("unregistered_key");
  if (!registry.verify(input.keyId, challenge, input.signature)) reasons.push("bad_signature");

  const approvedAt = Date.parse(input.approvedAt);
  const issuedAt = pending ? Date.parse(pending.issuedAt) : Number.NaN;
  const expiresAt = pending ? Date.parse(pending.expiresAt) : Number.NaN;
  if (
    !Number.isFinite(approvedAt) ||
    !Number.isFinite(issuedAt) ||
    approvedAt < issuedAt - deps.clockSkewMs ||
    approvedAt > expiresAt ||
    approvedAt > deps.now + deps.clockSkewMs
  ) {
    reasons.push("approved_at_outside_window");
  }
  return reasons;
}

function safeEqualHex(a: string, b: string): boolean {
  if (!CHALLENGE_RE.test(a) || !CHALLENGE_RE.test(b)) return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}

// ---- Audit provenance ----

export interface ApprovalProvenance {
  seq?: number;
  recordId: string;
  type: "approval" | "approval_rejected";
  checkAuditId: string;
  checkSeq?: number;
  outcome: ApprovalAuditData["outcome"];
  approverKeyId?: string;
  approvedAt?: string;
  approvalId?: string;
  rejectionReason?: string;
  /** Problems linking this record to its check. Empty when provenance is intact. */
  problems: Array<"missing_check" | "check_not_escalate" | "challenge_mismatch" | "duplicate_approval">;
}

/**
 * Walk a chain and pair every approval record with the check it refers to, so a
 * verifier can see the full provenance of each human approval: check (escalate,
 * challenge X) -> approval (challenge X, key K). Never throws.
 */
export function summarizeApprovals(records: Iterable<AuditRecord>): ApprovalProvenance[] {
  const checks = new Map<string, AuditRecord>();
  const out: ApprovalProvenance[] = [];
  const approvedChecks = new Set<string>();
  for (const rec of records) {
    const type = rec.type ?? "check";
    if (type === "check") {
      checks.set(rec.id, rec);
      continue;
    }
    const a = rec.approval;
    const checkId = a?.checkAuditId ?? "";
    const check = checks.get(checkId);
    const problems: ApprovalProvenance["problems"] = [];
    if (!check) problems.push("missing_check");
    else if (type === "approval") {
      // A rejected attempt against a non-escalate record is an expected, recorded event;
      // an *approval* that does not link to an escalated check with the same challenge is not.
      if (check.decision.verdict !== "escalate") problems.push("check_not_escalate");
      if (!a || !check.approvalRequest || check.approvalRequest.challenge !== a.challenge) problems.push("challenge_mismatch");
      if (approvedChecks.has(checkId)) problems.push("duplicate_approval");
      approvedChecks.add(checkId);
    }
    out.push({
      seq: rec.integrity?.seq,
      recordId: rec.id,
      type,
      checkAuditId: checkId,
      checkSeq: check?.integrity?.seq,
      outcome: a?.outcome ?? "rejected",
      approverKeyId: a?.approverKeyId,
      approvedAt: a?.approvedAt,
      approvalId: a?.approvalId,
      rejectionReason: a?.rejectionReason,
      problems,
    });
  }
  return out;
}
