import type { AgentContext, CheckResponse, Decision, TransactionIntent } from "@agentguard/core";
import type { AgentGuardClient, CheckOptions, WaitForApprovalOptions } from "./client.js";
import { GuardBlockedError, GuardEscalatedError } from "./errors.js";

/** Minimal duck-typed signer. Any object exposing one or both of these methods can be wrapped. */
export interface SignerLike {
  signTransaction?: (...args: any[]) => Promise<unknown>;
  sendTransaction?: (...args: any[]) => Promise<unknown>;
}

export type IntentInput = Omit<TransactionIntent, "id"> & { id?: string };

export interface EscalationInfo {
  decision: Decision;
  auditId: string;
  intent: TransactionIntent;
  /** Which signer method triggered the check. */
  method: "signTransaction" | "sendTransaction";
  /**
   * Challenge a registered approver device must sign (server mode). Absent when the
   * server has no approver keys registered, in which case the escalation cannot be
   * approved through the API at all.
   */
  approval?: { challenge: string; expiresAt: string };
}

/**
 * How an `escalate` verdict can become permission to sign.
 *
 * - `"server"` (default, I-HITL): only a server-verified approval counts. A human
 *   signs the challenge on a device the agent cannot reach, the server verifies the
 *   Ed25519 signature against its registry, and the SDK learns about it by polling
 *   `GET /v1/approvals/:auditId`. Nothing in this process can grant approval.
 * - `"callback"` (advisory, NOT I-HITL): `onEscalate` runs in this process and its
 *   `true` is trusted. Anything that can run code here (a prompt-injected tool, a
 *   compromised dependency, the agent itself) can approve its own transaction.
 *   Use only where the agent process is fully trusted and no money is at stake.
 */
export type ApprovalMode = "server" | "callback";

export interface GuardOptions {
  /**
   * Convert the signer's native transaction argument(s) into a TransactionIntent.
   * `id` may be omitted; one will be generated.
   */
  toIntent: (tx: any, ...rest: any[]) => IntentInput | Promise<IntentInput>;
  /** Static context or a function computing it per call. */
  context: AgentContext | ((intent: TransactionIntent) => AgentContext | Promise<AgentContext>);
  /** Per-call check options forwarded to the client. */
  checkOptions?: CheckOptions;
  /** See `ApprovalMode`. Default `"server"`. */
  approval?: ApprovalMode;
  /**
   * Server mode only. `true` (or options) makes the proxy block on `escalate`,
   * polling the server until a registered approver has signed the challenge; the
   * signer runs only after the server reports `approved`. Default `false`: the
   * proxy throws `GuardEscalatedError` (carrying `auditId` and `challenge`) and the
   * caller decides how to wait, e.g. `client.waitForApproval(auditId)` later.
   */
  waitForApproval?: boolean | WaitForApprovalOptions;
  /**
   * Server mode only. Notified when a check escalates, before any waiting: use it to
   * route `auditId` + `challenge` to the human (push notification, ticket, chat).
   * Its return value is ignored: it cannot approve anything. If it throws, the
   * transaction is aborted (fail closed).
   */
  onEscalationPending?: (info: EscalationInfo) => void | Promise<void>;
  /**
   * ADVISORY MODE ONLY (`approval: "callback"`). THIS IS NOT I-HITL.
   *
   * Runs in the agent's own process on `escalate`; returning literal `true` lets the
   * transaction proceed. Because it executes on the same host as the agent, the agent
   * (or anything that compromises it) can call it, stub it or simulate its answer, so
   * it provides no guarantee that a human was involved. Never use it where the agent
   * is untrusted or where the signer controls real funds; use server mode instead.
   * Passing it in server mode is a configuration error and `guard()` throws.
   */
  onEscalate?: (info: EscalationInfo) => boolean | void | Promise<boolean | void>;
  /** Observability hook invoked for every decision regardless of verdict. */
  onDecision?: (info: EscalationInfo) => void | Promise<void>;
  /** Generate intent ids. Default: crypto.randomUUID. */
  generateId?: () => string;
  /** Where the one-time advisory-mode warning goes. Default `console.warn`. */
  warn?: (message: string) => void;
}

export type Guarded<S extends SignerLike> = S & {
  /** The unwrapped signer. */
  readonly __agentguardInner: S;
};

const GUARDED_METHODS = ["signTransaction", "sendTransaction"] as const;

export const ADVISORY_MODE_WARNING =
  "[agentguard] guard() is running with approval: \"callback\" (advisory mode). onEscalate executes inside the agent process, " +
  "so the agent can approve its own escalated transactions. This is NOT inalienable human-in-the-loop (I-HITL). " +
  "Use approval: \"server\" with registered approver keys for any signer that controls real funds.";

let advisoryWarned = false;

/** Test hook: reset the one-time advisory warning. */
export function __resetAdvisoryWarning(): void {
  advisoryWarned = false;
}

/**
 * Wrap a signer so that every `signTransaction` / `sendTransaction` call is checked
 * against AgentGuard first. Returns a Proxy; all other properties pass through untouched.
 *
 * On `escalate` the default (`approval: "server"`) never consults code in this
 * process: it either throws `GuardEscalatedError` with the challenge for a human,
 * or (with `waitForApproval`) polls the server until a registered approver's
 * signature has been verified there.
 */
export function guard<S extends SignerLike>(signer: S, client: AgentGuardClient, opts: GuardOptions): Guarded<S> {
  const genId = opts.generateId ?? (() => globalThis.crypto.randomUUID());
  const mode: ApprovalMode = opts.approval ?? "server";
  if (mode !== "server" && mode !== "callback") throw new TypeError(`guard(): unknown approval mode '${String(mode)}'`);

  if (mode === "server") {
    if (opts.onEscalate !== undefined) {
      throw new TypeError(
        'guard(): onEscalate is not allowed with approval: "server". A local callback cannot approve an escalation (I-HITL); ' +
          'route the challenge to a human with onEscalationPending and wait with waitForApproval, or opt into advisory mode explicitly with approval: "callback".',
      );
    }
  } else {
    if (typeof opts.onEscalate !== "function") throw new TypeError('guard(): approval: "callback" requires an onEscalate function');
    if (opts.waitForApproval) throw new TypeError('guard(): waitForApproval only applies to approval: "server"');
    if (!advisoryWarned) {
      advisoryWarned = true;
      (opts.warn ?? ((m: string) => console.warn(m)))(ADVISORY_MODE_WARNING);
    }
  }

  // Captured once so a later mutation of `opts` cannot switch modes or inject a callback.
  const onEscalate = mode === "callback" ? opts.onEscalate : undefined;
  const waitOpts: WaitForApprovalOptions | undefined =
    mode === "server" && opts.waitForApproval ? (opts.waitForApproval === true ? {} : opts.waitForApproval) : undefined;

  async function runCheck(method: (typeof GUARDED_METHODS)[number], args: unknown[]): Promise<CheckResponse> {
    const partial = await opts.toIntent(args[0], ...args.slice(1));
    const intent: TransactionIntent = { ...partial, id: partial.id ?? genId() };
    const context = typeof opts.context === "function" ? await opts.context(intent) : opts.context;
    const res = await client.check(intent, context, opts.checkOptions);
    const info: EscalationInfo = { decision: res.decision, auditId: res.auditId, intent, method, approval: res.approval };
    await opts.onDecision?.(info);

    switch (res.decision.verdict) {
      case "allow":
        return res;
      case "block":
        throw new GuardBlockedError(res.decision, res.auditId);
      case "escalate": {
        if (mode === "callback") {
          // Advisory mode. See GuardOptions.onEscalate: this is not I-HITL.
          const approved = await onEscalate!(info);
          if (approved !== true) throw new GuardEscalatedError(res.decision, res.auditId, res.approval);
          return res;
        }
        // Server mode: nothing local can approve. Hand the challenge to a human, then
        // either wait for the server to report a verified approval or throw.
        await opts.onEscalationPending?.(info);
        if (!waitOpts) throw new GuardEscalatedError(res.decision, res.auditId, res.approval);
        if (!res.approval) {
          throw new GuardEscalatedError(res.decision, res.auditId, undefined, "server has no approver keys registered; cannot be approved");
        }
        const granted = await client.waitForApproval(res.auditId, waitOpts);
        if (granted.status !== "approved" || granted.auditId !== res.auditId) {
          throw new GuardEscalatedError(res.decision, res.auditId, res.approval, "approval not granted");
        }
        return res;
      }
      default:
        throw new GuardEscalatedError(res.decision, res.auditId, res.approval);
    }
  }

  return new Proxy(signer, {
    get(target, prop, receiver) {
      if (prop === "__agentguardInner") return target;
      const value = Reflect.get(target, prop, receiver);
      if ((GUARDED_METHODS as readonly PropertyKey[]).includes(prop) && typeof value === "function") {
        const method = prop as (typeof GUARDED_METHODS)[number];
        return async (...args: unknown[]) => {
          await runCheck(method, args);
          return (value as (...a: unknown[]) => Promise<unknown>).apply(target, args);
        };
      }
      return value;
    },
  }) as Guarded<S>;
}
