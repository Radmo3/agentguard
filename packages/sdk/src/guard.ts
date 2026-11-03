import type { AgentContext, CheckResponse, Decision, TransactionIntent } from "@agentguard/core";
import type { AgentGuardClient, CheckOptions } from "./client.js";
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
}

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
  /**
   * Called on `escalate`. Return `true` to proceed (human approved), `false`/void to abort with
   * GuardEscalatedError. Default: throw GuardEscalatedError.
   */
  onEscalate?: (info: EscalationInfo) => boolean | void | Promise<boolean | void>;
  /** Observability hook invoked for every decision regardless of verdict. */
  onDecision?: (info: EscalationInfo) => void | Promise<void>;
  /** Generate intent ids. Default: crypto.randomUUID. */
  generateId?: () => string;
}

export type Guarded<S extends SignerLike> = S & {
  /** The unwrapped signer. */
  readonly __agentguardInner: S;
};

const GUARDED_METHODS = ["signTransaction", "sendTransaction"] as const;

/**
 * Wrap a signer so that every `signTransaction` / `sendTransaction` call is checked
 * against AgentGuard first. Returns a Proxy; all other properties pass through untouched.
 */
export function guard<S extends SignerLike>(signer: S, client: AgentGuardClient, opts: GuardOptions): Guarded<S> {
  const genId = opts.generateId ?? (() => globalThis.crypto.randomUUID());

  async function runCheck(method: (typeof GUARDED_METHODS)[number], args: unknown[]): Promise<CheckResponse> {
    const partial = await opts.toIntent(args[0], ...args.slice(1));
    const intent: TransactionIntent = { ...partial, id: partial.id ?? genId() };
    const context = typeof opts.context === "function" ? await opts.context(intent) : opts.context;
    const res = await client.check(intent, context, opts.checkOptions);
    const info: EscalationInfo = { decision: res.decision, auditId: res.auditId, intent, method };
    await opts.onDecision?.(info);

    switch (res.decision.verdict) {
      case "allow":
        return res;
      case "block":
        throw new GuardBlockedError(res.decision, res.auditId);
      case "escalate": {
        if (!opts.onEscalate) throw new GuardEscalatedError(res.decision, res.auditId);
        const approved = await opts.onEscalate(info);
        if (approved !== true) throw new GuardEscalatedError(res.decision, res.auditId);
        return res;
      }
      default:
        throw new GuardEscalatedError(res.decision, res.auditId);
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
