import pino, { type Logger, type LoggerOptions } from "pino";

/**
 * Keys whose values are replaced with "[REDACTED]" in every log line emitted at
 * a level above `debug`. Matching is case-insensitive on the key name and
 * applies at any depth of the logged object (bounded by MAX_DEPTH).
 *
 * Rationale: calldata / raw transactions can embed secrets (permit signatures,
 * memo fields) and are large; metadata is agent-controlled free-form input;
 * api keys and signatures must never land in logs at all.
 */
export const DEFAULT_REDACT_KEYS: readonly string[] = [
  "x-api-key",
  "apikey",
  "api_key",
  "apiKey",
  "authorization",
  "cookie",
  "set-cookie",
  "x-agentguard-signature",
  "signature",
  "signingsecret",
  "signingSecret",
  "privatekey",
  "privateKey",
  "secret",
  "password",
  "token",
  "data", // EVM calldata
  "calldata",
  "raw", // Solana serialized tx
  "rawtx",
  "rawTx",
  "rawTrace",
  "metadata",
];

const REDACTED = "[REDACTED]";
const MAX_DEPTH = 12;
const DEBUG_LEVEL = 20;

export interface RedactingLoggerOptions extends LoggerOptions {
  /** Extra keys to redact on top of DEFAULT_REDACT_KEYS. */
  redactKeys?: readonly string[];
  /** Destination stream (tests). */
  stream?: { write(s: string): unknown };
}

/** Deep-copy `value` replacing every property whose key is in `keys`. Cycle-safe, depth-bounded. */
export function redactObject<T>(value: T, keys: ReadonlySet<string>, depth = 0, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object") return value;
  if (depth > MAX_DEPTH) return "[TRUNCATED]" as unknown as T;
  if (seen.has(value as object)) return "[CIRCULAR]" as unknown as T;
  seen.add(value as object);
  if (Array.isArray(value)) return value.map((v) => redactObject(v, keys, depth + 1, seen)) as unknown as T;
  if (value instanceof Error) {
    // Preserve Error identity for pino's err serializer, but scrub nested props.
    const copy = Object.create(Object.getPrototypeOf(value)) as Error & Record<string, unknown>;
    Object.defineProperty(copy, "message", { value: value.message, enumerable: false, writable: true, configurable: true });
    Object.defineProperty(copy, "stack", { value: value.stack, enumerable: false, writable: true, configurable: true });
    Object.defineProperty(copy, "name", { value: value.name, enumerable: false, writable: true, configurable: true });
    for (const k of Object.keys(value)) {
      copy[k] = keys.has(k.toLowerCase()) ? REDACTED : redactObject((value as unknown as Record<string, unknown>)[k], keys, depth + 1, seen);
    }
    return copy as unknown as T;
  }
  if (value instanceof Date || Buffer.isBuffer(value)) return value;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = keys.has(k.toLowerCase()) ? REDACTED : redactObject(v, keys, depth + 1, seen);
  }
  return out as T;
}

/**
 * Build a pino logger whose `info` and higher levels never contain values
 * under the redaction keys. `debug`/`trace` are left untouched so operators can
 * opt into full payloads locally.
 */
export function createRedactingLogger(opts: RedactingLoggerOptions = {}): Logger {
  const { redactKeys, stream, hooks, ...rest } = opts;
  const keys = new Set([...DEFAULT_REDACT_KEYS, ...(redactKeys ?? [])].map((k) => k.toLowerCase()));
  const options: LoggerOptions = {
    ...rest,
    hooks: {
      ...hooks,
      logMethod(args, method, level) {
        if (level > DEBUG_LEVEL && args.length > 0 && args[0] !== null && typeof args[0] === "object") {
          args[0] = redactObject(args[0], keys);
        }
        if (hooks?.logMethod) return hooks.logMethod.call(this, args, method, level);
        return method.apply(this, args);
      },
    },
  };
  return stream ? pino(options, stream as pino.DestinationStream) : pino(options);
}
