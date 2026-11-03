import { createHash } from "node:crypto";

/**
 * Deterministic JSON: object keys sorted lexicographically at every level,
 * bigints rendered as decimal strings, Dates as ISO strings, `undefined`
 * properties dropped (array holes become null, as in JSON.stringify).
 * Non-finite numbers are rejected because they have no JSON representation.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(v: unknown): unknown {
  if (v === null || v === undefined) return v === undefined ? undefined : null;
  switch (typeof v) {
    case "bigint":
      return v.toString();
    case "number":
      if (!Number.isFinite(v)) throw new TypeError("canonicalJson: non-finite number");
      return v;
    case "string":
    case "boolean":
      return v;
    case "object": {
      if (v instanceof Date) return v.toISOString();
      if (Array.isArray(v)) return v.map((x) => (x === undefined ? null : canonicalize(x)));
      if (typeof (v as { toJSON?: unknown }).toJSON === "function") return canonicalize((v as { toJSON: () => unknown }).toJSON());
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(v as object).sort()) {
        const c = canonicalize((v as Record<string, unknown>)[k]);
        if (c !== undefined) out[k] = c;
      }
      return out;
    }
    default:
      return undefined; // functions, symbols: dropped like JSON.stringify
  }
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}
