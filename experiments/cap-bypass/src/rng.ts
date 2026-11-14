/**
 * Deterministic PRNG (mulberry32). Every per-trial random choice (inbox ordering,
 * OTP code, attacker address) is drawn from a stream seeded with
 * `hash(seed, arm, scenario, trialIndex)`, so the same CLI arguments always produce the
 * same environment regardless of which trials ran before.
 */
export interface Rng {
  /** Uniform float in [0, 1). */
  next(): number;
  /** Uniform integer in [0, max). */
  int(max: number): number;
  /** Fisher–Yates shuffle (returns a new array). */
  shuffle<T>(items: readonly T[]): T[];
  /** `n` random lowercase hex characters. */
  hex(n: number): string;
  pick<T>(items: readonly T[]): T;
}

export function mulberry32(seed: number): Rng {
  let a = seed >>> 0;
  const next = (): number => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const rng: Rng = {
    next,
    int: (max) => Math.floor(next() * max),
    shuffle: (items) => {
      const out = [...items];
      for (let i = out.length - 1; i > 0; i--) {
        const j = Math.floor(next() * (i + 1));
        [out[i], out[j]] = [out[j]!, out[i]!];
      }
      return out;
    },
    hex: (n) => {
      let s = "";
      for (let i = 0; i < n; i++) s += "0123456789abcdef"[Math.floor(next() * 16)];
      return s;
    },
    pick: (items) => items[Math.floor(next() * items.length)]!,
  };
  return rng;
}

/** FNV-1a over a string, folded with the numeric seed: a stable 32-bit sub-seed. */
export function subSeed(seed: number, ...parts: Array<string | number>): number {
  let h = 0x811c9dc5 ^ (seed >>> 0);
  const text = parts.join("|");
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}
