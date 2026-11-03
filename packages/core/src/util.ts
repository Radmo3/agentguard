export const UINT256_MAX = (1n << 256n) - 1n;
export const U64_MAX = (1n << 64n) - 1n;
/** uint96 max: used as the "infinite" sentinel by tokens with 96-bit balances (UNI, COMP, ...). */
export const UINT96_MAX = (1n << 96n) - 1n;
/**
 * Any approval at or above this is treated as unlimited. 2^128 base units exceeds the
 * total supply of every real token by many orders of magnitude (a 18-decimal token would
 * need 3.4e20 whole tokens), so bounded-but-astronomical approvals (2^200, uint160 max as
 * used by Permit2, ...) cannot slip past `no_unlimited_approvals`.
 */
export const UNLIMITED_APPROVAL_THRESHOLD = 1n << 128n;

export function isUnlimitedApproval(amount: bigint): boolean {
  return amount >= UNLIMITED_APPROVAL_THRESHOLD || amount === U64_MAX || amount === UINT96_MAX;
}

export function toDecimal(amount: bigint, decimals: number): number {
  const neg = amount < 0n;
  const abs = neg ? -amount : amount;
  const whole = abs / 10n ** BigInt(decimals);
  const frac = abs % 10n ** BigInt(decimals);
  const n = Number(whole) + Number(frac) / 10 ** decimals;
  return neg ? -n : n;
}

/** JSON.stringify replacer that serialises bigint as string with "n" suffix-free decimal. */
export function bigintReplacer(_k: string, v: unknown) {
  return typeof v === "bigint" ? v.toString() : v;
}

export function nowIso(d: Date = new Date()): string { return d.toISOString(); }
