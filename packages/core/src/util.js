export const UINT256_MAX = (1n << 256n) - 1n;
export const U64_MAX = (1n << 64n) - 1n;
export function isUnlimitedApproval(amount) {
    return amount >= UINT256_MAX / 2n || amount === U64_MAX;
}
export function toDecimal(amount, decimals) {
    const neg = amount < 0n;
    const abs = neg ? -amount : amount;
    const whole = abs / 10n ** BigInt(decimals);
    const frac = abs % 10n ** BigInt(decimals);
    const n = Number(whole) + Number(frac) / 10 ** decimals;
    return neg ? -n : n;
}
/** JSON.stringify replacer that serialises bigint as string with "n" suffix-free decimal. */
export function bigintReplacer(_k, v) {
    return typeof v === "bigint" ? v.toString() : v;
}
export function nowIso(d = new Date()) { return d.toISOString(); }
//# sourceMappingURL=util.js.map