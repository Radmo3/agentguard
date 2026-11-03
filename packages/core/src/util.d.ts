export declare const UINT256_MAX: bigint;
export declare const U64_MAX: bigint;
export declare function isUnlimitedApproval(amount: bigint): boolean;
export declare function toDecimal(amount: bigint, decimals: number): number;
/** JSON.stringify replacer that serialises bigint as string with "n" suffix-free decimal. */
export declare function bigintReplacer(_k: string, v: unknown): unknown;
export declare function nowIso(d?: Date): string;
