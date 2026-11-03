import {
  AddressLookupTableAccount, ComputeBudgetInstruction, ComputeBudgetProgram, PublicKey, SystemInstruction,
  SystemProgram, TransactionInstruction, VersionedTransaction, type MessageAccountKeys,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, TokenInstruction,
  decodeApproveCheckedInstructionUnchecked, decodeApproveInstructionUnchecked,
  decodeCloseAccountInstructionUnchecked, decodeRevokeInstructionUnchecked,
  decodeSetAuthorityInstructionUnchecked, decodeTransferCheckedInstructionUnchecked,
  decodeTransferInstructionUnchecked,
} from "@solana/spl-token";
import type { ConnectionLike } from "./connection.js";

export const COMPUTE_BUDGET_PROGRAM_ID = ComputeBudgetProgram.programId.toBase58();
export const SYSTEM_PROGRAM_ID = SystemProgram.programId.toBase58();
export const TOKEN_PROGRAM_IDS = new Set([TOKEN_PROGRAM_ID.toBase58(), TOKEN_2022_PROGRAM_ID.toBase58()]);

export type DecodedIx =
  | { kind: "system.transfer"; from: string; to: string; lamports: bigint }
  | { kind: "system.other"; type: string }
  | { kind: "token.transfer"; source: string; destination: string; owner: string; amount: bigint; mint?: string; decimals?: number; programId: string }
  | { kind: "token.approve"; account: string; delegate: string; owner: string; amount: bigint; mint?: string; programId: string }
  | { kind: "token.revoke"; account: string; owner: string; programId: string }
  | { kind: "token.setAuthority"; account: string; currentAuthority: string; authorityType: number; newAuthority?: string; programId: string }
  | { kind: "token.closeAccount"; account: string; destination: string; authority: string; programId: string }
  | { kind: "token.other"; instruction: number; programId: string }
  | { kind: "computeBudget"; type: string; units?: number; microLamports?: bigint }
  | { kind: "unknown"; programId: string; dataLength: number };

/** Parse base64 `raw` into a VersionedTransaction. Handles legacy and v0 wire formats. */
export function deserializeTransaction(raw: string): VersionedTransaction {
  const buf = Buffer.from(raw, "base64");
  return VersionedTransaction.deserialize(buf);
}

/** Resolve all account keys, loading address lookup tables for v0 messages when needed. */
export async function resolveAccountKeys(tx: VersionedTransaction, connection: ConnectionLike): Promise<MessageAccountKeys> {
  const msg = tx.message;
  const lookups = msg.addressTableLookups;
  if (!lookups || lookups.length === 0) return msg.getAccountKeys();
  const keys = lookups.map((l) => l.accountKey);
  const infos = await connection.getMultipleAccountsInfo(keys);
  const addressLookupTableAccounts: AddressLookupTableAccount[] = [];
  infos.forEach((info, i) => {
    if (!info) throw new Error(`address lookup table ${keys[i]!.toBase58()} not found`);
    addressLookupTableAccounts.push(new AddressLookupTableAccount({
      key: keys[i]!, state: AddressLookupTableAccount.deserialize(info.data),
    }));
  });
  return msg.getAccountKeys({ addressLookupTableAccounts });
}

/** Expand compiled instructions into TransactionInstruction objects. */
export function expandInstructions(tx: VersionedTransaction, keys: MessageAccountKeys): TransactionInstruction[] {
  const msg = tx.message;
  return msg.compiledInstructions.map((ci) => {
    const programId = keys.get(ci.programIdIndex);
    if (!programId) throw new Error(`program id index ${ci.programIdIndex} out of range`);
    return new TransactionInstruction({
      programId,
      keys: ci.accountKeyIndexes.map((idx) => {
        const pubkey = keys.get(idx);
        if (!pubkey) throw new Error(`account index ${idx} out of range`);
        return { pubkey, isSigner: msg.isAccountSigner(idx), isWritable: msg.isAccountWritable(idx) };
      }),
      data: Buffer.from(ci.data),
    });
  });
}

const b58 = (k: PublicKey | undefined) => (k ? k.toBase58() : "");

/** Decode a single instruction. Never throws. */
export function decodeInstruction(ix: TransactionInstruction): DecodedIx {
  const pid = ix.programId.toBase58();
  try {
    if (pid === SYSTEM_PROGRAM_ID) {
      const type = SystemInstruction.decodeInstructionType(ix);
      if (type === "Transfer") {
        const t = SystemInstruction.decodeTransfer(ix);
        return { kind: "system.transfer", from: b58(t.fromPubkey), to: b58(t.toPubkey), lamports: BigInt(t.lamports) };
      }
      if (type === "TransferWithSeed") {
        const t = SystemInstruction.decodeTransferWithSeed(ix);
        return { kind: "system.transfer", from: b58(t.fromPubkey), to: b58(t.toPubkey), lamports: BigInt(t.lamports) };
      }
      return { kind: "system.other", type };
    }
    if (pid === COMPUTE_BUDGET_PROGRAM_ID) {
      const type = ComputeBudgetInstruction.decodeInstructionType(ix);
      if (type === "SetComputeUnitLimit") {
        return { kind: "computeBudget", type, units: ComputeBudgetInstruction.decodeSetComputeUnitLimit(ix).units };
      }
      if (type === "SetComputeUnitPrice") {
        return { kind: "computeBudget", type, microLamports: BigInt(ComputeBudgetInstruction.decodeSetComputeUnitPrice(ix).microLamports) };
      }
      return { kind: "computeBudget", type };
    }
    if (TOKEN_PROGRAM_IDS.has(pid)) {
      const op = ix.data[0];
      switch (op) {
        case TokenInstruction.Transfer: {
          const d = decodeTransferInstructionUnchecked(ix);
          return { kind: "token.transfer", programId: pid, source: b58(d.keys.source?.pubkey), destination: b58(d.keys.destination?.pubkey),
            owner: b58(d.keys.owner?.pubkey), amount: d.data.amount };
        }
        case TokenInstruction.TransferChecked: {
          const d = decodeTransferCheckedInstructionUnchecked(ix);
          return { kind: "token.transfer", programId: pid, source: b58(d.keys.source?.pubkey), destination: b58(d.keys.destination?.pubkey),
            owner: b58(d.keys.owner?.pubkey), amount: d.data.amount, mint: b58(d.keys.mint?.pubkey), decimals: d.data.decimals };
        }
        case TokenInstruction.Approve: {
          const d = decodeApproveInstructionUnchecked(ix);
          return { kind: "token.approve", programId: pid, account: b58(d.keys.account?.pubkey), delegate: b58(d.keys.delegate?.pubkey),
            owner: b58(d.keys.owner?.pubkey), amount: d.data.amount };
        }
        case TokenInstruction.ApproveChecked: {
          const d = decodeApproveCheckedInstructionUnchecked(ix);
          return { kind: "token.approve", programId: pid, account: b58(d.keys.account?.pubkey), delegate: b58(d.keys.delegate?.pubkey),
            owner: b58(d.keys.owner?.pubkey), amount: d.data.amount, mint: b58(d.keys.mint?.pubkey) };
        }
        case TokenInstruction.Revoke: {
          const d = decodeRevokeInstructionUnchecked(ix);
          return { kind: "token.revoke", programId: pid, account: b58(d.keys.account?.pubkey), owner: b58(d.keys.owner?.pubkey) };
        }
        case TokenInstruction.SetAuthority: {
          const d = decodeSetAuthorityInstructionUnchecked(ix);
          return { kind: "token.setAuthority", programId: pid, account: b58(d.keys.account?.pubkey), currentAuthority: b58(d.keys.currentAuthority?.pubkey),
            authorityType: d.data.authorityType, newAuthority: d.data.newAuthority ? d.data.newAuthority.toBase58() : undefined };
        }
        case TokenInstruction.CloseAccount: {
          const d = decodeCloseAccountInstructionUnchecked(ix);
          return { kind: "token.closeAccount", programId: pid, account: b58(d.keys.account?.pubkey), destination: b58(d.keys.destination?.pubkey),
            authority: b58(d.keys.authority?.pubkey) };
        }
        default:
          return { kind: "token.other", programId: pid, instruction: op ?? -1 };
      }
    }
  } catch {
    /* fall through to unknown */
  }
  return { kind: "unknown", programId: pid, dataLength: ix.data.length };
}
