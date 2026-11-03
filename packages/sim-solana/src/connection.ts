import type {
  AccountInfo, PublicKey, RpcResponseAndContext, SimulatedTransactionResponse,
  SimulateTransactionConfig, VersionedTransaction,
} from "@solana/web3.js";

/**
 * Minimal subset of `@solana/web3.js` `Connection` used by the adapter.
 * A real `Connection` satisfies it; tests supply a mock.
 */
export interface ConnectionLike {
  simulateTransaction(
    transaction: VersionedTransaction,
    config?: SimulateTransactionConfig,
  ): Promise<RpcResponseAndContext<SimulatedTransactionResponse>>;
  getAccountInfo(publicKey: PublicKey): Promise<AccountInfo<Buffer> | null>;
  getMultipleAccountsInfo(publicKeys: PublicKey[]): Promise<(AccountInfo<Buffer> | null)[]>;
}
