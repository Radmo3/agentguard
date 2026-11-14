import type { PolicySet } from "@signhold/core";

/**
 * A conservative starting policy suitable for an autonomous agent with a small
 * operating budget. Operators are expected to copy and tune it.
 */
export const conservativeDefaultPolicy: PolicySet = {
  id: "conservative-default",
  version: 1,
  rules: [
    {
      id: "sim-must-succeed",
      kind: "require_simulation_ok",
      onViolation: "block",
      description: "Never sign a transaction whose simulation reverted.",
    },
    {
      id: "no-unlimited-approvals",
      kind: "no_unlimited_approvals",
      onViolation: "block",
      description: "Unlimited token approvals are the most common drain vector.",
    },
    {
      id: "no-eoa-approvals",
      kind: "no_eoa_approvals",
      onViolation: "block",
      description: "Approvals to externally-owned accounts have no legitimate protocol use.",
    },
    {
      id: "denylist",
      kind: "denylist",
      onViolation: "block",
      description: "Operator-supplied denylist from the agent context.",
    },
    {
      id: "max-tx-100usd",
      kind: "max_tx_usd",
      onViolation: "block",
      params: { maxUsd: 100 },
      description: "No single transaction may spend more than $100.",
    },
    {
      id: "max-window-500usd",
      kind: "max_window_usd",
      onViolation: "escalate",
      params: { maxUsd: 500 },
      description: "Escalate once rolling-window spend would exceed $500.",
    },
    {
      id: "max-native-0.05",
      kind: "max_native_value",
      onViolation: "escalate",
      params: { maxWei: "50000000000000000" }, // 0.05 ETH (or 0.05e18 lamports-equivalent on Solana)
      description: "Escalate native transfers above 0.05 units.",
    },
    {
      id: "new-contracts",
      kind: "no_new_contracts",
      onViolation: "escalate",
      description: "Interacting with contracts that have no history needs a human look.",
    },
    {
      id: "slippage-100bps",
      kind: "max_slippage_bps",
      onViolation: "escalate",
      params: { maxBps: 100 },
      description: "Escalate swaps whose simulated output is >1% below the expected output.",
    },
  ],
};
