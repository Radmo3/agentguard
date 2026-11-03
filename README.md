# AgentGuard

AgentGuard is a transaction guardrail layer for AI agents that hold crypto wallets. Before an agent signs or broadcasts anything, it submits the proposed transaction to AgentGuard, which simulates it against live chain state, evaluates the simulated effects against an operator-defined policy, and returns `allow`, `block` or `escalate` with a human-readable explanation, a 0–100 risk score and an immutable audit record. Agents never get to decide for themselves whether a transaction is safe.

It works on EVM chains and Solana, decodes the usual drain vectors (unlimited approvals, `setApprovalForAll`, permits, swaps with zero minimum output, SetAuthority, interactions with never-seen contracts), and ships with a conservative default policy plus a TypeScript SDK that wraps any signer so that `signTransaction` / `sendTransaction` are checked transparently.

## Architecture

```
                    +----------------------------------------------------+
   AI agent         |                 AgentGuard API (Fastify)            |
 +-----------+      |                                                    |
 | signer    |      |  POST /v1/check                                    |
 |   wrapped |      |     |                                              |
 |   by      | ---> |     v                                              |
 | @agentguard/sdk  |  ChainAdapter.simulate(intent)                     |
 +-----------+      |     |   +-- @agentguard/sim-evm    (viem)          |
                    |     |   +-- @agentguard/sim-solana (@solana/web3.js)|
                    |     v                                              |
                    |  SimulationResult { deltas, approvals, warnings,   |
                    |                     newContracts, ok }             |
                    |     |                                              |
                    |     v                                              |
                    |  @agentguard/policy PolicyEngine.evaluate(         |
                    |     {intent, simulation, context, policy})          |
                    |     |                                              |
                    |     v                                              |
                    |  Decision { verdict, riskScore, findings,          |
                    |             explanation }  --> AuditStore           |
                    +----------------------------------------------------+
                                   ^
                                   |  shared types: @agentguard/core
```

Workspaces (`packages/*`): `core` (shared contracts), `policy` (rules + engine), `sim-evm`, `sim-solana`, `api`, `sdk`. `examples/` holds the end-to-end demo.

## Quickstart

Requires Node 22+.

```bash
npm install
npm run build
npm run typecheck
npm run test
npm run demo          # == npx tsx examples/demo.ts (in-process API, mock RPC, no network)
```

Run the server against real RPC endpoints:

```bash
export AGENTGUARD_EVM_RPC_URL=https://mainnet.base.org
export AGENTGUARD_SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
export AGENTGUARD_API_KEYS=secret-1,secret-2          # omit to disable auth (not recommended)
export AGENTGUARD_POLICY_FILE=./policy.json           # optional; defaults to conservativeDefaultPolicy
export AGENTGUARD_AUDIT_FILE=./audit.jsonl            # optional; defaults to in-memory
export AGENTGUARD_KNOWN_EVM_CONTRACTS=0xabc...,0xdef... # optional; enables new-contract detection
export AGENTGUARD_KNOWN_SOLANA_PROGRAMS=Tokenkeg...,1111... # optional
export AGENTGUARD_RATE_LIMIT_MAX=120                  # optional; per AGENTGUARD_RATE_LIMIT_WINDOW_MS (default 60000)
export PORT=8787 LOG_LEVEL=info
node packages/api/dist/main.js
```

## API

### `POST /v1/check`

Headers: `content-type: application/json`, `x-api-key: <key>` (when keys are configured). All `bigint` fields are decimal strings.

Request:

```json
{
  "intent": {
    "id": "3f1c…",
    "chain": "evm",
    "chainId": 8453,
    "from": "0x1111111111111111111111111111111111111111",
    "to": "0x3333333333333333333333333333333333333333",
    "value": "0",
    "data": "0xa9059cbb000000000000000000000000222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000004c4b40",
    "description": "pay supplier invoice #42"
  },
  "context": {
    "agentId": "ops-agent-1",
    "spentUsdInWindow": 120,
    "windowSeconds": 3600,
    "denylist": ["0xbad0000000000000000000000000000000000bad"]
  },
  "policyId": "conservative-default"
}
```

Solana intents carry the base64 serialized (versioned) transaction in `raw` instead of `to`/`data`.

Response (`200`):

```json
{
  "decision": {
    "intentId": "3f1c…",
    "verdict": "allow",
    "riskScore": 0,
    "findings": [],
    "explanation": "Transaction 3f1c… from 0x1111… to 0x3333… on evm (\"pay supplier invoice #42\") was allowed with risk score 0/100. No policy rules fired.",
    "simulation": {
      "ok": true,
      "deltas": [{ "asset": "0x3333…", "symbol": "USDC", "decimals": 6, "amount": "-5000000", "usdValue": -5 }],
      "approvals": [],
      "contractsTouched": ["0x3333…"],
      "newContracts": [],
      "gasEstimate": "52000",
      "warnings": []
    },
    "policyId": "conservative-default",
    "policyVersion": 1,
    "evaluatedAt": "2026-11-03T01:50:00.000Z"
  },
  "auditId": "7d2e…"
}
```

`verdict` is one of `allow`, `block`, `escalate`. If simulation or the engine fails, the API fails closed with `escalate` and a `simulation_error` / `engine_error` finding. Other routes: `GET /healthz`, `GET /v1/audit/:id`, `GET /v1/audit?agentId=&limit=&cursor=`. Errors: `400 bad_request | unsupported_chain`, `401 unauthorized`, `404 policy_not_found`.

## SDK

```ts
import { AgentGuardClient, guard, GuardBlockedError, GuardEscalatedError } from "@agentguard/sdk";

const client = new AgentGuardClient({ baseUrl: "http://localhost:8787", apiKey: process.env.AGENTGUARD_KEY });

const safeSigner = guard(signer, client, {
  // Map the signer's native tx argument to a TransactionIntent (id is generated for you).
  toIntent: (tx) => ({ chain: "evm", chainId: 8453, from: tx.from, to: tx.to, value: tx.value, data: tx.data }),
  context: { agentId: "ops-agent-1", windowSeconds: 3600 },
  onEscalate: async ({ decision, auditId }) => askHumanForApproval(decision.explanation, auditId), // return true to proceed
  onDecision: ({ decision }) => metrics.record(decision.verdict, decision.riskScore),
});

try {
  await safeSigner.sendTransaction(tx);           // checked first; throws on block / unapproved escalate
} catch (err) {
  if (err instanceof GuardBlockedError) console.error("blocked:", err.decision.explanation);
  if (err instanceof GuardEscalatedError) console.warn("needs review:", err.auditId);
}
```

`client.check(intent, context)` is available for direct use without wrapping a signer.

## Policy

Policies are JSON, validated by `loadPolicy` from `@agentguard/policy`. Rule kinds: `max_tx_usd`, `max_window_usd`, `allowlist_only`, `denylist`, `no_unlimited_approvals`, `max_slippage_bps`, `no_new_contracts`, `require_simulation_ok`, `max_native_value`, `custom`. `onViolation` is `block` (default) or `escalate`; the strictest firing rule wins.

```json
{
  "id": "treasury-ops",
  "version": 2,
  "rules": [
    { "id": "sim-ok",        "kind": "require_simulation_ok" },
    { "id": "no-unlimited",  "kind": "no_unlimited_approvals" },
    { "id": "denylist",      "kind": "denylist", "params": { "addresses": ["0xbad0000000000000000000000000000000000bad"] } },
    { "id": "tx-cap",        "kind": "max_tx_usd",      "params": { "maxUsd": 250 } },
    { "id": "window-cap",    "kind": "max_window_usd",  "params": { "maxUsd": 2000 }, "onViolation": "escalate" },
    { "id": "native-cap",    "kind": "max_native_value","params": { "maxWei": "100000000000000000" }, "onViolation": "escalate" },
    { "id": "new-contracts", "kind": "no_new_contracts", "onViolation": "escalate" },
    { "id": "slippage",      "kind": "max_slippage_bps", "params": { "maxBps": 50 }, "onViolation": "escalate" },
    { "id": "only-known",    "kind": "allowlist_only",  "params": { "addresses": ["0x3333…", "0x4444…"] } }
  ]
}
```

The built-in `conservativeDefaultPolicy` ($100/tx, $500/window, no unlimited approvals, escalate on new contracts and >0.05 native) is used when no policy file is supplied.

## Roadmap

- Model-based anomaly scoring on top of the rule engine (per-agent behavioural baselines, outlier detection on deltas and counterparties).
- Contract reputation data: verified-source, age, TVL and known-exploit feeds folded into `newContracts` and the risk score.
- SOC 2 controls for the hosted service: tamper-evident audit log, key rotation, retention policies.
- Custody integrations: Fireblocks policy-engine hooks and Safe (Gnosis) guard module so AgentGuard sits inline with institutional signing.
