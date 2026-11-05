# AgentGuard

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) [![Node 22+](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](package.json) [![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)](tsconfig.base.json)

AgentGuard is a transaction guardrail layer for AI agents that hold crypto wallets. Before an agent signs or broadcasts anything, it submits the proposed transaction to AgentGuard, which simulates it against live chain state, evaluates the simulated effects against an operator-defined policy, and returns `allow`, `block` or `escalate` with a human-readable explanation, a 0–100 risk score and an immutable audit record. Agents never get to decide for themselves whether a transaction is safe.

It works on EVM chains and Solana, decodes the usual drain vectors (unlimited approvals, `setApprovalForAll`, permits, swaps with zero minimum output, SetAuthority, interactions with never-seen contracts), and ships with a conservative default policy plus a TypeScript SDK that wraps any signer so that `signTransaction` / `sendTransaction` are checked transparently.

![AgentGuard demo: seven transactions checked through the SDK against the in-process API](docs/demo.gif)

On top of the rule engine, a **contract reputation** layer (`@agentguard/reputation`, in this repo) aggregates allow/deny lists, on-chain heuristics (age, proxy, bytecode size) and optional external intel feeds, and an optional **behavioral anomaly** layer (`@agentguard/behavior`, separately licensed, see [What's open and what's not](#whats-open-and-whats-not)) scores each transaction against the agent's own learned baseline. Both plug into the same pipeline and both fail closed: an outage or an unreadable profile escalates, never allows.

## What's open and what's not

Everything in this repository is open source under the [Apache License 2.0](LICENSE): the shared types, the policy engine and default policy, the EVM and Solana simulation adapters, the contract reputation layer, the HTTP API with its tamper-evident audit log, the SDK, the demo and all of the tests.

The **behavioral anomaly layer** is not in this repository. It ships as a separately licensed package, `@agentguard/behavior`, that learns a per-agent baseline (counterparties, amounts, cadence, approvals) from allowed decisions and flags transactions that are out of character for that agent, for example a $95 transfer to a never-paid address from an agent whose history is 30 routine $5 payments, which no static rule catches. It plugs into the open core without any code change here:

- `createServer()` accepts it through [`ServerOptions.behavior`](packages/api/src/types.ts) (`{ store, persist }`), and the engine takes its synchronous `behavior` custom rule like any other.
- `bootstrap()` / `main.ts` load it dynamically when it is installed: `AGENTGUARD_PROFILE_FILE` selects the JSONL profile store (unset means in-memory), `AGENTGUARD_BEHAVIOR=false` turns the layer off. When the package is not installed the server logs `@agentguard/behavior not installed: behavioral anomaly detection disabled` and runs with the rules in this repo.
- The contract between the two is the `createBehaviorIntegration()` factory described by `BehaviorModuleLike` in `packages/api/src/types.ts`. The API tests exercise that contract, and the fail-closed behaviour around it, with an in-test stub ([`packages/api/test/behavior-stub.ts`](packages/api/test/behavior-stub.ts)), so you can run the whole suite without the private package. Anything with the same shape (your own anomaly model included) can be plugged in the same way.

The `@agentguard/behavior` package lives at https://github.com/Radmo3/agentguard-behavior (private; contact the maintainers for licensing).

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
                    |     |                                              |
                    |     +--> @agentguard/reputation .prefetch()  (await)|
                    |     +--> ServerOptions.behavior store.get()  (await)|
                    |          (optional: @agentguard/behavior, external) |
                    |     v                                              |
                    |  @agentguard/policy PolicyEngine.evaluate(         |
                    |     {intent, simulation, context, policy})          |
                    |     |  built-in rules + custom "behavior" and       |
                    |     |  "reputation" rules (synchronous cache reads) |
                    |     v                                              |
                    |  Decision { verdict, riskScore, findings,          |
                    |             explanation }  --> AuditStore (chained) |
                    |                           --> persistOutcome()      |
                    +----------------------------------------------------+
                                   ^
                                   |  shared types: @agentguard/core
```

Workspaces (`packages/*`): `core` (shared contracts), `policy` (rules + engine), `sim-evm`, `sim-solana`, `reputation` (address reputation providers + cache), `api`, `sdk`. `examples/` holds the end-to-end demo. The behavioral anomaly layer is an external package (see above).

## Quickstart

Requires Node 22+.

```bash
npm install
npm run build
npm run typecheck
npm run test
npm run demo          # == npx tsx examples/demo.ts (in-process API, mock RPC, no network)
```

The demo runs seven cases through the SDK against the in-process API: (a) small ERC-20 transfer → `allow`, (b) unlimited approve → `block`, (c) call into a never-seen contract → `escalate`, (d) Solana SPL transfer → `allow`, (e) a bounded, under-cap approval whose spender is an EOA rather than a contract (no protocol needs that; it is how a drainer gets `transferFrom` rights) → `block`, (f) transfer whose recipient is on the operator's reputation denylist → `block`, (g) reputation provider outage → `escalate`.

Run the server against real RPC endpoints:

```bash
export AGENTGUARD_EVM_RPC_URL=https://mainnet.base.org
export AGENTGUARD_SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
export AGENTGUARD_API_KEYS=ops-bot:secret-1,treasury:secret-2  # id:key pairs; required when NODE_ENV=production
export AGENTGUARD_AUDIT_SIGNING_KEY=<ed25519 seed hex|base64|pkcs8 pem>  # required in production; dev generates an ephemeral key
export AGENTGUARD_POLICY_FILE=./policy.json           # optional; defaults to conservativeDefaultPolicy
export AGENTGUARD_AUDIT_FILE=./audit.jsonl            # optional; defaults to in-memory
export AGENTGUARD_KNOWN_EVM_CONTRACTS=0xabc...,0xdef... # optional; enables new-contract detection
export AGENTGUARD_KNOWN_SOLANA_PROGRAMS=Tokenkeg...,1111... # optional
export AGENTGUARD_PROFILE_FILE=./profiles.jsonl       # behavior baselines (requires the external @agentguard/behavior package); unset => in-memory, lost on restart
export AGENTGUARD_BEHAVIOR=true                        # false disables the behavior layer and its default-policy rule (no-op when the package is not installed)
export AGENTGUARD_REPUTATION_ALLOWLIST=./allow.json    # optional comma-separated list files (see packages/reputation/data/*.json)
export AGENTGUARD_REPUTATION_DENYLIST=./deny.json      # optional; denylisted addresses are `malicious` => block
export AGENTGUARD_REPUTATION_HTTP_URL=                 # optional external intel feed; {address} {chain} {chainId} are substituted; JSON {verdict,score?,tags?}
export AGENTGUARD_REPUTATION=true                      # false disables the reputation layer and its default-policy rule
export AGENTGUARD_RATE_LIMIT_MAX=120                  # per key per AGENTGUARD_RATE_LIMIT_WINDOW_MS (default 60000); 0 disables
export AGENTGUARD_REQUIRE_SIGNED_REQUESTS=false       # true => every request must carry an HMAC signature (see SECURITY.md)
export AGENTGUARD_BODY_LIMIT_BYTES=65536              # max request body
export AGENTGUARD_TRUST_PROXY=                        # false (default) | true | hop count | CIDR list
export AGENTGUARD_CORS_ORIGINS=                       # unset => CORS disabled
export PORT=8787 LOG_LEVEL=info NODE_ENV=production
node packages/api/dist/main.js
```

See [SECURITY.md](SECURITY.md) for key handling and the deployment hardening checklist, and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the threat model.

## API

### `POST /v1/check`

Headers: `content-type: application/json` (the only accepted type), `x-api-key: <key>` (when keys are configured), optionally `x-agentguard-signature` / `x-agentguard-timestamp` / `x-agentguard-nonce` for HMAC request signing (SDK: `signRequests: true`). All `bigint` fields are decimal strings. Bodies are validated strictly: unknown keys are rejected, `intent.id` must be a UUID, addresses are checked per chain, `description` ≤ 2 KB, `metadata` ≤ 8 KB serialized, calldata ≤ 128 KB, bodies ≤ 64 KB.

Request:

```json
{
  "intent": {
    "id": "3f1c0d1e-5b7a-4c2e-9f3a-1d2e3f4a5b6c",
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

`verdict` is one of `allow`, `block`, `escalate`. If simulation, the engine, the adapter circuit breaker, the reputation prefetch or the behavior profile load fails, the API fails closed with `escalate` and a `simulation_error` / `engine_error` / `adapter_unavailable` / `invalid_decision` / `reputation_error` / `behavior_error` finding; it never returns `allow` on an error path (a `block` from another rule is never downgraded). Every audit record is hash-chained and (when a signing key is configured) Ed25519-signed in its `integrity` field, and carries the submitting key id in `principal`. `explanation` quotes the agent's `description` as an escaped, length-capped JSON string literal labelled "agent's stated purpose", so injected text can never masquerade as a finding.

`simulation.recipients` lists the addresses that receive funds as decoded from calldata / instructions (ERC-20 `transfer` targets, swap recipients, SPL destinations, `SetAuthority` new authorities); the `denylist`, `allowlist_only`, behavior and reputation rules all treat these as counterparties, so a drain cannot hide behind a trusted token contract.

Other routes: `GET /healthz`, `GET /v1/audit/:id`, `GET /v1/audit?agentId=&limit=&cursor=`, `GET /v1/audit/verify?from=&to=&requireSignatures=` (re-walks the hash chain and reports `hash_mismatch` / `broken_link` / `seq_gap` / `bad_signature`). Offline: `npx tsx packages/api/scripts/verify-audit.ts audit.jsonl --public-key pub.pem --require-signatures`.

Errors are always JSON with a `requestId`: `400 bad_request | unsupported_chain`, `401 unauthorized | invalid_signature`, `404 policy_not_found | not_found`, `413 payload_too_large`, `415 unsupported_media_type`, `429 rate_limited` (with `retry-after`), `503 audit_unavailable`, `500 internal_error` (generic body; details only in server logs).

## SDK

```ts
import { AgentGuardClient, guard, GuardBlockedError, GuardEscalatedError } from "@agentguard/sdk";

const client = new AgentGuardClient({
  baseUrl: "https://agentguard.internal",
  apiKey: process.env.AGENTGUARD_KEY,
  signRequests: true, // HMAC-sign every request (timestamp + nonce, 5-minute replay window)
});

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

`client.check(intent, context)` is available for direct use without wrapping a signer. `guard()` fails closed: network errors, 4xx/5xx, malformed responses and exceptions thrown by your hooks all prevent the signer from being called.

## Policy

Policies are JSON, validated by `loadPolicy` from `@agentguard/policy`. Rule kinds: `max_tx_usd`, `max_window_usd`, `allowlist_only`, `denylist`, `no_unlimited_approvals`, `no_eoa_approvals`, `max_slippage_bps`, `no_new_contracts`, `require_simulation_ok`, `max_native_value`, `custom`. `onViolation` is `block` (default) or `escalate`; the strictest firing rule wins. "Unlimited" means any approval ≥ 2^128 base units, or exactly `u64::MAX` / `uint96::MAX`, so bounded-but-astronomical amounts (2^200, Permit2's `uint160` max) are caught too.

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
    { "id": "only-known",    "kind": "allowlist_only",  "params": { "addresses": ["0x3333…", "0x4444…"] } },
    { "id": "behavior",      "kind": "custom", "params": { "fn": "behavior", "escalateAt": 50, "blockAt": 85 } },
    { "id": "reputation",    "kind": "custom", "params": { "fn": "reputation" } }
  ]
}
```

The built-in `conservativeDefaultPolicy` ($100/tx, $500/window, no unlimited or EOA approvals, escalate on new contracts and >0.05 native) is used when no policy file is supplied; the server's bootstrap appends the `reputation` custom rule to it, and the `behavior` rule when the external `@agentguard/behavior` package is installed. A policy file is used verbatim: add the `custom` rules above to opt in (bootstrap logs a warning when a loaded policy omits a rule whose layer is active, and a policy that references a `custom` rule the engine does not have escalates with `engine_error` rather than silently passing).

### Behavior layer (`@agentguard/behavior`, external)

An optional, separately licensed package. Each agent gets a profile learned only from **allowed** decisions (a blocked drain cannot teach the baseline); the rule scores a transaction against that profile synchronously from a store the API warms before `evaluate`, escalating at anomaly ≥ 50 and blocking at ≥ 85 by default (per-rule `params` override). Profiles persist to `AGENTGUARD_PROFILE_FILE` as JSONL with a per-agent hash-chained event log. Wiring details are in [What's open and what's not](#whats-open-and-whats-not); the failure modes (`behavior_error` escalation when the profile cannot be read, persist failures never changing a verdict) are enforced here, in `packages/api`, regardless of which implementation is plugged in.

### Reputation layer (`@agentguard/reputation`)

`ReputationService` fans a lookup out to providers with a per-provider timeout and aggregates with precedence malicious > suspicious > trusted > unknown. Providers: `StaticListProvider` (bundled seed of well-known contracts + operator allow/deny files; deny wins), `OnChainHeuristicsProvider` (EOA vs contract, bytecode size, EIP-1167/1967 proxies, contract age; Solana loader, upgrade authority, program age), `HttpProvider` (generic bounded-and-validated adapter for GoPlus/Blockaid-style APIs). In the default fail-closed mode a provider error or timeout lifts the risk floor, tags the result `provider_error`, and the policy rule escalates regardless of score. Results are LRU-cached with separate TTLs for conclusive, negative and errored lookups. The rule reads the cache synchronously, so the API awaits `prefetch(intent, simulation)` before every evaluate; a cache miss escalates with tag `not_prefetched`.

## Security

Hardening, key handling and the deployment checklist live in [SECURITY.md](SECURITY.md); the attacker models, STRIDE analysis and residual risks are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). The fail-closed invariant is enforced by tests: `packages/api/test/failclosed.test.ts` (adapter/engine/breaker/audit failure matrix), `packages/api/test/integration.test.ts` (behavior/reputation outage, prefetch failure, persist failure) and `packages/api/test/adversarial.test.ts` (prompt injection through `description`/`metadata`, oversized and deeply nested payloads, trailing calldata, 2^256-1 / 2^255 / 2^200 / 2^64-1 approvals, approvals to EOAs, mixed-case denylisted recipients, Solana duplicate ComputeBudget + SetAuthority, HMAC replay, audit-chain tamper, learned-then-drain through the behavior integration (stubbed), and a 200-case seeded fuzz loop asserting no 500s and no `allow` on a failed simulation).

## Roadmap

- Verified-source / TVL / known-exploit feeds as additional reputation providers (the `HttpProvider` adapter is the integration point); per-tenant baselines shared across agents of the same operator.
- SOC 2 controls for the hosted service: retention policies, per-tenant audit scoping, signed policy files, response signing (tamper-evident audit log and key rotation shipped in 0.1).
- Custody integrations: Fireblocks policy-engine hooks and Safe (Gnosis) guard module so AgentGuard sits inline with institutional signing.

## Contributing and license

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md) (build, test, DCO sign-off) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Vulnerabilities go to the process in [SECURITY.md](SECURITY.md), never to a public issue.

AgentGuard is licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attribution. The `@agentguard/behavior` package is proprietary and is not covered by this license.

