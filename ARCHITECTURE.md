# AgentGuard — Architecture

Transaction guardrail layer for AI agents that hold wallets. An agent proposes a
transaction; AgentGuard simulates it, evaluates it against policy, and returns
`allow | block | escalate` with a human-readable explanation and an audit record.

## Monorepo layout (npm workspaces, TypeScript, ESM, Node 22)

```
packages/
  core/        shared types, Decision model, errors, chain-adapter interface
  policy/      chain-agnostic policy engine (rules, evaluation, explanations)
  sim-evm/     EVM adapter: calldata decoding, eth_call simulation, balance/approval diffs (viem)
  sim-solana/  Solana adapter: simulateTransaction, account/token diffs (@solana/web3.js)
  reputation/  address/contract reputation: providers (static lists, on-chain heuristics, HTTP intel),
               fail-closed aggregation, LRU cache with TTLs, `reputation` custom rule
  api/         Fastify HTTP server exposing POST /v1/check, tamper-evident audit log, bootstrap wiring
  sdk/         TypeScript SDK: `guard(signer)` wrapper + thin HTTP client (HMAC signing)
examples/      end-to-end demo scripts

(external)
  @agentguard/behavior   per-agent behavioural baseline, deterministic anomaly scoring,
                         JSONL/in-memory profile stores with hash-chained event log,
                         `behavior` custom rule. Separately licensed; NOT in this repo.
```

`reputation` (here) and `behavior` (external) depend only on `core`. They expose
their rule as a plain function with the engine's `CustomRuleFn` shape; `api`
injects them duck-typed (`ServerOptions.behavior`, `ServerOptions.reputation`) and
`bootstrap` loads them dynamically, so `api` has no compile-time dependency on
either. The behavior package is loaded by name (`@agentguard/behavior`, overridable
via `BootstrapEnv.behaviorModule`) and must export
`createBehaviorIntegration({ profilePath }) => { store, rule, persist }`
(`BehaviorModuleLike` in `packages/api/src/types.ts`); when it is not installed
bootstrap logs a warning and runs without it. `packages/api/test/behavior-stub.ts`
is a minimal implementation of that contract used by the API tests.

## Request flow

```
agent → sdk.check(intent) → api POST /v1/check (auth, HMAC, rate limit, strict schema)
      → adapter.simulate(intent) → SimulationResult            (circuit breaker; failure => escalate)
      → await reputation.prefetch(intent, simulation)         (warms the cache; failure => escalate)
      → await behavior.store.get(context.agentId)             (if installed; warms peek(); failure => escalate)
      → policyEngine.evaluate({intent, simulation, context, policy}) → Decision
            built-in rules + custom rules "behavior" / "reputation" (synchronous cache reads)
      → audit.record(...)                                       (hash chain + Ed25519; failure => 503)
      → await behavior.persist(agentId, intent, simulation, decision)   (failure logged, verdict unchanged)
      → response
```

The two awaits before `evaluate` exist because the engine evaluates rules
synchronously; a rule that performed I/O could not be made fail-closed from
inside the engine. Anything that fails before `evaluate` forces `escalate` on
top of whatever the engine returns (a `block` is never downgraded). Only
allowed decisions shape an agent's baseline; blocked/escalated ones are
appended to its verdict history.

## Shared contracts (packages/core/src/types.ts)

All packages import types from `@agentguard/core`. Do NOT redefine them.
Key types: `Chain`, `TransactionIntent`, `SimulationResult`, `AssetDelta`,
`ApprovalChange`, `PolicyRule`, `PolicySet`, `Decision`, `Verdict`,
`ChainAdapter`, `AgentContext`, `AuditRecord`, `AuditIntegrity`.

`SimulationResult.recipients` (optional) carries decoded fund recipients
(ERC-20 transfer targets, swap recipients, SPL destinations and their owners,
SetAuthority new authorities). `ApprovalChange.spenderIsContract` is `false`
for EOA spenders. `isUnlimitedApproval` treats anything ≥ 2^128, `u64::MAX` or
`uint96::MAX` as unlimited. Adapters MUST populate these; rules MUST treat
`recipients` as counterparties alongside `to` and `contractsTouched`.

## Conventions

- ESM, `"type": "module"`, TS `NodeNext` resolution, strict mode.
- Tests: vitest, colocated in `test/` per package.
- Amounts: always `bigint` on-chain units + `decimals`; USD values as `number`.
- Never throw from `evaluate`; return a Decision with `verdict: "escalate"` and
  reason `engine_error` instead.
- Custom rules are synchronous and read only from caches warmed by the API
  before `evaluate`; a cache miss must produce `escalate`, never `null`.
- Untrusted text (`description`, `metadata`, provider tags/evidence) is data:
  strip control characters and cap length before it reaches an explanation,
  and never let it influence a verdict.
- Each package has its own `package.json` with `build`, `test`, `typecheck`.
- No network calls in unit tests; adapters accept an injectable RPC client.
