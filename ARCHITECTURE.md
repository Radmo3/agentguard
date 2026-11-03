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
  api/         Fastify HTTP server exposing POST /v1/check, audit log
  sdk/         TypeScript SDK: `guard(signer)` wrapper + thin HTTP client
examples/      end-to-end demo scripts
```

## Request flow

```
agent → sdk.check(intent) → api POST /v1/check
      → adapter.simulate(intent) → SimulationResult
      → policyEngine.evaluate({intent, simulation, context}) → Decision
      → audit.record(...) → response
```

## Shared contracts (packages/core/src/types.ts)

All packages import types from `@agentguard/core`. Do NOT redefine them.
Key types: `Chain`, `TransactionIntent`, `SimulationResult`, `AssetDelta`,
`ApprovalChange`, `PolicyRule`, `PolicySet`, `Decision`, `Verdict`,
`ChainAdapter`, `AgentContext`.

## Conventions

- ESM, `"type": "module"`, TS `NodeNext` resolution, strict mode.
- Tests: vitest, colocated in `test/` per package.
- Amounts: always `bigint` on-chain units + `decimals`; USD values as `number`.
- Never throw from `evaluate`; return a Decision with `verdict: "escalate"` and
  reason `engine_error` instead.
- Each package has its own `package.json` with `build`, `test`, `typecheck`.
- No network calls in unit tests; adapters accept an injectable RPC client.
