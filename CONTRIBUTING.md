# Contributing to AgentGuard

Thanks for helping make agent wallets safer. This document covers how to build and test the project, how to send changes, and where security issues go.

## Security issues

**Do not open a public issue or pull request for a vulnerability.** Follow the reporting process in [SECURITY.md](SECURITY.md). Anything that could let a transaction be `allow`ed when it should not be, bypass the audit chain, or leak keys is a security issue, even if it looks like a plain bug.

## Getting started

Requires Node 22+ and npm 10+.

```bash
git clone <your fork>
cd agentguard
npm ci
npm run build        # tsc for every workspace, in dependency order
npm run typecheck
npm test             # vitest, no network access needed
npm run demo         # end-to-end demo against in-process API + mock RPC
```

Hygiene checks that CI also runs:

```bash
node scripts/lockfile-lint.mjs                                   # registry allowlist, https, integrity hashes
node scripts/check-pinned.mjs packages/api packages/sdk packages/core   # exact versions in security-owned packages
npm audit --omit=dev --audit-level=high || node scripts/audit-exceptions.mjs
```

## Repository layout

See [ARCHITECTURE.md](ARCHITECTURE.md). The short version: `packages/core` holds the shared types (never redefine them), `packages/policy` the rule engine, `packages/sim-evm` / `packages/sim-solana` the chain adapters, `packages/reputation` the counterparty reputation layer, `packages/api` the HTTP service, `packages/sdk` the client. `examples/` has the demo.

The behavioral anomaly layer (`@agentguard/behavior`) is a separately licensed package that is **not** in this repository. It plugs in through `ServerOptions.behavior` and the `createBehaviorIntegration` factory contract in `packages/api/src/types.ts`; the API tests exercise that contract with an in-test stub (`packages/api/test/behavior-stub.ts`).

## Ground rules for changes

- **Fail closed, always.** Nothing on an error path may produce `allow`, and nothing may downgrade a `block`. If you touch `packages/api/src/server.ts`, `packages/policy/src/engine.ts` or an adapter, extend `failclosed.test.ts` / `adversarial.test.ts` to cover the new path.
- **Untrusted text is data.** `description`, `metadata` and anything from an RPC or an intel feed never influences a verdict and is escaped and length-capped before it reaches an explanation or a log.
- **No network in unit tests.** Adapters take an injectable client; tests use in-memory mocks.
- **Pin what matters.** Dependencies of `api`, `sdk` and `core` use exact versions. New runtime dependencies need a one-line justification in the PR.
- **Conventions.** ESM, TypeScript strict, `NodeNext` resolution, `bigint` for on-chain amounts, `number` for USD. Tests live in `test/` next to the package they cover.

## Sending a pull request

1. Fork, branch from `master`, keep the change focused (one logical change per PR).
2. `npm run build && npm run typecheck && npm test && npm run demo` must pass locally.
3. Add or update tests. A PR that changes a verdict path without a test will be sent back.
4. Update docs that the change affects (README, ARCHITECTURE, SECURITY, THREAT_MODEL).
5. Write a clear description: what, why, and how you verified it. Reference issues with `Fixes #123`.

### Developer Certificate of Origin

By contributing you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the change or otherwise have the right to submit it under the Apache-2.0 license. Sign off each commit to say so:

```
git commit -s -m "policy: tighten slippage default"
```

which adds a `Signed-off-by: Your Name <you@example.com>` trailer. Commits without a sign-off cannot be merged.

## Reviews and merging

Maintainers review for correctness, security impact and test coverage, in that order. Expect questions about fail-closed behaviour on any change to the request pipeline. Squash merges are the default; the PR title becomes the commit subject, so keep it descriptive (`api: ...`, `policy: ...`, `sim-evm: ...`).

## License

By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
