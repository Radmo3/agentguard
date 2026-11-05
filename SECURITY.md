# Security Policy

AgentGuard sits between AI agents and the wallets they control. A bug here can
turn into a drained treasury, so security is the product's top priority and
every change in `packages/api`, `packages/sdk` and `packages/core` is reviewed
with that in mind. The threat model lives in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Reporting a vulnerability

- Email **security@agentguard.dev** (PGP key fingerprint published at `/.well-known/security.txt` on the hosted service). Do not open a public issue.
- Include: affected package and version, a minimal reproduction, the impact you believe it has (e.g. "allow verdict for a tx that should block"), and whether it is being exploited.
- We acknowledge within **2 business days**, give a severity assessment within **5 business days**, and aim to ship a fix for Critical/High issues within **14 days**. We coordinate disclosure with you and credit reporters who want credit.
- Safe harbour: good-faith research against your own deployment, or against the hosted staging environment, will not be pursued legally. Do not test against other customers' tenants or attempt to access data you do not own.

Severity guide (what we treat as Critical): anything that makes the API return
`allow` for a transaction that policy would otherwise block or escalate; audit
record forgery or silent deletion; API key or signing key disclosure; remote code execution.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x (current `main`) | Yes: security fixes land here |
| < 0.1 | No |

We support the latest minor release. Node **22+** is required; older Node
versions lack the `crypto.subtle`/`timingSafeEqual` behaviour we rely on and are not supported.

## Key handling

AgentGuard has three kinds of secrets. None of them are ever logged above
`debug` level, returned in error responses, or kept in plaintext in memory
longer than needed.

### API keys (`AGENTGUARD_API_KEYS`)

- Format: comma-separated `id:key` entries (`ops-bot:9f3c…,treasury:1ab2…`). The id is recorded in every audit record and log line; the key never is. Bare keys are accepted and get an id derived from a fingerprint.
- Keys are SHA-256 hashed at startup (`packages/api/src/auth.ts`, `ApiKeyring`) and the raw value is discarded. Comparison is `crypto.timingSafeEqual` on the hash with no early exit, so timing does not reveal which key (if any) matched.
- Generate keys with at least 256 bits of entropy: `openssl rand -hex 32`.
- Rotation: add the new `id:key`, restart (or roll the deployment), update clients, remove the old entry, restart. Because ids are stable you can rotate a key without losing audit attribution.
- The server **refuses to start** with `NODE_ENV=production` and no keys.

### Request signing secrets (optional, `signRequests` in the SDK)

- HMAC-SHA256 over `v1\n<timestamp>\n<nonce>\n<METHOD>\n<path?query>\n<sha256(body)>`, sent as `x-agentguard-signature: v1=<hex>` with `x-agentguard-timestamp` (unix ms) and `x-agentguard-nonce`.
- The HMAC key is `sha256(secret)`, so the server stores only that derived value. By default the API key doubles as the signing secret; a dedicated secret can be configured per key via `ServerOptions.apiKeys[].signingSecret`.
- Replay window is 5 minutes (`AGENTGUARD_SIGNING_WINDOW_MS`); nonces are cached per key for the window. Set `AGENTGUARD_REQUIRE_SIGNED_REQUESTS=true` to reject unsigned requests.

### Audit signing key (`AGENTGUARD_AUDIT_SIGNING_KEY`)

- Ed25519 private key as a 32-byte seed (hex or base64) or PKCS#8 PEM. Every audit record's chain hash is signed; the public key fingerprint (`keyId`) is embedded in the record.
- Required in production. In development an ephemeral key is generated and its `keyId` logged; records signed with it cannot be verified after a restart.
- Keep the private key in a secrets manager or HSM-backed env injection, never in the policy file or repo. Publish the public key (`AGENTGUARD_AUDIT_PUBLIC_KEYS` accepts extra verification keys for rotation) so auditors can verify exports offline with `packages/api/scripts/verify-audit.ts`.
- Generate: `node -e "const{generateKeyPairSync}=require('crypto');const k=generateKeyPairSync('ed25519');console.log(k.privateKey.export({type:'pkcs8',format:'pem'}));console.log(k.publicKey.export({type:'spki',format:'pem'}))"`.

## Deployment hardening checklist

Before exposing an AgentGuard API to agents that control real funds:

- [ ] `NODE_ENV=production` (enforces API keys and an audit signing key at boot).
- [ ] `AGENTGUARD_API_KEYS` set with per-client `id:key` entries, 256-bit keys, one key per agent/service. Never share a key between agents: the key id is your attribution in the audit log.
- [ ] `AGENTGUARD_AUDIT_SIGNING_KEY` provisioned from a secrets manager; public key archived separately.
- [ ] `AGENTGUARD_AUDIT_FILE` on durable, append-only storage (or ship JSONL lines to WORM object storage). Run `verify-audit.ts` on a schedule and alert on failure.
- [ ] TLS terminated in front of the API (the server speaks plain HTTP). If a proxy sets `x-forwarded-for`, set `AGENTGUARD_TRUST_PROXY` to the proxy's CIDR or hop count, never `true` on an open network: it governs per-IP rate limiting.
- [ ] Rate limits sized for your agents (`AGENTGUARD_RATE_LIMIT_MAX` per `AGENTGUARD_RATE_LIMIT_WINDOW_MS`); they are on by default at 120/min per key.
- [ ] Body limit left at 64 KiB unless you have a documented need (`AGENTGUARD_BODY_LIMIT_BYTES`).
- [ ] CORS left off (`AGENTGUARD_CORS_ORIGINS` unset) unless a browser dashboard needs it; then list exact origins.
- [ ] `AGENTGUARD_REQUIRE_SIGNED_REQUESTS=true` and SDK `signRequests: true` wherever the network path between agent and API is not fully trusted.
- [ ] RPC endpoints (`AGENTGUARD_EVM_RPC_URL`, `AGENTGUARD_SOLANA_RPC_URL`) are ones you operate or contractually trust; a lying RPC can make a drain simulate clean. Prefer private endpoints and pin them in the policy review.
- [ ] Policy file reviewed and version-bumped on every change; `allowlist_only` enabled for production agents.
- [ ] `LOG_LEVEL=info` or higher in production. `debug` emits calldata and raw transactions.
- [ ] Circuit breaker thresholds (`AGENTGUARD_ADAPTER_FAILURE_THRESHOLD`, `AGENTGUARD_ADAPTER_RESET_MS`, `AGENTGUARD_ADAPTER_TIMEOUT_MS`) reviewed; when open, every check escalates (never allows).
- [ ] Process runs as an unprivileged user with a read-only filesystem except the audit path; no shell in the container image.
- [ ] Graceful shutdown wired to your orchestrator (SIGTERM; in-flight checks drain for `AGENTGUARD_SHUTDOWN_GRACE_MS`, default 10 s). Never SIGKILL a pod with checks in flight if you can avoid it: the agent will see a network error and (correctly) refuse to sign.
- [ ] On the agent side: wrap the signer with `guard()`; never give the agent a code path that bypasses it; treat every `AgentGuardClientError` as "do not sign".
- [ ] `npm audit --omit=dev --audit-level=high` and `scripts/lockfile-lint.mjs` pass in CI; `.audit-exceptions.json` entries are reviewed before their `until` date.
- [ ] If you run the external `@agentguard/behavior` package: `AGENTGUARD_PROFILE_FILE` on durable storage with the same protections as the audit file (an attacker who can rewrite a profile can teach the baseline), and verify per-agent event chains with that package's `verifyEventChain` if you suspect tampering.
- [ ] `AGENTGUARD_REPUTATION_DENYLIST` maintained from your incident process; `AGENTGUARD_REPUTATION_HTTP_URL` points only at feeds you contractually trust, over TLS. Provider outages escalate every check (fail closed), so alert on `provider_error` in findings rather than loosening `failMode`.
- [ ] Leave `AGENTGUARD_REPUTATION` on (and `AGENTGUARD_BEHAVIOR`, when the external behavior package is installed); if you load your own policy file, add the `reputation` (and `behavior`) custom rules to it (bootstrap warns when a loaded policy omits a rule whose layer is active).

## What the API guarantees

- **Fail closed.** Any exception in simulation, policy evaluation, the circuit breaker, the reputation prefetch, the behavior profile load (when a behavior integration is plugged in via `ServerOptions.behavior`) or response validation produces `escalate`, never `allow`, and never downgrades a `block`. If the audit store cannot record a decision the API returns `503 audit_unavailable` and no verdict at all. A behavior-profile write failure after the audit record is sealed is logged and does not alter the verdict. These guarantees live in `packages/api` and hold for any behavior implementation, including the separately licensed `@agentguard/behavior` package and the test stub.
- **Untrusted text cannot steer a verdict.** `description` and `metadata` never feed a rule (except the documented `metadata.expectedOutUsd` slippage hint, which can only make the check stricter) and reach the explanation only as an escaped, control-character-stripped, length-capped JSON string literal.
- **Tamper evidence.** Every audit record carries `integrity: { seq, prevHash, hash, alg, signature?, keyId? }`. `hash` is SHA-256 over canonical JSON (sorted keys, bigints as strings) of the record plus `seq`/`prevHash`. `GET /v1/audit/verify?from=&to=` and `scripts/verify-audit.ts` re-walk the chain.
- **No secrets in logs or responses.** `createRedactingLogger` strips api keys, signatures, calldata, raw transactions and metadata from every level above `debug`. 5xx responses are a fixed body plus `requestId`.
- **Strict input.** Unknown keys rejected, intent ids must be UUIDs, addresses validated per chain, bounded string lengths, no NaN/Infinity, JSON only, 64 KiB bodies.
