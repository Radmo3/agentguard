# Changelog

## Unreleased

- **Cap-bypass experiment harness** (`experiments/cap-bypass/`, private workspace, not published): a simulated reproduction of the I-HITL cap-bypass study (arXiv:2610.35835) with a `baseline` arm and a `signhold` arm (in-process API, operator-held policy, approver-device fixture unreachable from the agent), scripted agents for CI (`npm run experiment:smoke`), Anthropic / OpenAI / OpenAI-compatible model adapters, JSONL results with Wilson intervals and a markdown report. No network, no funds.
- **Renamed the project from AgentGuard to Signhold.** Signhold was briefly published as AgentGuard (Nov 2026) and renamed to avoid a conflict with an unrelated registered trademark. Package scope `@agentguard/*` is now `@signhold/*`, environment variables `AGENTGUARD_*` are now `SIGNHOLD_*`, the request-signing headers `x-agentguard-{signature,timestamp,nonce}` are now `x-signhold-{signature,timestamp,nonce}`, and the SDK classes `AgentGuard*` are now `Signhold*`. No security behaviour, canonical signing string, audit record format or policy semantics changed. Nothing had been published to npm under the old names.

## 0.1.0 (Nov 2026)

- Initial public release (as AgentGuard).
