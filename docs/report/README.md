# Technical report

`signhold-technical-report.pdf` — *Signhold: Outcome-Based Transaction Guardrails and Behavioral Anomaly Detection for AI Agents Holding Crypto Wallets* (November 2026, v1). LaTeX source alongside.

`evaluation-logs/` holds the raw output behind every number in Section 5: the public test run (353 tests; re-captured after the AgentGuard → Signhold rename, same test files and counts as at `f1cc764`), the 8-case demo including the human-approval sequence of case (h), and the 200-case seeded fuzz run, both at commit `f1cc764`. The drain-demo log is omitted because its explanation text names the proprietary behavioral layer's internal signals; its verdicts and anomaly scores are reported in the paper.
