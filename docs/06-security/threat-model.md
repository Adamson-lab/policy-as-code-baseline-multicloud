# Threat model (STRIDE) for the policy plane
See diagrams 16 (identity) and 17 (threats).
| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | Malicious PR weakens a control | code owners, two reviewers, parity gate, signed releases | Low |
| T2 | Break-glass abuse | MFA, alarm on use, 24h expiry, 2-day review | Medium |
| T3 | Guardrail detached via API | org-level deny on policy APIs, alarms on policy changes | Medium |
| T4 | Stale exemption | max 90 days, expiry sweeper, recertification | Low |
| T5 | Pipeline credential theft | OIDC, protected environments, no stored keys (PAC-006 applies to itself) | Low |
Control mapping is indicative (NIST CM-6, AC-6, AU-9; CIS 4.1, 5.4; ISO A.8.9, A.8.15); GRC review pending.
