# Business case, stakeholders, KPIs
| Activity | CISO | CCoE | Security/GRC | App teams | Audit |
|---|---|---|---|---|---|
| Set risk appetite | A | C | R | I | I |
| Author/maintain controls | C | A/R | C | C | I |
| Approve waivers | C | R | A | C | I |
| Comply / fix findings | I | I | I | A/R | I |
| Review evidence | I | I | R | I | A |
**KPIs (baselines assumed until Wave 1 measures them):** controls with all four engines (target 100%, proven by parity gate); share of full-fidelity mappings (currently reported in `docs/mapping-matrix.md`); policy violations caught in CI vs runtime (target > 80% in CI); open waivers past expiry (target 0); time from approved control to audit mode in all clouds (target < 5 working days).
**Value logic.** The cost of four hand-maintained policy sets is divergence risk and audit effort; the baseline trades some generator complexity for provable consistency. No savings figures are claimed.
