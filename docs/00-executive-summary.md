# Executive summary
**Problem.** Cloud guardrails are written separately in four dialects (Rego, AWS SCP, Azure Policy, GCP Org Policy). They drift, nobody can prove the same intent is enforced everywhere, and auditors get four stories.
**Approach.** One control catalogue (`controls/definitions.py`) generates all four engines. A parity gate proves every control exists in every engine and states, per engine, whether the mapping is **full**, **partial** or **compensating**. Rollout is audit-first, canary-first, with time-boxed waivers.
**Outcome (targets, to be proven in sandbox).** 12 baseline controls live in audit mode across three clouds, enforced by wave, with evidence generated automatically.
**Honest maturity.** Tier 3 prototype: generator, parity gate, oracle and 79 fixtures run here (8 tests pass). Generated Rego tests, Terraform modules and native policy JSON have **not** been executed against OPA or a cloud in this package; CI workflows are included to produce that evidence.
**Ask.** Approve Wave 0-1 (audit mode in one sandbox scope per cloud).
