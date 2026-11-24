# Requirements and traceability
FR-1 One catalogue entry yields Rego, SCP/Config, Azure Policy, GCP Org Policy. FR-2 Fidelity and gaps stated per engine. FR-3 Audit mode on every cloud. FR-4 Time-boxed waivers. FR-5 Evidence per release. FR-6 CI plan check without OPA installed (oracle fallback).
| NFR | Scenario | Target |
|---|---|---|
| Correctness | Any control missing an engine | build fails (parity gate) |
| Safety | New control released | audit mode first; enforce only after gate |
| Limits | SCP size/count | <= 4 bundles, each <= 5120 chars |
| Security | Policy authors | cannot deploy; deployers cannot merge |
| Operability | Mass false positive | revert to audit in minutes via effect/mode switch |
| Traceability | Requirement | design | test |
|---|---|---|
| FR-1, FR-2 | generator, manifest | `test_twelve_controls_four_engines`, parity gate |
| FR-3 | effect param, dryRunSpec, canary OU | rollout wave 1 evidence (pending) |
| FR-6 | `tools/evaluate_plan.py` | `test_plan_cli_exit_codes` |
| Limits | SCP bundling | `test_scp_bundles_respect_aws_limits` |
