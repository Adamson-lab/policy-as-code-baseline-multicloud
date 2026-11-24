# Test strategy and evidence
Executed here: 8 unit tests, 79 auto-generated fixtures through the Python oracle, structural parity gate, SCP size/count checks, plan CLI exit codes (`evidence/`).
Generated but **not executed here**: 79 Rego tests (`policies/rego/*_test.rego`) need `opa test` (CI job `opa`). Terraform modules need `terraform validate` (CI job `terraform`).
Pending: behavioural tests of native policies in live sandboxes (can a non-compliant resource actually be created?), chaos on break-glass, rollback drills.
