# Risk register
| ID | Risk | L | I | Owner | Mitigation | Residual |
|---|---|---|---|---|---|---|
| R-01 | Enforce breaks production workloads | M | H | CCoE | audit first, canary, waves, impact report | M |
| R-02 | Break-glass bypass abused | L | H | Security | MFA, alarm, review | M |
| R-03 | Generated Rego diverges from native intent | M | M | CCoE | parity gate, oracle, live sandbox tests (pending) | M |
| R-04 | Native engines change semantics (new aliases, constraints) | M | M | CCoE | quarterly review, version pins | L |
| R-05 | False sense of coverage from partial mappings | M | H | Architecture | fidelity ratings published, gaps in matrix | L |
Exit/portability: definitions are provider-neutral data; any engine can be replaced by changing its generator.
