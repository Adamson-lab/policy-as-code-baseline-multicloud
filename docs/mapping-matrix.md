# 1:1 control mapping matrix (generated)

Every control exists in all four engines. Fidelity is stated honestly: **full** = same enforcement semantics, **partial** = same intent with a documented gap, **compensating** = no native preventive equivalent, so a detective or structural control is used.

| ID | Control | Severity | OPA/Rego (Terraform plan) | AWS (SCP / Config) | Azure Policy | GCP Org Policy |
|---|---|---|---|---|---|---|
| PAC-001 | Block public object storage | critical | 6 rules | preventive / partial | preventive / full | preventive / full |
| PAC-002 | Customer-managed keys for data at rest | high | 4 rules | preventive / partial | preventive / full | preventive / full |
| PAC-003 | Approved regions only | high | 3 rules | preventive / full | preventive / full | preventive / full |
| PAC-004 | No public IPs on compute | critical | 3 rules | preventive / partial | preventive / full | preventive / full |
| PAC-005 | Encryption in transit (TLS 1.2+) | high | 3 rules | preventive / partial | preventive / partial | preventive / full |
| PAC-006 | No long-lived credentials | critical | 3 rules | preventive / full | preventive / partial | preventive / full |
| PAC-007 | Protect audit logging | critical | 4 rules | preventive / full | detective / partial | compensating / compensating |
| PAC-008 | Mandatory cost-center tag | medium | 3 rules | preventive / partial | preventive / full | custom-constraint / partial |
| PAC-009 | No public database endpoints | critical | 3 rules | detective / compensating | preventive / full | preventive / full |
| PAC-010 | No world-open ingress | critical | 4 rules | detective / compensating | preventive / full | custom-constraint / partial |
| PAC-011 | Hardened instance access | high | 3 rules | preventive / partial | preventive / partial | preventive / partial |
| PAC-012 | No default network | medium | 3 rules | preventive / full | detective / partial | preventive / full |

Fidelity totals across 36 cloud-native mappings: compensating 3, full 19, partial 14.

## Documented gaps

- **PAC-001 aws**: SCP protects the guardrail but cannot assert bucket values at create time; pair with Config rule s3-bucket-level-public-access-prohibited.
- **PAC-002 aws**: SCP forces encryption, not a customer-managed key; KMS key policy and Config rule encrypted-volumes complete the intent.
- **PAC-004 aws**: Covers launch-time public IPs; Elastic IP association needs a second statement or Config rule.
- **PAC-005 aws**: SCP condition applies to S3 requests; load balancer listeners are covered by the Rego gate and Config rule alb-http-to-https-redirection-check.
- **PAC-005 azure**: Policy covers storage accounts; App Service and others need their own aliases.
- **PAC-006 azure**: Azure has no org-wide key-creation switch; this covers storage shared keys. Entra app secrets need a separate governance process.
- **PAC-007 azure**: Azure Policy cannot deny deletion of diagnostic settings; compensate with resource locks and deny assignments.
- **PAC-007 gcp**: No Org Policy constraint protects audit logs; use an org-level aggregated sink plus IAM so only the platform group can edit it.
- **PAC-008 aws**: Only services that support tag-on-create; see project 3 for detect and correct layers.
- **PAC-008 gcp**: Custom constraints cover a limited set of resource types; validate CEL in a lab org first.
- **PAC-009 aws**: No SCP condition key exists for RDS PubliclyAccessible; Config rule plus auto-remediation and the Rego gate compensate.
- **PAC-010 aws**: Security-group CIDRs are not SCP condition keys; detective rule with auto-remediation plus the Rego gate.
- **PAC-010 gcp**: Validate CEL against firewall resource schema in a lab org before enforcing.
- **PAC-011 aws**: Same intent, different mechanism per cloud (IMDSv2 vs SSH passwords vs OS Login).
- **PAC-011 azure**: Same intent, different mechanism per cloud.
- **PAC-011 gcp**: Same intent, different mechanism per cloud.
- **PAC-012 azure**: Azure has no default VNet; the equivalent risk is implicit outbound access, audited via subnet property.

## Framework mapping (indicative, GRC review pending)

| ID | NIST 800-53 | CIS v8 | ISO 27001:2022 |
|---|---|---|---|
| PAC-001 | AC-3, AC-6 | 3.3 | A.8.3 |
| PAC-002 | SC-28, SC-12 | 3.11 | A.8.24 |
| PAC-003 | SA-9, SC-7 | 3.1 | A.5.23 |
| PAC-004 | SC-7, AC-4 | 12.2 | A.8.20 |
| PAC-005 | SC-8, SC-13 | 3.10 | A.8.24 |
| PAC-006 | IA-5, AC-2 | 5.2 | A.5.17 |
| PAC-007 | AU-2, AU-9 | 8.2 | A.8.15 |
| PAC-008 | CM-8 | 1.1 | A.5.9 |
| PAC-009 | SC-7, AC-4 | 12.2 | A.8.20 |
| PAC-010 | SC-7, CM-7 | 4.4, 12.2 | A.8.20 |
| PAC-011 | AC-17, IA-2 | 5.4, 6.3 | A.8.5 |
| PAC-012 | CM-6, SC-7 | 4.1 | A.8.9 |
