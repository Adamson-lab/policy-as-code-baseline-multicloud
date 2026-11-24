"""SINGLE SOURCE OF TRUTH: 12 baseline controls, each mapped 1:1 to OPA/Rego (Terraform plan), AWS SCP/Config, Azure Policy, GCP Org Policy.
Edit here, run `python3 tools/build_policies.py`, commit generated artifacts. Fidelity is stated honestly per engine."""
AWS_REGIONS = ["us-east-1", "us-east-2", "eu-west-1", "eu-central-1"]
AZ_REGIONS = ["eastus", "eastus2", "westeurope", "northeurope"]
GCP_LOCS = ["US", "EU", "US-EAST1", "US-CENTRAL1", "EUROPE-WEST1"]
PLAT = {"ArnNotLike": {"aws:PrincipalArn": ["arn:aws:iam::*:role/pac-platform-admin"]}}


def T(type_, attr, op, val=None, miss=False):
    return dict(type=type_, attr=attr, op=op, val=val, miss=miss)


def scp(*stmts):
    return dict(kind="preventive", artifact={"Version": "2012-10-17", "Statement": list(stmts)})


def az(rule, effects=("Audit", "Deny", "Disabled"), default="Audit", details=None, mode="All", kind="preventive"):
    return dict(kind=kind, rule=rule, effects=list(effects), default=default, details=details, mode=mode)


def gbool(c):
    return dict(kind="preventive", constraint=c, policy={"name": f"organizations/ORG_ID/policies/{c}", "spec": {"rules": [{"enforce": True}]}})


def glist(c, allowed=None, denied=None, deny_all=False):
    v = {"denyAll": True} if deny_all else {"values": ({"allowedValues": allowed} if allowed else {"deniedValues": denied})}
    return dict(kind="preventive", constraint=c, policy={"name": f"organizations/ORG_ID/policies/{c}", "spec": {"rules": [v]}})


def F(**k):
    return k


CONTROLS = [
dict(id="PAC-001", title="Block public object storage", severity="critical", intent="Object storage is never readable by the anonymous internet.",
     fw={"NIST 800-53": ["AC-3", "AC-6"], "CIS v8": ["3.3"], "ISO 27001": ["A.8.3"]},
     tf=[T("aws_s3_bucket_public_access_block", a, "eq", True) for a in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")] +
        [T("azurerm_storage_account", "allow_nested_items_to_be_public", "eq", False), T("google_storage_bucket", "public_access_prevention", "eq", "enforced")],
     aws=dict(scp({"Sid": "PAC001ProtectPublicAccessBlock", "Effect": "Deny", "Action": ["s3:PutAccountPublicAccessBlock", "s3:PutBucketPublicAccessBlock", "s3:DeleteBucketPublicAccessBlock"], "Resource": "*", "Condition": PLAT}),
              fidelity="partial", gap="SCP protects the guardrail but cannot assert bucket values at create time; pair with Config rule s3-bucket-level-public-access-prohibited."),
     azure=dict(az({"allOf": [{"field": "type", "equals": "Microsoft.Storage/storageAccounts"}, {"field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", "notEquals": False}]}), fidelity="full"),
     gcp=dict(gbool("storage.publicAccessPrevention"), fidelity="full")),
dict(id="PAC-002", title="Customer-managed keys for data at rest", severity="high", intent="Regulated data stores use keys the organization controls.",
     fw={"NIST 800-53": ["SC-28", "SC-12"], "CIS v8": ["3.11"], "ISO 27001": ["A.8.24"]},
     tf=[T("aws_ebs_volume", "encrypted", "eq", True), T("aws_db_instance", "storage_encrypted", "eq", True), T("azurerm_managed_disk", "disk_encryption_set_id", "exists"), T("google_storage_bucket", "encryption.0.default_kms_key_name", "exists")],
     aws=dict(scp({"Sid": "PAC002RequireEbsEncryption", "Effect": "Deny", "Action": "ec2:CreateVolume", "Resource": "*", "Condition": {"Bool": {"ec2:Encrypted": "false"}}},
                  {"Sid": "PAC002RequireRdsEncryption", "Effect": "Deny", "Action": "rds:CreateDBInstance", "Resource": "*", "Condition": {"Bool": {"rds:StorageEncrypted": "false"}}}),
              fidelity="partial", gap="SCP forces encryption, not a customer-managed key; KMS key policy and Config rule encrypted-volumes complete the intent."),
     azure=dict(az({"allOf": [{"field": "type", "equals": "Microsoft.Storage/storageAccounts"}, {"field": "Microsoft.Storage/storageAccounts/encryption.keySource", "notEquals": "Microsoft.Keyvault"}]}), fidelity="full"),
     gcp=dict(glist("gcp.restrictNonCmekServices", denied=["storage.googleapis.com", "bigquery.googleapis.com", "compute.googleapis.com"]), fidelity="full")),
dict(id="PAC-003", title="Approved regions only", severity="high", intent="Workloads and data stay in approved jurisdictions.",
     fw={"NIST 800-53": ["SA-9", "SC-7"], "CIS v8": ["3.1"], "ISO 27001": ["A.5.23"]},
     tf=[T("provider:aws", "region", "in", AWS_REGIONS), T("azurerm_resource_group", "location", "in", AZ_REGIONS), T("google_storage_bucket", "location", "in", GCP_LOCS)],
     aws=dict(scp({"Sid": "PAC003DenyNonApprovedRegions", "Effect": "Deny", "NotAction": ["iam:*", "organizations:*", "route53:*", "cloudfront:*", "support:*", "sts:*"], "Resource": "*", "Condition": {"StringNotEquals": {"aws:RequestedRegion": AWS_REGIONS}}}), fidelity="full"),
     azure=dict(az({"allOf": [{"field": "location", "notIn": AZ_REGIONS + ["global"]}]}), fidelity="full"),
     gcp=dict(glist("gcp.resourceLocations", allowed=["in:us-locations", "in:eu-locations"]), fidelity="full")),
dict(id="PAC-004", title="No public IPs on compute", severity="critical", intent="Compute is reachable only through approved ingress paths.",
     fw={"NIST 800-53": ["SC-7", "AC-4"], "CIS v8": ["12.2"], "ISO 27001": ["A.8.20"]},
     tf=[T("aws_instance", "associate_public_ip_address", "eq", False), T("azurerm_public_ip", "id", "forbid"), T("google_compute_instance", "network_interface.0.access_config", "absent")],
     aws=dict(scp({"Sid": "PAC004DenyPublicIpOnLaunch", "Effect": "Deny", "Action": "ec2:RunInstances", "Resource": "arn:aws:ec2:*:*:network-interface/*", "Condition": {"Bool": {"ec2:AssociatePublicIpAddress": "true"}}}),
              fidelity="partial", gap="Covers launch-time public IPs; Elastic IP association needs a second statement or Config rule."),
     azure=dict(az({"allOf": [{"field": "type", "equals": "Microsoft.Network/networkInterfaces"}, {"field": "Microsoft.Network/networkInterfaces/ipconfigurations[*].publicIpAddress.id", "exists": True}]}), fidelity="full"),
     gcp=dict(glist("compute.vmExternalIpAccess", deny_all=True), fidelity="full")),
dict(id="PAC-005", title="Encryption in transit (TLS 1.2+)", severity="high", intent="No plaintext or legacy-TLS paths to data services.",
     fw={"NIST 800-53": ["SC-8", "SC-13"], "CIS v8": ["3.10"], "ISO 27001": ["A.8.24"]},
     tf=[T("aws_lb_listener", "protocol", "in", ["HTTPS", "TLS"]), T("azurerm_storage_account", "enable_https_traffic_only", "eq", True, miss=True), T("google_compute_ssl_policy", "min_tls_version", "in", ["TLS_1_2"])],
     aws=dict(scp({"Sid": "PAC005DenyInsecureTransport", "Effect": "Deny", "Action": "s3:*", "Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}), fidelity="partial", gap="SCP condition applies to S3 requests; load balancer listeners are covered by the Rego gate and Config rule alb-http-to-https-redirection-check."),
     azure=dict(az({"allOf": [{"field": "type", "equals": "Microsoft.Storage/storageAccounts"}, {"field": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly", "notEquals": True}]}), fidelity="partial", gap="Policy covers storage accounts; App Service and others need their own aliases."),
     gcp=dict(glist("gcp.restrictTLSVersion", denied=["TLS_VERSION_1", "TLS_VERSION_1_1"]), fidelity="full")),
dict(id="PAC-006", title="No long-lived credentials", severity="critical", intent="Workloads authenticate with short-lived, federated identity.",
     fw={"NIST 800-53": ["IA-5", "AC-2"], "CIS v8": ["5.2"], "ISO 27001": ["A.5.17"]},
     tf=[T("aws_iam_access_key", "id", "forbid"), T("azurerm_storage_account", "shared_access_key_enabled", "eq", False), T("google_service_account_key", "id", "forbid")],
     aws=dict(scp({"Sid": "PAC006DenyAccessKeyCreation", "Effect": "Deny", "Action": ["iam:CreateAccessKey"], "Resource": "*", "Condition": PLAT}), fidelity="full"),
     azure=dict(az({"allOf": [{"field": "type", "equals": "Microsoft.Storage/storageAccounts"}, {"field": "Microsoft.Storage/storageAccounts/allowSharedKeyAccess", "notEquals": False}]}), fidelity="partial", gap="Azure has no org-wide key-creation switch; this covers storage shared keys. Entra app secrets need a separate governance process."),
     gcp=dict(gbool("iam.disableServiceAccountKeyCreation"), fidelity="full")),
dict(id="PAC-007", title="Protect audit logging", severity="critical", intent="Audit trails cannot be switched off or bypassed.",
     fw={"NIST 800-53": ["AU-2", "AU-9"], "CIS v8": ["8.2"], "ISO 27001": ["A.8.15"]},
     tf=[T("aws_cloudtrail", "is_multi_region_trail", "eq", True), T("aws_cloudtrail", "enable_log_file_validation", "eq", True), T("azurerm_monitor_diagnostic_setting", "log_analytics_workspace_id", "exists"), T("google_project_iam_audit_config", "service", "eq", "allServices")],
     aws=dict(scp({"Sid": "PAC007ProtectCloudTrail", "Effect": "Deny", "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors"], "Resource": "*", "Condition": PLAT}), fidelity="full"),
     azure=dict(az({"field": "type", "equals": "Microsoft.Resources/subscriptions"}, effects=("AuditIfNotExists", "Disabled"), default="AuditIfNotExists",
                   details={"type": "Microsoft.Insights/diagnosticSettings", "existenceCondition": {"field": "Microsoft.Insights/diagnosticSettings/logs.enabled", "equals": "true"}}, kind="detective"),
                fidelity="partial", gap="Azure Policy cannot deny deletion of diagnostic settings; compensate with resource locks and deny assignments."),
     gcp=dict(kind="compensating", artifact={"aggregatedSink": {"parent": "organizations/ORG_ID", "includeChildren": True, "destination": "storage.googleapis.com/ORG_AUDIT_BUCKET"},
                                              "auditConfig": {"service": "allServices", "logTypes": ["ADMIN_READ", "DATA_READ", "DATA_WRITE"]}},
              fidelity="compensating", gap="No Org Policy constraint protects audit logs; use an org-level aggregated sink plus IAM so only the platform group can edit it.")),
dict(id="PAC-008", title="Mandatory cost-center tag", severity="medium", intent="Every resource is attributable to a cost owner.",
     fw={"NIST 800-53": ["CM-8"], "CIS v8": ["1.1"], "ISO 27001": ["A.5.9"]},
     tf=[T("aws_s3_bucket", "tags_all.cost-center", "exists"), T("azurerm_resource_group", "tags.cost-center", "exists"), T("google_compute_instance", "labels.cost-center", "exists")],
     aws=dict(scp({"Sid": "PAC008RequireCostCenterTag", "Effect": "Deny", "Action": ["ec2:RunInstances", "rds:CreateDBInstance", "s3:CreateBucket"], "Resource": "*", "Condition": {"Null": {"aws:RequestTag/cost-center": "true"}}}), fidelity="partial", gap="Only services that support tag-on-create; see project 3 for detect and correct layers."),
     azure=dict(az({"field": "tags['cost-center']", "exists": False}, mode="Indexed"), fidelity="full"),
     gcp=dict(kind="custom-constraint", constraint="custom.pac008RequireCostCenterLabel",
              artifact={"constraint": {"name": "organizations/ORG_ID/customConstraints/custom.pac008RequireCostCenterLabel", "resourceTypes": ["compute.googleapis.com/Instance"], "methodTypes": ["CREATE"], "condition": "resource.labels.exists(k, k == 'cost-center')", "actionType": "ALLOW", "displayName": "PAC-008 require cost-center label"},
                        "policy": {"name": "organizations/ORG_ID/policies/custom.pac008RequireCostCenterLabel", "spec": {"rules": [{"enforce": True}]}}},
              fidelity="partial", gap="Custom constraints cover a limited set of resource types; validate CEL in a lab org first.")),
dict(id="PAC-009", title="No public database endpoints", severity="critical", intent="Databases are reachable only on private paths.",
     fw={"NIST 800-53": ["SC-7", "AC-4"], "CIS v8": ["12.2"], "ISO 27001": ["A.8.20"]},
     tf=[T("aws_db_instance", "publicly_accessible", "eq", False, miss=True), T("azurerm_mssql_server", "public_network_access_enabled", "eq", False), T("google_sql_database_instance", "settings.0.ip_configuration.0.ipv4_enabled", "eq", False)],
     aws=dict(kind="detective", artifact={"ConfigRuleName": "pac-009-rds-public-access", "Source": {"Owner": "AWS", "SourceIdentifier": "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"}, "Scope": {"ComplianceResourceTypes": ["AWS::RDS::DBInstance"]}},
              fidelity="compensating", gap="No SCP condition key exists for RDS PubliclyAccessible; Config rule plus auto-remediation and the Rego gate compensate."),
     azure=dict(az({"allOf": [{"field": "type", "equals": "Microsoft.Sql/servers"}, {"field": "Microsoft.Sql/servers/publicNetworkAccess", "notEquals": "Disabled"}]}), fidelity="full"),
     gcp=dict(gbool("sql.restrictPublicIp"), fidelity="full")),
dict(id="PAC-010", title="No world-open ingress", severity="critical", intent="No management or data ports are open to the internet.",
     fw={"NIST 800-53": ["SC-7", "CM-7"], "CIS v8": ["4.4", "12.2"], "ISO 27001": ["A.8.20"]},
     tf=[T("aws_vpc_security_group_ingress_rule", "cidr_ipv4", "ne", "0.0.0.0/0"), T("azurerm_network_security_rule", "source_address_prefix", "ne", "*"), T("azurerm_network_security_rule", "source_address_prefix", "ne", "0.0.0.0/0"), T("google_compute_firewall", "source_ranges", "not_contains", "0.0.0.0/0")],
     aws=dict(kind="detective", artifact={"ConfigRuleName": "pac-010-restricted-ingress", "Source": {"Owner": "AWS", "SourceIdentifier": "RESTRICTED_INCOMING_TRAFFIC"}, "InputParameters": {"blockedPort1": "22", "blockedPort2": "3389"}, "Scope": {"ComplianceResourceTypes": ["AWS::EC2::SecurityGroup"]}},
              fidelity="compensating", gap="Security-group CIDRs are not SCP condition keys; detective rule with auto-remediation plus the Rego gate."),
     azure=dict(az({"allOf": [{"field": "type", "equals": "Microsoft.Network/networkSecurityGroups/securityRules"}, {"field": "Microsoft.Network/networkSecurityGroups/securityRules/direction", "equals": "Inbound"}, {"field": "Microsoft.Network/networkSecurityGroups/securityRules/access", "equals": "Allow"},
                   {"field": "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix", "in": ["*", "0.0.0.0/0", "Internet"]}]}), fidelity="full"),
     gcp=dict(kind="custom-constraint", constraint="custom.pac010DenyWorldOpenIngress",
              artifact={"constraint": {"name": "organizations/ORG_ID/customConstraints/custom.pac010DenyWorldOpenIngress", "resourceTypes": ["compute.googleapis.com/Firewall"], "methodTypes": ["CREATE", "UPDATE"], "condition": "resource.direction == 'INGRESS' && resource.sourceRanges.exists(r, r == '0.0.0.0/0')", "actionType": "DENY", "displayName": "PAC-010 deny world-open ingress"},
                        "policy": {"name": "organizations/ORG_ID/policies/custom.pac010DenyWorldOpenIngress", "spec": {"rules": [{"enforce": True}]}}},
              fidelity="partial", gap="Validate CEL against firewall resource schema in a lab org before enforcing.")),
dict(id="PAC-011", title="Hardened instance access", severity="high", intent="No weak instance access paths (IMDSv1, password SSH, unmanaged keys).",
     fw={"NIST 800-53": ["AC-17", "IA-2"], "CIS v8": ["5.4", "6.3"], "ISO 27001": ["A.8.5"]},
     tf=[T("aws_instance", "metadata_options.0.http_tokens", "eq", "required"), T("azurerm_linux_virtual_machine", "disable_password_authentication", "eq", True, miss=True), T("google_compute_instance", "metadata.enable-oslogin", "eq", "TRUE")],
     aws=dict(scp({"Sid": "PAC011RequireImdsv2", "Effect": "Deny", "Action": "ec2:RunInstances", "Resource": "arn:aws:ec2:*:*:instance/*", "Condition": {"StringNotEquals": {"ec2:MetadataHttpTokens": "required"}}}), fidelity="partial", gap="Same intent, different mechanism per cloud (IMDSv2 vs SSH passwords vs OS Login)."),
     azure=dict(az({"allOf": [{"field": "type", "equals": "Microsoft.Compute/virtualMachines"}, {"field": "Microsoft.Compute/virtualMachines/osProfile.linuxConfiguration", "exists": True}, {"field": "Microsoft.Compute/virtualMachines/osProfile.linuxConfiguration.disablePasswordAuthentication", "notEquals": True}]}), fidelity="partial", gap="Same intent, different mechanism per cloud."),
     gcp=dict(gbool("compute.requireOsLogin"), fidelity="partial", gap="Same intent, different mechanism per cloud.")),
dict(id="PAC-012", title="No default network", severity="medium", intent="Networks are designed, never created implicitly with permissive defaults.",
     fw={"NIST 800-53": ["CM-6", "SC-7"], "CIS v8": ["4.1"], "ISO 27001": ["A.8.9"]},
     tf=[T("aws_default_vpc", "id", "forbid"), T("azurerm_subnet", "default_outbound_access_enabled", "eq", False), T("google_compute_network", "auto_create_subnetworks", "eq", False)],
     aws=dict(scp({"Sid": "PAC012DenyDefaultVpc", "Effect": "Deny", "Action": ["ec2:CreateDefaultVpc", "ec2:CreateDefaultSubnet"], "Resource": "*"}), fidelity="full"),
     azure=dict(az({"allOf": [{"field": "type", "equals": "Microsoft.Network/virtualNetworks/subnets"}, {"field": "Microsoft.Network/virtualNetworks/subnets/defaultOutboundAccess", "notEquals": False}]}, effects=("Audit", "Disabled"), kind="detective"),
                fidelity="partial", gap="Azure has no default VNet; the equivalent risk is implicit outbound access, audited via subnet property."),
     gcp=dict(gbool("compute.skipDefaultNetworkCreation"), fidelity="full")),
]
