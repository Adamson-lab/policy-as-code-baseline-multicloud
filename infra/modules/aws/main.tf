terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

variable "repo_root" {
  type    = string
  default = "../../.."
}

variable "target_ids" {
  type        = list(string)
  description = "OU or account IDs to attach to. Start with the canary OU, then promote wave by wave."
}

locals {
  bundle_files = fileset("${var.repo_root}/policies/aws/scp/bundles", "pac-bundle-*.json")
  config_rules = fileset("${var.repo_root}/policies/aws/config", "PAC-*.json")
}

# SCPs are packed into bundles because AWS allows 5 per target and 5120 chars per policy (ADR-0006).
resource "aws_organizations_policy" "bundle" {
  for_each = local.bundle_files
  name     = trimsuffix(each.key, ".json")
  type     = "SERVICE_CONTROL_POLICY"
  content  = file("${var.repo_root}/policies/aws/scp/bundles/${each.key}")
}

resource "aws_organizations_policy_attachment" "bundle" {
  for_each  = { for p in setproduct(tolist(local.bundle_files), var.target_ids) : "${p[0]}-${p[1]}" => p }
  policy_id = aws_organizations_policy.bundle[each.value[0]].id
  target_id = each.value[1]
}

# Detective compensating controls (no SCP condition key exists for these)
resource "aws_config_organization_managed_rule" "compensating" {
  for_each        = local.config_rules
  name            = jsondecode(file("${var.repo_root}/policies/aws/config/${each.key}")).ConfigRuleName
  rule_identifier = jsondecode(file("${var.repo_root}/policies/aws/config/${each.key}")).Source.SourceIdentifier
}

output "bundle_policy_ids" {
  value = { for k, v in aws_organizations_policy.bundle : k => v.id }
}
