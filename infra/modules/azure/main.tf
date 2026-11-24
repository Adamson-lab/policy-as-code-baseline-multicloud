terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.110"
    }
  }
}

variable "repo_root" {
  type    = string
  default = "../../.."
}

variable "definition_scope" {
  type        = string
  description = "Management group ID where definitions and the initiative live"
}

variable "assignment_scope" {
  type        = string
  description = "Management group ID to assign to. Start with the sandbox group."
}

variable "effect_overrides" {
  type        = map(string)
  default     = {}
  description = "Per-control effect, e.g. { PAC-001 = Deny }. Default is each definition's audit-safe default."
}

variable "location" {
  type    = string
  default = "eastus"
}

locals {
  manifest = jsondecode(file("${var.repo_root}/controls/manifest.json"))
  defs     = { for m in local.manifest : m.id => m }
  docs     = { for id, m in local.defs : id => jsondecode(file("${var.repo_root}/${m.files.azure}")).properties }
  pname    = { for id in keys(local.defs) : id => "effect${replace(id, "-", "")}" }
}

resource "azurerm_policy_definition" "pac" {
  for_each            = local.defs
  name                = lower(each.key)
  policy_type         = "Custom"
  mode                = local.docs[each.key].mode
  display_name        = local.docs[each.key].displayName
  description         = local.docs[each.key].description
  management_group_id = var.definition_scope
  metadata            = jsonencode(local.docs[each.key].metadata)
  policy_rule         = jsonencode(local.docs[each.key].policyRule)
  parameters          = jsonencode(local.docs[each.key].parameters)
}

resource "azurerm_policy_set_definition" "baseline" {
  name                = "pac-baseline-v1"
  policy_type         = "Custom"
  display_name        = "Policy-as-Code Baseline v1"
  management_group_id = var.definition_scope

  parameters = jsonencode({
    for id, d in local.docs : local.pname[id] => {
      type          = "String"
      defaultValue  = d.parameters.effect.defaultValue
      allowedValues = d.parameters.effect.allowedValues
    }
  })

  dynamic "policy_definition_reference" {
    for_each = local.defs
    content {
      policy_definition_id = azurerm_policy_definition.pac[policy_definition_reference.key].id
      reference_id         = lower(policy_definition_reference.key)
      parameter_values     = jsonencode({ effect = { value = "[parameters('${local.pname[policy_definition_reference.key]}')]" } })
    }
  }
}

resource "azurerm_management_group_policy_assignment" "baseline" {
  name                 = "pac-baseline"
  management_group_id  = var.assignment_scope
  policy_definition_id = azurerm_policy_set_definition.baseline.id
  location             = var.location

  identity {
    type = "SystemAssigned"
  }

  parameters = jsonencode({
    for id in keys(local.defs) : local.pname[id] => {
      value = lookup(var.effect_overrides, id, local.docs[id].parameters.effect.defaultValue)
    }
  })
}
