terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.40"
    }
  }
}

variable "repo_root" {
  type    = string
  default = "../../.."
}

variable "parent" {
  type        = string
  description = "folders/123 or organizations/123. Start with a sandbox folder."
}

variable "mode" {
  type        = string
  default     = "dry_run"
  description = "dry_run writes dry_run_spec only (audit); enforce writes spec"
  validation {
    condition     = contains(["dry_run", "enforce"], var.mode)
    error_message = "mode must be dry_run or enforce"
  }
}

locals {
  manifest = jsondecode(file("${var.repo_root}/controls/manifest.json"))
  gcp = {
    for m in local.manifest : m.id => {
      constraint = element(split("/", jsondecode(file("${var.repo_root}/${m.files.gcp}")).name), 3)
      rules      = jsondecode(file("${var.repo_root}/${m.files.gcp}")).spec.rules
    } if m.engines.gcp.kind == "preventive"
  }
}

resource "google_org_policy_policy" "pac" {
  for_each = local.gcp
  name     = "${var.parent}/policies/${each.value.constraint}"
  parent   = var.parent

  dynamic "spec" {
    for_each = var.mode == "enforce" ? [1] : []
    content {
      dynamic "rules" {
        for_each = each.value.rules
        content {
          enforce  = try(rules.value.enforce ? "TRUE" : "FALSE", null)
          deny_all = try(rules.value.denyAll ? "TRUE" : null, null)
          dynamic "values" {
            for_each = try([rules.value.values], [])
            content {
              allowed_values = try(values.value.allowedValues, null)
              denied_values  = try(values.value.deniedValues, null)
            }
          }
        }
      }
    }
  }

  dynamic "dry_run_spec" {
    for_each = var.mode == "dry_run" ? [1] : []
    content {
      dynamic "rules" {
        for_each = each.value.rules
        content {
          enforce  = try(rules.value.enforce ? "TRUE" : "FALSE", null)
          deny_all = try(rules.value.denyAll ? "TRUE" : null, null)
          dynamic "values" {
            for_each = try([rules.value.values], [])
            content {
              allowed_values = try(values.value.allowedValues, null)
              denied_values  = try(values.value.deniedValues, null)
            }
          }
        }
      }
    }
  }
}
