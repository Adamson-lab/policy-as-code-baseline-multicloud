# Sandbox composition (placeholders only). Each cloud applies with its own backend and OIDC identity.
module "aws" {
  source     = "../../modules/aws"
  target_ids = ["ou-xxxx-canary000"]
}

# module "azure" {
#   source           = "../../modules/azure"
#   definition_scope = "/providers/Microsoft.Management/managementGroups/mg-platform"
#   assignment_scope = "/providers/Microsoft.Management/managementGroups/mg-sandbox"
# }

# module "gcp" {
#   source = "../../modules/gcp"
#   parent = "folders/000000000000"
#   mode   = "dry_run"
# }
