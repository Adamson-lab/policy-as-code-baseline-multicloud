# GENERATED from the same fixtures the Python oracle executes. DO NOT EDIT.
package pac.c007_test

import rego.v1

import data.pac.c007

test_aws_cloudtrail_pass if {
	count(c007.deny) == 0 with input as {"resource_changes": [{"address": "aws_cloudtrail.t", "type": "aws_cloudtrail", "change": {"actions": ["create"], "after": {"is_multi_region_trail": true, "enable_log_file_validation": true}}}]}
}

test_aws_cloudtrail_is_multi_region_trail_eq_1 if {
	count(c007.deny) == 1 with input as {"resource_changes": [{"address": "aws_cloudtrail.t", "type": "aws_cloudtrail", "change": {"actions": ["create"], "after": {"is_multi_region_trail": false, "enable_log_file_validation": true}}}]}
}

test_aws_cloudtrail_enable_log_file_validation_eq_2 if {
	count(c007.deny) == 1 with input as {"resource_changes": [{"address": "aws_cloudtrail.t", "type": "aws_cloudtrail", "change": {"actions": ["create"], "after": {"is_multi_region_trail": true, "enable_log_file_validation": false}}}]}
}

test_azurerm_monitor_diagnostic_setting_pass if {
	count(c007.deny) == 0 with input as {"resource_changes": [{"address": "azurerm_monitor_diagnostic_setting.t", "type": "azurerm_monitor_diagnostic_setting", "change": {"actions": ["create"], "after": {"log_analytics_workspace_id": "x"}}}]}
}

test_azurerm_monitor_diagnostic_setting_log_analytics_workspace_id_exists_3 if {
	count(c007.deny) == 1 with input as {"resource_changes": [{"address": "azurerm_monitor_diagnostic_setting.t", "type": "azurerm_monitor_diagnostic_setting", "change": {"actions": ["create"], "after": {}}}]}
}

test_google_project_iam_audit_config_pass if {
	count(c007.deny) == 0 with input as {"resource_changes": [{"address": "google_project_iam_audit_config.t", "type": "google_project_iam_audit_config", "change": {"actions": ["create"], "after": {"service": "allServices"}}}]}
}

test_google_project_iam_audit_config_service_eq_allServices if {
	count(c007.deny) == 1 with input as {"resource_changes": [{"address": "google_project_iam_audit_config.t", "type": "google_project_iam_audit_config", "change": {"actions": ["create"], "after": {"service": "invalid"}}}]}
}
