# GENERATED from the same fixtures the Python oracle executes. DO NOT EDIT.
package pac.c006_test

import rego.v1

import data.pac.c006

test_aws_iam_access_key_pass if {
	count(c006.deny) == 0 with input as {"resource_changes": []}
}

test_aws_iam_access_key_fail if {
	count(c006.deny) == 1 with input as {"resource_changes": [{"address": "aws_iam_access_key.bad", "type": "aws_iam_access_key", "change": {"actions": ["create"], "after": {"id": "x"}}}]}
}

test_azurerm_storage_account_pass if {
	count(c006.deny) == 0 with input as {"resource_changes": [{"address": "azurerm_storage_account.t", "type": "azurerm_storage_account", "change": {"actions": ["create"], "after": {"shared_access_key_enabled": false}}}]}
}

test_azurerm_storage_account_shared_access_key_enabled_eq_1 if {
	count(c006.deny) == 1 with input as {"resource_changes": [{"address": "azurerm_storage_account.t", "type": "azurerm_storage_account", "change": {"actions": ["create"], "after": {"shared_access_key_enabled": true}}}]}
}

test_google_service_account_key_pass if {
	count(c006.deny) == 0 with input as {"resource_changes": []}
}

test_google_service_account_key_fail if {
	count(c006.deny) == 1 with input as {"resource_changes": [{"address": "google_service_account_key.bad", "type": "google_service_account_key", "change": {"actions": ["create"], "after": {"id": "x"}}}]}
}
