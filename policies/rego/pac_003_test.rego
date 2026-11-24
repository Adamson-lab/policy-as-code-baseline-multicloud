# GENERATED from the same fixtures the Python oracle executes. DO NOT EDIT.
package pac.c003_test

import rego.v1

import data.pac.c003

test_provider_aws_pass if {
	count(c003.deny) == 0 with input as {"configuration": {"provider_config": {"aws": {"expressions": {"region": {"constant_value": "us-east-1"}}}}}, "resource_changes": []}
}

test_provider_aws_fail if {
	count(c003.deny) == 1 with input as {"configuration": {"provider_config": {"aws": {"expressions": {"region": {"constant_value": "zz-invalid-1"}}}}}, "resource_changes": []}
}

test_azurerm_resource_group_pass if {
	count(c003.deny) == 0 with input as {"resource_changes": [{"address": "azurerm_resource_group.t", "type": "azurerm_resource_group", "change": {"actions": ["create"], "after": {"location": "eastus"}}}]}
}

test_azurerm_resource_group_location_in_1 if {
	count(c003.deny) == 1 with input as {"resource_changes": [{"address": "azurerm_resource_group.t", "type": "azurerm_resource_group", "change": {"actions": ["create"], "after": {"location": "invalid-zz"}}}]}
}

test_google_storage_bucket_pass if {
	count(c003.deny) == 0 with input as {"resource_changes": [{"address": "google_storage_bucket.t", "type": "google_storage_bucket", "change": {"actions": ["create"], "after": {"location": "US"}}}]}
}

test_google_storage_bucket_location_in_2 if {
	count(c003.deny) == 1 with input as {"resource_changes": [{"address": "google_storage_bucket.t", "type": "google_storage_bucket", "change": {"actions": ["create"], "after": {"location": "invalid-zz"}}}]}
}
