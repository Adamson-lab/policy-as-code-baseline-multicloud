# GENERATED from the same fixtures the Python oracle executes. DO NOT EDIT.
package pac.c008_test

import rego.v1

import data.pac.c008

test_aws_s3_bucket_pass if {
	count(c008.deny) == 0 with input as {"resource_changes": [{"address": "aws_s3_bucket.t", "type": "aws_s3_bucket", "change": {"actions": ["create"], "after": {"tags_all": {"cost-center": "x"}}}}]}
}

test_aws_s3_bucket_tags_all_cost_center_exists_1 if {
	count(c008.deny) == 1 with input as {"resource_changes": [{"address": "aws_s3_bucket.t", "type": "aws_s3_bucket", "change": {"actions": ["create"], "after": {"tags_all": {"cost-center": null}}}}]}
}

test_azurerm_resource_group_pass if {
	count(c008.deny) == 0 with input as {"resource_changes": [{"address": "azurerm_resource_group.t", "type": "azurerm_resource_group", "change": {"actions": ["create"], "after": {"tags": {"cost-center": "x"}}}}]}
}

test_azurerm_resource_group_tags_cost_center_exists_2 if {
	count(c008.deny) == 1 with input as {"resource_changes": [{"address": "azurerm_resource_group.t", "type": "azurerm_resource_group", "change": {"actions": ["create"], "after": {"tags": {"cost-center": null}}}}]}
}

test_google_compute_instance_pass if {
	count(c008.deny) == 0 with input as {"resource_changes": [{"address": "google_compute_instance.t", "type": "google_compute_instance", "change": {"actions": ["create"], "after": {"labels": {"cost-center": "x"}}}}]}
}

test_google_compute_instance_labels_cost_center_exists_3 if {
	count(c008.deny) == 1 with input as {"resource_changes": [{"address": "google_compute_instance.t", "type": "google_compute_instance", "change": {"actions": ["create"], "after": {"labels": {"cost-center": null}}}}]}
}
