# GENERATED from the same fixtures the Python oracle executes. DO NOT EDIT.
package pac.c001_test

import rego.v1

import data.pac.c001

test_aws_s3_bucket_public_access_block_pass if {
	count(c001.deny) == 0 with input as {"resource_changes": [{"address": "aws_s3_bucket_public_access_block.t", "type": "aws_s3_bucket_public_access_block", "change": {"actions": ["create"], "after": {"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}}}]}
}

test_aws_s3_bucket_public_access_block_block_public_acls_eq_1 if {
	count(c001.deny) == 1 with input as {"resource_changes": [{"address": "aws_s3_bucket_public_access_block.t", "type": "aws_s3_bucket_public_access_block", "change": {"actions": ["create"], "after": {"block_public_acls": false, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}}}]}
}

test_aws_s3_bucket_public_access_block_block_public_policy_eq_2 if {
	count(c001.deny) == 1 with input as {"resource_changes": [{"address": "aws_s3_bucket_public_access_block.t", "type": "aws_s3_bucket_public_access_block", "change": {"actions": ["create"], "after": {"block_public_acls": true, "block_public_policy": false, "ignore_public_acls": true, "restrict_public_buckets": true}}}]}
}

test_aws_s3_bucket_public_access_block_ignore_public_acls_eq_3 if {
	count(c001.deny) == 1 with input as {"resource_changes": [{"address": "aws_s3_bucket_public_access_block.t", "type": "aws_s3_bucket_public_access_block", "change": {"actions": ["create"], "after": {"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": false, "restrict_public_buckets": true}}}]}
}

test_aws_s3_bucket_public_access_block_restrict_public_buckets_eq_4 if {
	count(c001.deny) == 1 with input as {"resource_changes": [{"address": "aws_s3_bucket_public_access_block.t", "type": "aws_s3_bucket_public_access_block", "change": {"actions": ["create"], "after": {"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": false}}}]}
}

test_azurerm_storage_account_pass if {
	count(c001.deny) == 0 with input as {"resource_changes": [{"address": "azurerm_storage_account.t", "type": "azurerm_storage_account", "change": {"actions": ["create"], "after": {"allow_nested_items_to_be_public": false}}}]}
}

test_azurerm_storage_account_allow_nested_items_to_be_public_eq_5 if {
	count(c001.deny) == 1 with input as {"resource_changes": [{"address": "azurerm_storage_account.t", "type": "azurerm_storage_account", "change": {"actions": ["create"], "after": {"allow_nested_items_to_be_public": true}}}]}
}

test_google_storage_bucket_pass if {
	count(c001.deny) == 0 with input as {"resource_changes": [{"address": "google_storage_bucket.t", "type": "google_storage_bucket", "change": {"actions": ["create"], "after": {"public_access_prevention": "enforced"}}}]}
}

test_google_storage_bucket_public_access_prevention_eq_enforced if {
	count(c001.deny) == 1 with input as {"resource_changes": [{"address": "google_storage_bucket.t", "type": "google_storage_bucket", "change": {"actions": ["create"], "after": {"public_access_prevention": "invalid"}}}]}
}
