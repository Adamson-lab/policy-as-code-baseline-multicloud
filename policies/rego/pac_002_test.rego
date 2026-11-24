# GENERATED from the same fixtures the Python oracle executes. DO NOT EDIT.
package pac.c002_test

import rego.v1

import data.pac.c002

test_aws_ebs_volume_pass if {
	count(c002.deny) == 0 with input as {"resource_changes": [{"address": "aws_ebs_volume.t", "type": "aws_ebs_volume", "change": {"actions": ["create"], "after": {"encrypted": true}}}]}
}

test_aws_ebs_volume_encrypted_eq_1 if {
	count(c002.deny) == 1 with input as {"resource_changes": [{"address": "aws_ebs_volume.t", "type": "aws_ebs_volume", "change": {"actions": ["create"], "after": {"encrypted": false}}}]}
}

test_aws_db_instance_pass if {
	count(c002.deny) == 0 with input as {"resource_changes": [{"address": "aws_db_instance.t", "type": "aws_db_instance", "change": {"actions": ["create"], "after": {"storage_encrypted": true}}}]}
}

test_aws_db_instance_storage_encrypted_eq_2 if {
	count(c002.deny) == 1 with input as {"resource_changes": [{"address": "aws_db_instance.t", "type": "aws_db_instance", "change": {"actions": ["create"], "after": {"storage_encrypted": false}}}]}
}

test_azurerm_managed_disk_pass if {
	count(c002.deny) == 0 with input as {"resource_changes": [{"address": "azurerm_managed_disk.t", "type": "azurerm_managed_disk", "change": {"actions": ["create"], "after": {"disk_encryption_set_id": "x"}}}]}
}

test_azurerm_managed_disk_disk_encryption_set_id_exists_3 if {
	count(c002.deny) == 1 with input as {"resource_changes": [{"address": "azurerm_managed_disk.t", "type": "azurerm_managed_disk", "change": {"actions": ["create"], "after": {}}}]}
}

test_google_storage_bucket_pass if {
	count(c002.deny) == 0 with input as {"resource_changes": [{"address": "google_storage_bucket.t", "type": "google_storage_bucket", "change": {"actions": ["create"], "after": {"encryption": [{"default_kms_key_name": "x"}]}}}]}
}

test_google_storage_bucket_encryption_0_default_kms_key_name_exists_4 if {
	count(c002.deny) == 1 with input as {"resource_changes": [{"address": "google_storage_bucket.t", "type": "google_storage_bucket", "change": {"actions": ["create"], "after": {"encryption": [{"default_kms_key_name": null}]}}}]}
}
