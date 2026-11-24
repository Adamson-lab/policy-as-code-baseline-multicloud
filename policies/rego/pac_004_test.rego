# GENERATED from the same fixtures the Python oracle executes. DO NOT EDIT.
package pac.c004_test

import rego.v1

import data.pac.c004

test_aws_instance_pass if {
	count(c004.deny) == 0 with input as {"resource_changes": [{"address": "aws_instance.t", "type": "aws_instance", "change": {"actions": ["create"], "after": {"associate_public_ip_address": false}}}]}
}

test_aws_instance_associate_public_ip_address_eq_1 if {
	count(c004.deny) == 1 with input as {"resource_changes": [{"address": "aws_instance.t", "type": "aws_instance", "change": {"actions": ["create"], "after": {"associate_public_ip_address": true}}}]}
}

test_azurerm_public_ip_pass if {
	count(c004.deny) == 0 with input as {"resource_changes": []}
}

test_azurerm_public_ip_fail if {
	count(c004.deny) == 1 with input as {"resource_changes": [{"address": "azurerm_public_ip.bad", "type": "azurerm_public_ip", "change": {"actions": ["create"], "after": {"id": "x"}}}]}
}

test_google_compute_instance_pass if {
	count(c004.deny) == 0 with input as {"resource_changes": [{"address": "google_compute_instance.t", "type": "google_compute_instance", "change": {"actions": ["create"], "after": {}}}]}
}

test_google_compute_instance_network_interface_0_access_config_absent_2 if {
	count(c004.deny) == 1 with input as {"resource_changes": [{"address": "google_compute_instance.t", "type": "google_compute_instance", "change": {"actions": ["create"], "after": {"network_interface": [{"access_config": [{"present": true}]}]}}}]}
}
