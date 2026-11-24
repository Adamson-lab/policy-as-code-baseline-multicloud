# GENERATED from the same fixtures the Python oracle executes. DO NOT EDIT.
package pac.c012_test

import rego.v1

import data.pac.c012

test_aws_default_vpc_pass if {
	count(c012.deny) == 0 with input as {"resource_changes": []}
}

test_aws_default_vpc_fail if {
	count(c012.deny) == 1 with input as {"resource_changes": [{"address": "aws_default_vpc.bad", "type": "aws_default_vpc", "change": {"actions": ["create"], "after": {"id": "x"}}}]}
}

test_azurerm_subnet_pass if {
	count(c012.deny) == 0 with input as {"resource_changes": [{"address": "azurerm_subnet.t", "type": "azurerm_subnet", "change": {"actions": ["create"], "after": {"default_outbound_access_enabled": false}}}]}
}

test_azurerm_subnet_default_outbound_access_enabled_eq_1 if {
	count(c012.deny) == 1 with input as {"resource_changes": [{"address": "azurerm_subnet.t", "type": "azurerm_subnet", "change": {"actions": ["create"], "after": {"default_outbound_access_enabled": true}}}]}
}

test_google_compute_network_pass if {
	count(c012.deny) == 0 with input as {"resource_changes": [{"address": "google_compute_network.t", "type": "google_compute_network", "change": {"actions": ["create"], "after": {"auto_create_subnetworks": false}}}]}
}

test_google_compute_network_auto_create_subnetworks_eq_2 if {
	count(c012.deny) == 1 with input as {"resource_changes": [{"address": "google_compute_network.t", "type": "google_compute_network", "change": {"actions": ["create"], "after": {"auto_create_subnetworks": true}}}]}
}
