# GENERATED from the same fixtures the Python oracle executes. DO NOT EDIT.
package pac.c010_test

import rego.v1

import data.pac.c010

test_aws_vpc_security_group_ingress_rule_pass if {
	count(c010.deny) == 0 with input as {"resource_changes": [{"address": "aws_vpc_security_group_ingress_rule.t", "type": "aws_vpc_security_group_ingress_rule", "change": {"actions": ["create"], "after": {"cidr_ipv4": "10.0.0.0/8"}}}]}
}

test_aws_vpc_security_group_ingress_rule_cidr_ipv4_ne_0_0_0_0_0 if {
	count(c010.deny) == 1 with input as {"resource_changes": [{"address": "aws_vpc_security_group_ingress_rule.t", "type": "aws_vpc_security_group_ingress_rule", "change": {"actions": ["create"], "after": {"cidr_ipv4": "0.0.0.0/0"}}}]}
}

test_azurerm_network_security_rule_pass if {
	count(c010.deny) == 0 with input as {"resource_changes": [{"address": "azurerm_network_security_rule.t", "type": "azurerm_network_security_rule", "change": {"actions": ["create"], "after": {"source_address_prefix": "10.0.0.0/8"}}}]}
}

test_azurerm_network_security_rule_source_address_prefix_ne_star if {
	count(c010.deny) == 1 with input as {"resource_changes": [{"address": "azurerm_network_security_rule.t", "type": "azurerm_network_security_rule", "change": {"actions": ["create"], "after": {"source_address_prefix": "*"}}}]}
}

test_azurerm_network_security_rule_source_address_prefix_ne_0_0_0_0_0 if {
	count(c010.deny) == 1 with input as {"resource_changes": [{"address": "azurerm_network_security_rule.t", "type": "azurerm_network_security_rule", "change": {"actions": ["create"], "after": {"source_address_prefix": "0.0.0.0/0"}}}]}
}

test_google_compute_firewall_pass if {
	count(c010.deny) == 0 with input as {"resource_changes": [{"address": "google_compute_firewall.t", "type": "google_compute_firewall", "change": {"actions": ["create"], "after": {"source_ranges": ["10.0.0.0/8"]}}}]}
}

test_google_compute_firewall_source_ranges_not_contains_0_0_0_0_0 if {
	count(c010.deny) == 1 with input as {"resource_changes": [{"address": "google_compute_firewall.t", "type": "google_compute_firewall", "change": {"actions": ["create"], "after": {"source_ranges": ["0.0.0.0/0"]}}}]}
}
