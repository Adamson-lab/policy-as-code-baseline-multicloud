# GENERATED from the same fixtures the Python oracle executes. DO NOT EDIT.
package pac.c005_test

import rego.v1

import data.pac.c005

test_aws_lb_listener_pass if {
	count(c005.deny) == 0 with input as {"resource_changes": [{"address": "aws_lb_listener.t", "type": "aws_lb_listener", "change": {"actions": ["create"], "after": {"protocol": "HTTPS"}}}]}
}

test_aws_lb_listener_protocol_in_1 if {
	count(c005.deny) == 1 with input as {"resource_changes": [{"address": "aws_lb_listener.t", "type": "aws_lb_listener", "change": {"actions": ["create"], "after": {"protocol": "invalid-zz"}}}]}
}

test_azurerm_storage_account_pass if {
	count(c005.deny) == 0 with input as {"resource_changes": [{"address": "azurerm_storage_account.t", "type": "azurerm_storage_account", "change": {"actions": ["create"], "after": {"enable_https_traffic_only": true}}}]}
}

test_azurerm_storage_account_enable_https_traffic_only_eq_2 if {
	count(c005.deny) == 1 with input as {"resource_changes": [{"address": "azurerm_storage_account.t", "type": "azurerm_storage_account", "change": {"actions": ["create"], "after": {"enable_https_traffic_only": false}}}]}
}

test_google_compute_ssl_policy_pass if {
	count(c005.deny) == 0 with input as {"resource_changes": [{"address": "google_compute_ssl_policy.t", "type": "google_compute_ssl_policy", "change": {"actions": ["create"], "after": {"min_tls_version": "TLS_1_2"}}}]}
}

test_google_compute_ssl_policy_min_tls_version_in_3 if {
	count(c005.deny) == 1 with input as {"resource_changes": [{"address": "google_compute_ssl_policy.t", "type": "google_compute_ssl_policy", "change": {"actions": ["create"], "after": {"min_tls_version": "invalid-zz"}}}]}
}
