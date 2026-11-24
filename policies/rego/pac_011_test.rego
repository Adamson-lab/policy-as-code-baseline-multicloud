# GENERATED from the same fixtures the Python oracle executes. DO NOT EDIT.
package pac.c011_test

import rego.v1

import data.pac.c011

test_aws_instance_pass if {
	count(c011.deny) == 0 with input as {"resource_changes": [{"address": "aws_instance.t", "type": "aws_instance", "change": {"actions": ["create"], "after": {"metadata_options": [{"http_tokens": "required"}]}}}]}
}

test_aws_instance_metadata_options_0_http_tokens_eq_required if {
	count(c011.deny) == 1 with input as {"resource_changes": [{"address": "aws_instance.t", "type": "aws_instance", "change": {"actions": ["create"], "after": {"metadata_options": [{"http_tokens": "invalid"}]}}}]}
}

test_azurerm_linux_virtual_machine_pass if {
	count(c011.deny) == 0 with input as {"resource_changes": [{"address": "azurerm_linux_virtual_machine.t", "type": "azurerm_linux_virtual_machine", "change": {"actions": ["create"], "after": {"disable_password_authentication": true}}}]}
}

test_azurerm_linux_virtual_machine_disable_password_authentication_eq_2 if {
	count(c011.deny) == 1 with input as {"resource_changes": [{"address": "azurerm_linux_virtual_machine.t", "type": "azurerm_linux_virtual_machine", "change": {"actions": ["create"], "after": {"disable_password_authentication": false}}}]}
}

test_google_compute_instance_pass if {
	count(c011.deny) == 0 with input as {"resource_changes": [{"address": "google_compute_instance.t", "type": "google_compute_instance", "change": {"actions": ["create"], "after": {"metadata": {"enable-oslogin": "TRUE"}}}}]}
}

test_google_compute_instance_metadata_enable_oslogin_eq_TRUE if {
	count(c011.deny) == 1 with input as {"resource_changes": [{"address": "google_compute_instance.t", "type": "google_compute_instance", "change": {"actions": ["create"], "after": {"metadata": {"enable-oslogin": "invalid"}}}}]}
}
