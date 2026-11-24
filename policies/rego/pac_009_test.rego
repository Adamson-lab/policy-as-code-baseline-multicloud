# GENERATED from the same fixtures the Python oracle executes. DO NOT EDIT.
package pac.c009_test

import rego.v1

import data.pac.c009

test_aws_db_instance_pass if {
	count(c009.deny) == 0 with input as {"resource_changes": [{"address": "aws_db_instance.t", "type": "aws_db_instance", "change": {"actions": ["create"], "after": {"publicly_accessible": false}}}]}
}

test_aws_db_instance_publicly_accessible_eq_1 if {
	count(c009.deny) == 1 with input as {"resource_changes": [{"address": "aws_db_instance.t", "type": "aws_db_instance", "change": {"actions": ["create"], "after": {"publicly_accessible": true}}}]}
}

test_azurerm_mssql_server_pass if {
	count(c009.deny) == 0 with input as {"resource_changes": [{"address": "azurerm_mssql_server.t", "type": "azurerm_mssql_server", "change": {"actions": ["create"], "after": {"public_network_access_enabled": false}}}]}
}

test_azurerm_mssql_server_public_network_access_enabled_eq_2 if {
	count(c009.deny) == 1 with input as {"resource_changes": [{"address": "azurerm_mssql_server.t", "type": "azurerm_mssql_server", "change": {"actions": ["create"], "after": {"public_network_access_enabled": true}}}]}
}

test_google_sql_database_instance_pass if {
	count(c009.deny) == 0 with input as {"resource_changes": [{"address": "google_sql_database_instance.t", "type": "google_sql_database_instance", "change": {"actions": ["create"], "after": {"settings": [{"ip_configuration": [{"ipv4_enabled": false}]}]}}}]}
}

test_google_sql_database_instance_settings_0_ip_configuration_0_ipv4_enable if {
	count(c009.deny) == 1 with input as {"resource_changes": [{"address": "google_sql_database_instance.t", "type": "google_sql_database_instance", "change": {"actions": ["create"], "after": {"settings": [{"ip_configuration": [{"ipv4_enabled": true}]}]}}}]}
}
