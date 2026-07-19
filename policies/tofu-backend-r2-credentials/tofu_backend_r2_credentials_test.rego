package main

import data.lib.testdata
import rego.v1

test_compliant_backend_is_allowed if {
	count(deny) == 0 with input as testdata.root(testdata.backend)
}

test_committed_credentials_are_denied if {
	msgs := deny with input as testdata.root_with({
		"access_key": "4e5f6a7b8c9d",
		"secret_key": "0123456789abcdef0123456789abcdef01234567",
	})
	count(msgs) == 2
	some m in msgs
	contains(m.msg, "must not set access_key")
	contains(m.msg, "pass AWS_ACCESS_KEY_ID instead")
	some n in msgs
	contains(n.msg, "must not set secret_key")
}

test_session_token_is_denied if {
	msgs := deny with input as testdata.root_with({"token": "sts-token"})
	some m in msgs
	contains(m.msg, "must not set token")
	contains(m.msg, "pass AWS_SESSION_TOKEN instead")
}

# An interpolation is no better: the backend cannot resolve it, so it ends up
# in the state as the literal string.
test_credential_from_a_variable_is_denied if {
	msgs := deny with input as testdata.root_with({"secret_key": "${var.r2_secret_key}"})
	some m in msgs
	contains(m.msg, "must not set secret_key")
}

test_every_machine_local_setting_is_reported if {
	msgs := deny with input as testdata.root_with({
		"profile": "r2",
		"shared_config_files": ["~/.aws/config"],
		"shared_credentials_files": ["~/.aws/credentials"],
	})
	every setting in machine_local_settings {
		some m in msgs
		contains(m.msg, sprintf("must not set %s", [setting]))
	}
}

test_machine_local_setting_names_its_reason if {
	msgs := deny with input as testdata.root_with({"profile": "r2"})
	some m in msgs
	contains(m.msg, "resolves against one developer's filesystem and is not reproducible in CI")
}

test_plain_aws_backend_is_ignored if {
	count(deny) == 0 with input as testdata.root({
		"bucket": "tofu-state",
		"key": "roots/example/terraform.tfstate",
		"region": "eu-central-1",
		"profile": "production",
	})
}
