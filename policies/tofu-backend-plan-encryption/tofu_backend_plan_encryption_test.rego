package main

import rego.v1

backend := {"s3": [{"bucket": "tofu-state"}]}

valid_encryption := {
	"key_provider": {"pbkdf2": {"plan": [{"passphrase": "${var.encryption_passphrase}"}]}},
	"method": {"aes_gcm": {"plan": [{"keys": "${key_provider.pbkdf2.plan}"}]}},
	"plan": [{
		"enforced": true,
		"method": "${method.aes_gcm.plan}",
	}],
}

root_with(terraform_body) := [{
	"path": "roots/example/versions.tf",
	"contents": {"terraform": [terraform_body]},
}]

root_with_encryption_patch(patch) := root_with({
	"backend": backend,
	"encryption": [object.union(valid_encryption, patch)],
})

test_compliant_root_is_allowed if {
	count(deny) == 0 with input as root_with({
		"backend": backend,
		"encryption": [valid_encryption],
	})
}

test_module_without_backend_is_ignored if {
	count(deny) == 0 with input as [{
		"path": "lib/modules/example/versions.tf",
		"contents": {"terraform": [{"required_version": ">= 1.12.4"}]},
	}]
}

test_root_detected_via_state_store if {
	msgs := deny with input as root_with({"state_store": {"foo": [{}]}})
	some m in msgs
	contains(m.msg, "terraform.encryption block is missing")
}

test_missing_encryption_is_denied if {
	msgs := deny with input as root_with({"backend": backend})
	some m in msgs
	contains(m.msg, "roots/example: terraform.encryption block is missing")
}

test_missing_plan_sub_block_is_denied if {
	msgs := deny with input as root_with({
		"backend": backend,
		"encryption": [{
			"key_provider": {"pbkdf2": {"plan": [{"passphrase": "x"}]}},
			"method": {"aes_gcm": {"plan": [{"keys": "${key_provider.pbkdf2.plan}"}]}},
		}],
	})
	some m in msgs
	contains(m.msg, "has no plan{} sub-block")
}

test_enforced_false_is_denied if {
	msgs := deny with input as root_with_encryption_patch({"plan": [{
		"enforced": false,
		"method": "${method.aes_gcm.plan}",
	}]})
	some m in msgs
	contains(m.msg, "must set enforced = true")
}

test_enforced_unset_is_denied if {
	msgs := deny with input as root_with_encryption_patch({"plan": [{"method": "${method.aes_gcm.plan}"}]})
	some m in msgs
	contains(m.msg, "must set enforced = true")
}

test_enforced_from_variable_is_denied if {
	msgs := deny with input as root_with_encryption_patch({"plan": [{
		"enforced": "${var.enforce}",
		"method": "${method.aes_gcm.plan}",
	}]})
	some m in msgs
	contains(m.msg, "must set enforced = true")
}

test_missing_method_attribute_is_denied if {
	msgs := deny with input as root_with_encryption_patch({"plan": [{"enforced": true}]})
	some m in msgs
	contains(m.msg, "must set method")
}

test_undeclared_method_is_denied if {
	msgs := deny with input as root_with_encryption_patch({"plan": [{
		"enforced": true,
		"method": "${method.aes_gcm.missing}",
	}]})
	some m in msgs
	contains(m.msg, "is not a declared method block")
}

test_undeclared_key_provider_is_denied if {
	msgs := deny with input as root_with_encryption_patch({"method": {"aes_gcm": {"plan": [{"keys": "${key_provider.pbkdf2.missing}"}]}}})
	some m in msgs
	contains(m.msg, "is not a declared key_provider block")
}

test_split_across_files_in_one_root_is_allowed if {
	count(deny) == 0 with input as [
		{
			"path": "roots/example/versions.tf",
			"contents": {"terraform": [{
				"backend": backend,
				"encryption": [{"plan": [{
					"enforced": true,
					"method": "${method.aes_gcm.plan}",
				}]}],
			}]},
		},
		{
			"path": "roots/example/encryption.tf",
			"contents": {"terraform": [{"encryption": [{
				"key_provider": {"pbkdf2": {"plan": [{"passphrase": "x"}]}},
				"method": {"aes_gcm": {"plan": [{"keys": "${key_provider.pbkdf2.plan}"}]}},
			}]}]},
		},
	]
}

test_declarations_do_not_leak_between_roots if {
	msgs := deny with input as [
		{
			"path": "roots/one/versions.tf",
			"contents": {"terraform": [{"backend": backend, "encryption": [valid_encryption]}]},
		},
		{
			"path": "roots/two/versions.tf",
			"contents": {"terraform": [{
				"backend": backend,
				"encryption": [{"plan": [{
					"enforced": true,
					"method": "${method.aes_gcm.plan}",
				}]}],
			}]},
		},
	]
	some m in msgs
	contains(m.msg, "roots/two")
	contains(m.msg, "is not a declared method block")
}

test_only_the_offending_root_is_reported if {
	msgs := deny with input as [
		{
			"path": "roots/good/versions.tf",
			"contents": {"terraform": [{"backend": backend, "encryption": [valid_encryption]}]},
		},
		{"path": "roots/bad/versions.tf", "contents": {"terraform": [{"backend": backend}]}},
	]
	count(msgs) == 1
	some m in msgs
	contains(m.msg, "roots/bad")
}
