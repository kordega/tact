package main

import data.lib.testdata
import rego.v1

# The builders and the compliant encryption block live in lib.testdata, shared
# with the state encryption tests: both files assert on the same warn set, so a
# root that satisfies one policy but not the other would carry the other
# policy's warnings into these assertions.

test_compliant_root_is_allowed if {
	count(warn) == 0 with input as testdata.encryption_root({
		"backend": testdata.encryption_backend,
		"encryption": [testdata.encryption],
	})
}

test_module_without_backend_is_ignored if {
	count(warn) == 0 with input as [{
		"path": "lib/modules/example/versions.tf",
		"contents": {"terraform": [{"required_version": ">= 1.12.4"}]},
	}]
}

test_root_detected_via_state_store if {
	msgs := warn with input as testdata.encryption_root({"state_store": {"foo": [{}]}})
	some m in msgs
	contains(m.msg, "terraform.encryption block is missing")
}

test_missing_encryption_is_denied if {
	msgs := warn with input as testdata.encryption_root({"backend": testdata.encryption_backend})
	some m in msgs
	contains(m.msg, "roots/example: terraform.encryption block is missing, so plan files are written in plaintext")
}

test_missing_plan_sub_block_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"plan": []})
	some m in msgs
	contains(m.msg, "has no plan{} sub-block")
}

test_enforced_false_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"plan": [{
		"enforced": false,
		"method": "${method.aes_gcm.plan}",
	}]})
	some m in msgs
	contains(m.msg, "terraform.encryption.plan must set enforced = true (got false)")
}

test_enforced_unset_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"plan": [{"method": "${method.aes_gcm.plan}"}]})
	some m in msgs
	contains(m.msg, "terraform.encryption.plan must set enforced = true")
}

test_enforced_from_variable_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"plan": [{
		"enforced": "${var.enforce}",
		"method": "${method.aes_gcm.plan}",
	}]})
	some m in msgs
	contains(m.msg, "terraform.encryption.plan must set enforced = true")
}

test_missing_method_attribute_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"plan": [{"enforced": true}]})
	some m in msgs
	contains(m.msg, "terraform.encryption.plan must set method")
}

test_undeclared_method_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"plan": [{
		"enforced": true,
		"method": "${method.aes_gcm.missing}",
	}]})
	some m in msgs
	contains(m.msg, "terraform.encryption.plan.method references \"method.aes_gcm.missing\"")
}

test_undeclared_key_provider_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"method": {"aes_gcm": {
		"plan": [{"keys": "${key_provider.pbkdf2.missing}"}],
		"state": [{"keys": "${key_provider.pbkdf2.state}"}],
	}}})
	some m in msgs
	contains(m.msg, "method.aes_gcm.plan keys references \"key_provider.pbkdf2.missing\"")
}

# The state chain is intact in the fixture above, so a message about
# method.aes_gcm.state would mean this policy audits methods that the plan
# block does not depend on.
test_undeclared_key_provider_is_scoped_to_the_plan_chain if {
	msgs := warn with input as testdata.encryption_root_with({"method": {"aes_gcm": {
		"plan": [{"keys": "${key_provider.pbkdf2.missing}"}],
		"state": [{"keys": "${key_provider.pbkdf2.state}"}],
	}}})
	every m in msgs {
		not contains(m.msg, "method.aes_gcm.state keys")
	}
}

test_split_across_files_in_one_root_is_allowed if {
	count(warn) == 0 with input as [
		{
			"path": "roots/example/versions.tf",
			"contents": {"terraform": [{
				"backend": testdata.encryption_backend,
				"encryption": [{
					"plan": testdata.encryption.plan,
					"state": testdata.encryption.state,
				}],
			}]},
		},
		{
			"path": "roots/example/encryption.tf",
			"contents": {"terraform": [{"encryption": [{
				"key_provider": testdata.encryption.key_provider,
				"method": testdata.encryption.method,
			}]}]},
		},
	]
}

test_declarations_do_not_leak_between_roots if {
	msgs := warn with input as [
		{
			"path": "roots/one/versions.tf",
			"contents": {"terraform": [{
				"backend": testdata.encryption_backend,
				"encryption": [testdata.encryption],
			}]},
		},
		{
			"path": "roots/two/versions.tf",
			"contents": {"terraform": [{
				"backend": testdata.encryption_backend,
				"encryption": [{"plan": testdata.encryption.plan}],
			}]},
		},
	]
	some m in msgs
	contains(m.msg, "roots/two")
	contains(m.msg, "terraform.encryption.plan.method references")
}

# A root with no encryption block at all is reported by both the plan and the
# state policy, so the assertion is that nothing points at the compliant root
# rather than a count of one.
test_only_the_offending_root_is_reported if {
	msgs := warn with input as [
		{
			"path": "roots/good/versions.tf",
			"contents": {"terraform": [{
				"backend": testdata.encryption_backend,
				"encryption": [testdata.encryption],
			}]},
		},
		{
			"path": "roots/bad/versions.tf",
			"contents": {"terraform": [{"backend": testdata.encryption_backend}]},
		},
	]
	count(msgs) > 0
	every m in msgs {
		contains(m.msg, "roots/bad")
	}
}
