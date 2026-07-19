package main

import data.lib.testdata
import rego.v1

# The builders and the compliant encryption block live in lib.testdata, shared
# with the plan encryption tests: both files assert on the same warn set, so a
# root that satisfies one policy but not the other would carry the other
# policy's warnings into these assertions.
#
# test_compliant_root_is_allowed and test_module_without_backend_is_ignored are
# not repeated here for that same reason: they assert count(warn) == 0 over
# both policies at once, so the plan test file already covers this one.

test_state_root_detected_via_state_store if {
	msgs := warn with input as testdata.encryption_root({"state_store": {"foo": [{}]}})
	some m in msgs
	contains(m.msg, "terraform.encryption block is missing, so state is written in plaintext")
}

test_missing_encryption_warns_about_state if {
	msgs := warn with input as testdata.encryption_root({"backend": testdata.encryption_backend})
	some m in msgs
	contains(m.msg, "roots/example: terraform.encryption block is missing, so state is written in plaintext")
}

# The plan block is intact, so this is the case the policy exists for: a root
# that encrypts its plan files and leaves its state readable.
test_missing_state_sub_block_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"state": []})
	some m in msgs
	contains(m.msg, "roots/example: terraform.encryption is declared but has no state{} sub-block")
}

test_state_enforced_false_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"state": [{
		"enforced": false,
		"method": "${method.aes_gcm.state}",
	}]})
	some m in msgs
	contains(m.msg, "terraform.encryption.state must set enforced = true (got false)")
}

test_state_enforced_unset_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"state": [{"method": "${method.aes_gcm.state}"}]})
	some m in msgs
	contains(m.msg, "terraform.encryption.state must set enforced = true (got <unset>)")
}

test_state_enforced_from_variable_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"state": [{
		"enforced": "${var.enforce}",
		"method": "${method.aes_gcm.state}",
	}]})
	some m in msgs
	contains(m.msg, "terraform.encryption.state must set enforced = true")
}

test_state_missing_method_attribute_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"state": [{"enforced": true}]})
	some m in msgs
	contains(m.msg, "terraform.encryption.state must set method")
}

test_state_undeclared_method_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"state": [{
		"enforced": true,
		"method": "${method.aes_gcm.missing}",
	}]})
	some m in msgs
	contains(m.msg, "terraform.encryption.state.method references \"method.aes_gcm.missing\"")
}

test_state_undeclared_key_provider_is_denied if {
	msgs := warn with input as testdata.encryption_root_with({"method": {"aes_gcm": {
		"plan": [{"keys": "${key_provider.pbkdf2.plan}"}],
		"state": [{"keys": "${key_provider.pbkdf2.missing}"}],
	}}})
	some m in msgs
	contains(m.msg, "method.aes_gcm.state keys references \"key_provider.pbkdf2.missing\"")
}

# The plan chain is intact in the fixture above, so a message about
# method.aes_gcm.plan would mean this policy audits methods that the state
# block does not depend on.
test_state_undeclared_key_provider_is_scoped_to_the_state_chain if {
	msgs := warn with input as testdata.encryption_root_with({"method": {"aes_gcm": {
		"plan": [{"keys": "${key_provider.pbkdf2.plan}"}],
		"state": [{"keys": "${key_provider.pbkdf2.missing}"}],
	}}})
	every m in msgs {
		not contains(m.msg, "method.aes_gcm.plan keys")
	}
}

# A root may encrypt state and plan with one method rather than two. Both
# policies then report the same broken key provider reference, and warn is a
# set, so the root is still reported once.
test_shared_method_is_reported_once if {
	msgs := warn with input as testdata.encryption_root_with({
		"method": {"aes_gcm": {"shared": [{"keys": "${key_provider.pbkdf2.missing}"}]}},
		"plan": [{"enforced": true, "method": "${method.aes_gcm.shared}"}],
		"state": [{"enforced": true, "method": "${method.aes_gcm.shared}"}],
	})
	keys_msgs := [m | some m in msgs; contains(m.msg, "keys references")]
	count(keys_msgs) == 1
}

test_state_split_across_files_in_one_root_is_allowed if {
	count(warn) == 0 with input as [
		{
			"path": "roots/example/versions.tf",
			"contents": {"terraform": [{
				"backend": testdata.encryption_backend,
				"encryption": [{"state": testdata.encryption.state}],
			}]},
		},
		{
			"path": "roots/example/encryption.tf",
			"contents": {"terraform": [{"encryption": [{
				"key_provider": testdata.encryption.key_provider,
				"method": testdata.encryption.method,
				"plan": testdata.encryption.plan,
			}]}]},
		},
	]
}

test_state_declarations_do_not_leak_between_roots if {
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
				"encryption": [{
					"plan": testdata.encryption.plan,
					"state": testdata.encryption.state,
				}],
			}]},
		},
	]
	some m in msgs
	contains(m.msg, "roots/two")
	contains(m.msg, "terraform.encryption.state.method references")
}
