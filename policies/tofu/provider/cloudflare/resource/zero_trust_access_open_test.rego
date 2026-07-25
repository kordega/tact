package main

import data.lib.testdata
import rego.v1

test_allow_everyone_without_require_is_denied if {
	msgs := deny with input as testdata.access_policy_with({"include": [{"everyone": {}}]})
	some m in msgs
	contains(m.msg, "cloudflare_zero_trust_access_policy.p decides \"allow\" for an include of everyone")
	contains(m.msg, "entire internet")
}

# everyone AND a require still narrows to whoever satisfies the require, so it is
# not an open door.
test_allow_everyone_with_a_require_is_allowed if {
	count(deny) == 0 with input as testdata.access_policy_with({
		"include": [{"everyone": {}}],
		"require": [{"login_method": {"id": "${var.mfa}"}}],
	})
}

# The compliant base admits one email domain, not everyone.
test_a_named_include_is_allowed if {
	count(deny) == 0 with input as testdata.access_policy_with({})
}

# everyone under a "deny" decision blocks the internet rather than admitting it.
test_deny_decision_with_everyone_is_allowed if {
	count(deny) == 0 with input as testdata.access_policy_with({
		"decision": "deny",
		"include": [{"everyone": {}}],
	})
}

# `decision = var.decision` renders as "${var.decision}", which is not "allow".
test_a_decision_from_a_variable_stands_the_rule_down if {
	count(deny) == 0 with input as testdata.access_policy_with({
		"decision": "${var.decision}",
		"include": [{"everyone": {}}],
	})
}
