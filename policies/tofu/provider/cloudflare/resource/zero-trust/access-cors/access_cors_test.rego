package main

import data.lib.testdata
import rego.v1

test_all_origins_with_credentials_is_denied if {
	msgs := deny with input as testdata.access_app_cors({
		"allow_all_origins": true,
		"allow_credentials": true,
	})
	some m in msgs
	contains(m.msg, "cloudflare_zero_trust_access_application.app sets cors_headers with allow_all_origins and allow_credentials both true")
}

# Reflecting any origin without credentials cannot relay a session, so it is not
# the exposure this rule is about.
test_all_origins_without_credentials_is_allowed if {
	count(deny) == 0 with input as testdata.access_app_cors({
		"allow_all_origins": true,
		"allow_credentials": false,
	})
}

# Credentials with a named origin list is the ordinary, safe shape.
test_credentials_with_named_origins_is_allowed if {
	count(deny) == 0 with input as testdata.access_app_cors({
		"allowed_origins": ["https://app.example.com"],
		"allow_credentials": true,
	})
}

# `allow_all_origins = var.x` renders as "${var.x}", which is not true.
test_all_origins_from_a_variable_stands_the_rule_down if {
	count(deny) == 0 with input as testdata.access_app_cors({
		"allow_all_origins": "${var.all}",
		"allow_credentials": true,
	})
}
