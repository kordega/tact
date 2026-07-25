package main

import data.lib.testdata
import rego.v1

# The nested "account -> { zone.* = "*" }" spelling, which grants the token over
# every zone in the account.
test_all_zones_wildcard_is_warned_about if {
	msgs := warn with input as testdata.api_token(
		"allow",
		{"com.cloudflare.api.account.${var.account_id}": {"com.cloudflare.api.account.zone.*": "*"}},
	)
	some m in msgs
	contains(m.msg, "cloudflare_api_token.ci grants \"com.cloudflare.api.account.zone.*\" = \"*\"")
}

# The flat account-wide wildcard.
test_all_accounts_wildcard_is_warned_about if {
	msgs := warn with input as testdata.api_token("allow", {"com.cloudflare.api.account.*": "*"})
	some m in msgs
	contains(m.msg, "grants \"com.cloudflare.api.account.*\" = \"*\"")
}

# A key naming one zone ends in the zone id, not ".*", so it is left alone.
test_a_named_zone_is_allowed if {
	count(warn) == 0 with input as testdata.api_token(
		"allow",
		{"com.cloudflare.api.account.zone.023e105f4ecef8ad9ca31a8372d0c353": "*"},
	)
}

# A deny statement narrowing a broad allow is not the exposure this rule is about.
test_a_deny_effect_wildcard_is_allowed if {
	count(warn) == 0 with input as testdata.api_token("deny", {"com.cloudflare.api.account.zone.*": "*"})
}

# `resources = { "...zone.*" = var.grant }` renders the grant as "${var.grant}",
# which is not "*", so the rule stands down.
test_a_wildcard_from_a_variable_stands_the_rule_down if {
	count(warn) == 0 with input as testdata.api_token(
		"allow",
		{"com.cloudflare.api.account.zone.*": "${var.grant}"},
	)
}

# effect is optional and defaults to allow, so a statement that omits it still
# grants and is still reported.
test_a_missing_effect_defaults_to_allow_and_is_warned_about if {
	token := testdata.resource_file("cloudflare_api_token", "ci", {
		"name": "ci",
		"policies": [{"resources": {"com.cloudflare.api.account.zone.*": "*"}}],
	})
	msgs := warn with input as token
	some m in msgs
	contains(m.msg, "\"com.cloudflare.api.account.zone.*\" = \"*\"")
}
