package main

import data.lib.testdata
import rego.v1

cors_file(rules) := testdata.resource_file("cloudflare_r2_bucket_cors", "assets", {
	"bucket_name": "assets",
	"rules": rules,
})

test_compliant_bucket_is_allowed if {
	count(deny) == 0 with input as testdata.bucket_file(testdata.bucket)
}

test_managed_domain_enabled_is_denied if {
	msgs := deny with input as testdata.resource_file("cloudflare_r2_managed_domain", "state", {
		"bucket_name": "tofu-state",
		"enabled": true,
	})
	some m in msgs
	contains(m, "cloudflare_r2_managed_domain.state enables the managed r2.dev domain")
	contains(m, "serves bucket tofu-state to anonymous callers")
}

test_managed_domain_disabled_is_allowed if {
	count(deny) == 0 with input as testdata.resource_file("cloudflare_r2_managed_domain", "state", {
		"bucket_name": "tofu-state",
		"enabled": false,
	})
}

# `enabled = var.public` cannot be proven to be true, and this policy only
# reports what it can prove.
test_managed_domain_from_a_variable_is_allowed if {
	count(deny) == 0 with input as testdata.resource_file("cloudflare_r2_managed_domain", "state", {
		"bucket_name": "tofu-state",
		"enabled": "${var.public}",
	})
}

test_custom_domain_is_allowed if {
	count(deny) == 0 with input as testdata.resource_file("cloudflare_r2_custom_domain", "assets", {
		"bucket_name": "assets",
		"domain": "assets.example.com",
		"enabled": true,
	})
}

test_wildcard_cors_origin_is_denied if {
	msgs := deny with input as cors_file([{"allowed": {
		"methods": ["GET"],
		"origins": ["https://example.com", "*"],
	}}])
	some m in msgs
	contains(m, "cloudflare_r2_bucket_cors.assets allows CORS origin \"*\"")
}

# Same rule written with block syntax: hcl2json renders `allowed` as a list.
test_wildcard_cors_origin_in_block_syntax_is_denied if {
	msgs := deny with input as cors_file([{"allowed": [{"origins": ["*"]}]}])
	some m in msgs
	contains(m, "allows CORS origin \"*\"")
}

test_wildcard_cors_header_is_denied if {
	msgs := deny with input as cors_file([{"allowed": {
		"headers": ["*"],
		"methods": ["GET"],
		"origins": ["https://example.com"],
	}}])
	some m in msgs
	contains(m, "allows CORS header \"*\"")
}

test_wildcard_in_a_later_rule_is_denied if {
	msgs := deny with input as cors_file([
		{"allowed": {
			"methods": ["GET"],
			"origins": ["https://example.com"],
		}},
		{"allowed": {
			"methods": ["PUT"],
			"origins": ["*"],
		}},
	])
	some m in msgs
	contains(m, "allows CORS origin \"*\"")
}

test_named_cors_origins_are_allowed if {
	count(deny) == 0 with input as cors_file([{"allowed": {
		"headers": ["content-type"],
		"methods": ["GET"],
		"origins": ["https://example.com"],
	}}])
}
