package main

import data.lib.testdata
import rego.v1

test_compliant_bucket_is_allowed if {
	count(deny) == 0 with input as testdata.bucket_file(testdata.bucket)
}

test_missing_lifecycle_is_denied if {
	msgs := deny with input as testdata.bucket_without(["/lifecycle"])
	some m in msgs
	contains(m, "cloudflare_r2_bucket.state must declare lifecycle { prevent_destroy = true }")
}

test_prevent_destroy_false_is_denied if {
	msgs := deny with input as testdata.bucket_with({"lifecycle": [{"prevent_destroy": false}]})
	some m in msgs
	contains(m, "must declare lifecycle { prevent_destroy = true }")
}

test_lifecycle_without_prevent_destroy_is_denied if {
	msgs := deny with input as testdata.bucket_with({"lifecycle": [{"ignore_changes": ["${name}"]}]})
	some m in msgs
	contains(m, "must declare lifecycle { prevent_destroy = true }")
}

test_prevent_destroy_alongside_other_meta_arguments_is_allowed if {
	count(deny) == 0 with input as testdata.bucket_with({"lifecycle": [{
		"ignore_changes": ["${name}"],
		"prevent_destroy": true,
	}]})
}

test_disabled_bucket_lock_rule_is_denied if {
	msgs := deny with input as testdata.resource_file("cloudflare_r2_bucket_lock", "state", {
		"bucket_name": "tofu-state",
		"rules": [{
			"id": "retain-30-days",
			"enabled": false,
		}],
	})
	some m in msgs
	contains(m, "cloudflare_r2_bucket_lock.state declares a bucket lock rule with enabled = false")
}

test_enabled_bucket_lock_rule_is_allowed if {
	count(deny) == 0 with input as testdata.resource_file("cloudflare_r2_bucket_lock", "state", {
		"bucket_name": "tofu-state",
		"rules": [{
			"id": "retain-30-days",
			"enabled": true,
		}],
	})
}

test_other_resource_types_are_ignored if {
	count(deny) == 0 with input as testdata.resource_file("cloudflare_record", "apex", {"name": "@"})
}
