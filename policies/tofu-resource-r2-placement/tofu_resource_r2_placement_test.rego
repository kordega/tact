package main

import data.lib.testdata
import rego.v1

test_compliant_bucket_is_allowed if {
	count(deny) == 0 with input as testdata.bucket_file(testdata.bucket)
}

test_other_resource_types_are_ignored if {
	count(deny) == 0 with input as testdata.resource_file("cloudflare_record", "apex", {"name": "@"})
}

test_missing_location_is_denied if {
	msgs := deny with input as testdata.bucket_without(["/location"])
	some m in msgs
	contains(m, "roots/example/r2.tf: cloudflare_r2_bucket.state must set location explicitly")
}

test_every_explicit_argument_is_reported if {
	msgs := deny with input as testdata.bucket_without(["/location", "/jurisdiction", "/storage_class"])
	count(msgs) == 3
	every argument, _ in explicit_arguments {
		some m in msgs
		contains(m, sprintf("must set %s explicitly", [argument]))
	}
}

test_missing_argument_names_its_reason if {
	msgs := deny with input as testdata.bucket_without(["/jurisdiction"])
	some m in msgs
	contains(m, "must set jurisdiction explicitly: R2 otherwise uses the default jurisdiction")
}

test_unknown_location_hint_is_denied if {
	msgs := deny with input as testdata.bucket_with({"location": "eu-central-1"})
	some m in msgs
	contains(m, "sets location = \"eu-central-1\", which is not one of apac, eeur, enam, oc, weur, wnam")
}

test_unknown_jurisdiction_is_denied if {
	msgs := deny with input as testdata.bucket_with({"jurisdiction": "pl"})
	some m in msgs
	contains(m, "sets jurisdiction = \"pl\", which is not one of default, eu, fedramp")
}

test_unknown_storage_class_is_denied if {
	msgs := deny with input as testdata.bucket_with({"storage_class": "Glacier"})
	some m in msgs
	contains(m, "sets storage_class = \"Glacier\", which is not one of InfrequentAccess, Standard")
}

test_infrequent_access_is_allowed if {
	count(deny) == 0 with input as testdata.bucket_with({"storage_class": "InfrequentAccess"})
}

# The value cannot be checked, only its presence: hcl2json renders
# `location = var.location` as "${var.location}".
test_location_from_a_variable_is_allowed if {
	count(deny) == 0 with input as testdata.bucket_with({"location": "${var.location}"})
}

test_several_buckets_are_reported_separately if {
	msgs := deny with input as [{
		"path": "roots/example/r2.tf",
		"contents": {"resource": {"cloudflare_r2_bucket": {
			"assets": [json.remove(testdata.bucket, ["/location"])],
			"state": [json.remove(testdata.bucket, ["/jurisdiction"])],
		}}},
	}]
	count(msgs) == 2
	some m in msgs
	contains(m, "cloudflare_r2_bucket.assets must set location")
	some n in msgs
	contains(n, "cloudflare_r2_bucket.state must set jurisdiction")
}
