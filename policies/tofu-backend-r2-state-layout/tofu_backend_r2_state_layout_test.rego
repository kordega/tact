package main

import data.lib.testdata
import rego.v1

test_compliant_layout_is_allowed if {
	count(deny) == 0 with input as testdata.root(testdata.backend)
}

test_missing_bucket_is_denied if {
	msgs := deny with input as testdata.root_without(["/bucket"])
	some m in msgs
	contains(m.msg, "roots/example: R2 backend must set bucket")
}

test_missing_key_is_denied if {
	msgs := deny with input as testdata.root_without(["/key"])
	some m in msgs
	contains(m.msg, "roots/example: R2 backend must set key")
}

test_empty_key_is_denied if {
	msgs := deny with input as testdata.root_with({"key": ""})
	some m in msgs
	contains(m.msg, "must set key")
}

test_two_roots_sharing_one_state_object_are_denied if {
	msgs := deny with input as array.concat(
		testdata.root_at("roots/one/versions.tf", testdata.backend),
		testdata.root_at("roots/two/versions.tf", testdata.backend),
	)
	some m in msgs
	contains(m.msg, "\"tofu-state/roots/example/terraform.tfstate\" is claimed by more than one root")
	contains(m.msg, "roots/one, roots/two")
}

test_the_collision_is_reported_once_for_all_roots_involved if {
	msgs := deny with input as array.concat(
		testdata.root_at("roots/one/versions.tf", testdata.backend),
		array.concat(
			testdata.root_at("roots/two/versions.tf", testdata.backend),
			testdata.root_at("roots/three/versions.tf", testdata.backend),
		),
	)
	count(msgs) == 1
	some m in msgs
	contains(m.msg, "roots/one, roots/three, roots/two")
}

test_two_roots_with_distinct_keys_are_allowed if {
	count(deny) == 0 with input as array.concat(
		testdata.root_at("roots/one/versions.tf", object.union(testdata.backend, {"key": "roots/one/terraform.tfstate"})),
		testdata.root_at("roots/two/versions.tf", object.union(testdata.backend, {"key": "roots/two/terraform.tfstate"})),
	)
}

# Same key, different bucket, is a deliberate layout and not a collision.
test_same_key_in_different_buckets_is_allowed if {
	count(deny) == 0 with input as array.concat(
		testdata.root_at("roots/one/versions.tf", object.union(testdata.backend, {"bucket": "tofu-state-one"})),
		testdata.root_at("roots/two/versions.tf", object.union(testdata.backend, {"bucket": "tofu-state-two"})),
	)
}

test_plain_aws_backend_is_ignored if {
	count(deny) == 0 with input as testdata.root({"region": "eu-central-1"})
}
