package lib.hcl

import rego.v1

test_directory_strips_the_file_name if {
	directory("roots/prd-tfstate/versions.tf") == "roots/prd-tfstate"
}

test_directory_of_a_top_level_file_is_empty if {
	directory("versions.tf") == ""
}

test_deref_unwraps_an_interpolation if {
	deref("${method.aes_gcm.plan}") == "method.aes_gcm.plan"
}

test_unresolved_detects_an_interpolation if {
	unresolved("${var.region}")
}

test_unresolved_rejects_a_literal if {
	not unresolved("auto")
}

test_unresolved_rejects_a_boolean if {
	not unresolved(true)
}

test_set_for_returns_the_entry if {
	set_for({"a": {1, 2}}, "a") == {1, 2}
}

test_set_for_defaults_to_the_empty_set if {
	set_for({"a": {1}}, "b") == set()
}

# `foo = { ... }` arrives as an object, `foo { ... }` as a list of objects.
test_blocks_wraps_an_object if {
	blocks({"s3": "https://example.com"}) == [{"s3": "https://example.com"}]
}

test_blocks_passes_a_list_through if {
	blocks([{"a": 1}, {"b": 2}]) == [{"a": 1}, {"b": 2}]
}

test_blocks_drops_non_objects_from_a_list if {
	blocks([{"a": 1}, "noise"]) == [{"a": 1}]
}

test_blocks_of_a_missing_attribute_is_empty if {
	blocks(null) == []
}

test_blocks_of_a_string_is_empty if {
	blocks("auto") == []
}

test_resources_flattens_every_file if {
	resources([
		{
			"path": "roots/example/r2.tf",
			"contents": {"resource": {"cloudflare_r2_bucket": {"state": [{"name": "tofu-state"}]}}},
		},
		{
			"path": "roots/example/dns.tf",
			"contents": {"resource": {"cloudflare_record": {"apex": [{"name": "@"}]}}},
		},
	]) == {
		{
			"path": "roots/example/r2.tf",
			"type": "cloudflare_r2_bucket",
			"name": "state",
			"body": {"name": "tofu-state"},
		},
		{
			"path": "roots/example/dns.tf",
			"type": "cloudflare_record",
			"name": "apex",
			"body": {"name": "@"},
		},
	}
}

test_resources_of_a_file_without_resources_is_empty if {
	resources([{
		"path": "roots/example/versions.tf",
		"contents": {"terraform": [{"required_version": ">= 1.12.4"}]},
	}]) == set()
}

test_address_joins_type_and_name if {
	address({"type": "cloudflare_r2_bucket", "name": "state"}) == "cloudflare_r2_bucket.state"
}

test_finding_carries_the_message_and_the_location if {
	finding("roots/example/versions.tf", "must set use_lockfile = true") == {
		"msg": "must set use_lockfile = true",
		"_loc": {"file": "roots/example/versions.tf", "line": 1},
	}
}
