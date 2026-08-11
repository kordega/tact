package lib.r2

import data.lib.testdata
import rego.v1

# Detection is tested once, here. Each R2 policy then tests its own rule
# against a root it can assume is already recognised as R2.

test_documented_endpoint_attribute_is_detected if {
	roots == {"roots/example"} with input as testdata.root(testdata.backend)
}

test_endpoints_written_as_a_block_is_detected if {
	roots == {"roots/example"} with input as testdata.root_with({"endpoints": [{"s3": "https://0123456789abcdef.r2.cloudflarestorage.com"}]})
}

test_legacy_endpoint_attribute_is_detected if {
	roots == {"roots/example"} with input as testdata.root(object.union(
		json.remove(testdata.backend, ["/endpoints"]),
		{"endpoint": "https://0123456789abcdef.r2.cloudflarestorage.com"},
	))
}

test_plain_aws_backend_is_not_an_r2_root if {
	roots == set() with input as testdata.root({
		"bucket": "tofu-state",
		"region": "eu-central-1",
	})
}

# A bucket named after R2 does not make the backend R2; only the host does.
test_lookalike_endpoint_is_not_an_r2_root if {
	roots == set() with input as testdata.root_with({"endpoints": {"s3": "https://s3.eu-central-1.amazonaws.com"}})
}

test_a_module_without_a_backend_is_not_a_root if {
	roots == set() with input as [{
		"path": "lib/modules/example/versions.tf",
		"contents": {"terraform": [{"required_version": ">= 1.12.4"}]},
	}]
}

test_each_root_is_detected_separately if {
	roots == {"roots/one", "roots/two"} with input as array.concat(
		testdata.root_at("roots/one/versions.tf", testdata.backend),
		testdata.root_at("roots/two/versions.tf", testdata.backend),
	)
}

test_backend_bodies_are_keyed_by_root if {
	backend_bodies == {"roots/example": {testdata.backend}} with input as testdata.root(testdata.backend)
}

test_backend_bodies_of_a_non_r2_root_are_not_collected if {
	backend_bodies == {} with input as testdata.root({"region": "eu-central-1"})
}

test_only_the_r2_endpoints_are_collected if {
	account_endpoints == {"roots/example": {"https://0123456789abcdef.r2.cloudflarestorage.com"}} with input as testdata.root(testdata.backend)
}

test_buckets_are_collected_with_their_address if {
	buckets == {{
		"path": "roots/example/r2.tf",
		"type": "cloudflare_r2_bucket",
		"name": "state",
		"body": testdata.bucket,
	}} with input as testdata.bucket_file(testdata.bucket)
}

test_resources_of_type_filters_by_type if {
	found := resources_of_type("cloudflare_r2_managed_domain") with input as testdata.resource_file("cloudflare_r2_managed_domain", "state", {"enabled": true})
	count(found) == 1
}

test_resources_of_an_absent_type_is_empty if {
	resources_of_type("cloudflare_r2_bucket_lock") == set() with input as testdata.bucket_file(testdata.bucket)
}

test_backend_file_is_the_file_the_backend_is_declared_in if {
	backend_file("roots/example") == "roots/example/versions.tf" with input as testdata.root(testdata.backend)
}

# A root that splits its terraform blocks across files has to resolve to one of
# them and always the same one, otherwise a single finding is reported once per
# file that happens to mention the backend.
test_backend_file_picks_one_file_for_a_split_root if {
	backend_file("roots/example") == "roots/example/backend.tf" with input as array.concat(
		testdata.root_at("roots/example/backend.tf", testdata.backend),
		testdata.root_at("roots/example/versions.tf", testdata.backend),
	)
}
