package main

import data.lib.testdata
import rego.v1

test_compliant_endpoint_is_allowed if {
	count(deny) == 0 with input as testdata.root(testdata.backend)
}

test_http_endpoint_is_denied if {
	msgs := deny with input as testdata.root_with({"endpoints": {"s3": "http://0123456789abcdef.r2.cloudflarestorage.com"}})
	some m in msgs
	contains(m, "must use https://")
}

test_credentials_in_the_endpoint_url_are_denied if {
	msgs := deny with input as testdata.root_with({"endpoints": {"s3": "https://key:secret@0123456789abcdef.r2.cloudflarestorage.com"}})
	some m in msgs
	contains(m, "must not carry credentials in the URL")
}

# The scheme separator must not be mistaken for a userinfo separator.
test_plain_endpoint_is_not_read_as_carrying_credentials if {
	msgs := deny with input as testdata.root(testdata.backend)
	every m in msgs {
		not contains(m, "must not carry credentials in the URL")
	}
}

test_interpolated_endpoint_is_denied if {
	msgs := deny with input as testdata.root_with({"endpoints": {"s3": "${var.r2_endpoint}"}})
	count(msgs) == 1
	some m in msgs
	contains(m, "a backend block cannot interpolate variables")
}

test_endpoints_written_as_a_block_is_detected if {
	count(deny) == 0 with input as testdata.root_with({"endpoints": [{"s3": "https://0123456789abcdef.r2.cloudflarestorage.com"}]})
}

test_legacy_endpoint_attribute_is_detected if {
	msgs := deny with input as testdata.root(object.union(
		json.remove(testdata.backend, ["/endpoints"]),
		{"endpoint": "http://0123456789abcdef.r2.cloudflarestorage.com"},
	))
	some m in msgs
	contains(m, "must use https://")
}

test_plain_aws_backend_is_ignored if {
	count(deny) == 0 with input as testdata.root({
		"bucket": "tofu-state",
		"key": "roots/example/terraform.tfstate",
		"region": "eu-central-1",
	})
}
