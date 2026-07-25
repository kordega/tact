package main

import data.lib.testdata
import rego.v1

test_compliant_backend_is_allowed if {
	count(deny) == 0 with input as testdata.root(testdata.backend)
}

test_every_required_true_setting_is_reported if {
	msgs := deny with input as testdata.root_without([
		"/skip_credentials_validation",
		"/skip_metadata_api_check",
		"/skip_region_validation",
		"/skip_requesting_account_id",
		"/skip_s3_checksum",
		"/use_path_style",
	])
	every setting, _ in required_true_settings {
		some m in msgs
		contains(m.msg, sprintf("must set %s = true", [setting]))
	}
}

test_missing_setting_names_its_reason if {
	msgs := deny with input as testdata.root_without(["/skip_s3_checksum"])
	some m in msgs
	contains(m.msg, "must set skip_s3_checksum = true (got <unset>): R2 rejects the trailing checksum")
}

test_required_setting_set_to_false_is_denied if {
	msgs := deny with input as testdata.root_with({"skip_s3_checksum": false})
	some m in msgs
	contains(m.msg, "must set skip_s3_checksum = true (got false)")
}

# hcl2json renders `skip_s3_checksum = var.skip` as "${var.skip}": it cannot be
# proven true here, so it is treated the same as false.
test_required_setting_from_a_variable_is_denied if {
	msgs := deny with input as testdata.root_with({"skip_s3_checksum": "${var.skip_checksum}"})
	some m in msgs
	contains(m.msg, "must set skip_s3_checksum = true")
}

test_wrong_region_is_denied if {
	msgs := deny with input as testdata.root_with({"region": "eu-central-1"})
	some m in msgs
	contains(m.msg, "must set region = \"auto\" (got eu-central-1)")
}

test_missing_region_is_denied if {
	msgs := deny with input as testdata.root_without(["/region"])
	some m in msgs
	contains(m.msg, "must set region = \"auto\" (got <unset>)")
}

test_plain_aws_backend_is_ignored if {
	count(deny) == 0 with input as testdata.root({
		"bucket": "tofu-state",
		"key": "roots/example/terraform.tfstate",
		"region": "eu-central-1",
	})
}

test_module_without_backend_is_ignored if {
	count(deny) == 0 with input as [{
		"path": "lib/modules/example/versions.tf",
		"contents": {"terraform": [{"required_version": ">= 1.12.4"}]},
	}]
}

test_only_the_offending_root_is_reported if {
	msgs := deny with input as array.concat(
		testdata.root_at("roots/good/versions.tf", object.union(testdata.backend, {"key": "roots/good/terraform.tfstate"})),
		testdata.root_at("roots/bad/versions.tf", json.remove(
			object.union(testdata.backend, {"key": "roots/bad/terraform.tfstate"}),
			["/skip_s3_checksum"],
		)),
	)
	count(msgs) == 1
	some m in msgs
	contains(m.msg, "roots/bad")
}

# Unlike terraform.encryption, two backend blocks in one root do not merge:
# tofu accepts exactly one, so each body is judged on its own.
test_settings_split_across_files_are_not_merged if {
	msgs := deny with input as [
		{
			"path": "roots/example/versions.tf",
			"contents": {"terraform": [{
				"backend": {"s3": [json.remove(testdata.backend, ["/skip_s3_checksum"])]},
				"encryption": [testdata.encryption],
			}]},
		},
		{
			"path": "roots/example/backend.tf",
			"contents": {"terraform": [{"backend": {"s3": [{"skip_s3_checksum": true}]}}]},
		},
	]
	some m in msgs
	contains(m.msg, "must set skip_s3_checksum = true")
}
