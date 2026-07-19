package main

import data.lib.testdata
import rego.v1

test_compliant_backend_is_allowed if {
	count(deny) == 0 with input as testdata.root(testdata.backend)
}

test_missing_use_lockfile_is_denied if {
	msgs := deny with input as testdata.root_without(["/use_lockfile"])
	some m in msgs
	contains(m.msg, "must set use_lockfile = true (got <unset>)")
}

test_use_lockfile_false_is_denied if {
	msgs := deny with input as testdata.root_with({"use_lockfile": false})
	some m in msgs
	contains(m.msg, "must set use_lockfile = true (got false)")
}

test_use_lockfile_from_a_variable_is_denied if {
	msgs := deny with input as testdata.root_with({"use_lockfile": "${var.locking}"})
	some m in msgs
	contains(m.msg, "must set use_lockfile = true")
}

test_dynamodb_table_is_denied if {
	msgs := deny with input as testdata.root_with({"dynamodb_table": "tofu-locks"})
	some m in msgs
	contains(m.msg, "must not set dynamodb_table")
}

# The AWS pairing of a lock table with no lockfile is the case worth catching:
# it reads as locked and is not.
test_dynamodb_table_instead_of_lockfile_reports_both if {
	msgs := deny with input as testdata.root(object.union(
		json.remove(testdata.backend, ["/use_lockfile"]),
		{"dynamodb_table": "tofu-locks"},
	))
	count(msgs) == 2
	some m in msgs
	contains(m.msg, "must set use_lockfile = true")
	some n in msgs
	contains(n.msg, "must not set dynamodb_table")
}

test_plain_aws_backend_is_ignored if {
	count(deny) == 0 with input as testdata.root({
		"bucket": "tofu-state",
		"key": "roots/example/terraform.tfstate",
		"region": "eu-central-1",
		"dynamodb_table": "tofu-locks",
	})
}
