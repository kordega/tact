package main

import data.lib.hcl
import data.lib.r2
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# Where the bucket's objects physically live, under whose data residency rules,
# and at what price. All three arguments are optional in the provider, and all
# three defaults are a decision made on your behalf at create time and then
# frozen: none of them can be changed on an existing bucket.

# The value is the reason the default is not good enough.
explicit_arguments := {
	"location": "R2 otherwise derives the location hint from wherever the create call happened to originate, so the same configuration lands in a different place depending on who applied it first",
	"jurisdiction": "R2 otherwise uses the default jurisdiction, which carries no data residency guarantee",
	"storage_class": "R2 otherwise picks Standard, and the storage class of a bucket is a cost decision that belongs in review",
}

# https://developers.cloudflare.com/r2/reference/data-location/
allowed_values := {
	"location": {"apac", "eeur", "enam", "oc", "weur", "wnam"},
	"jurisdiction": {"default", "eu", "fedramp"},
	"storage_class": {"InfrequentAccess", "Standard"},
}

deny contains hcl.finding(bucket.path, msg) if {
	some bucket in r2.buckets
	some argument, reason in explicit_arguments
	object.get(bucket.body, argument, null) == null
	msg := sprintf(
		"%s: %s must set %s explicitly: %s",
		[bucket.path, hcl.address(bucket), argument, reason],
	)
}

# Only literals can be checked; hcl2json renders `location = var.location` as
# "${var.location}", which says nothing about the value it will take.
deny contains hcl.finding(bucket.path, msg) if {
	some bucket in r2.buckets
	some argument, allowed in allowed_values
	value := object.get(bucket.body, argument, null)
	is_string(value)
	not hcl.unresolved(value)
	not value in allowed
	msg := sprintf(
		"%s: %s sets %s = %q, which is not one of %s",
		[bucket.path, hcl.address(bucket), argument, value, concat(", ", sort(allowed))],
	)
}
