package main

import data.lib.hcl
import data.lib.r2
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# Destroying an R2 bucket takes its objects with it, and there is no undo. The
# same goes for the arguments that cannot be updated in place - name, location
# and jurisdiction - where an edit plans as destroy-and-recreate rather than as
# the rename it looks like in the diff. prevent_destroy turns all of that into
# a failed plan instead of an outage.

deny contains msg if {
	some bucket in r2.buckets
	not lifecycle_prevents_destroy(bucket.body)
	msg := sprintf(
		"%s: %s must declare lifecycle { prevent_destroy = true }, destroying a bucket takes its objects with it",
		[bucket.path, hcl.address(bucket)],
	)
}

lifecycle_prevents_destroy(body) if {
	some lifecycle in hcl.blocks(object.get(body, "lifecycle", null))
	object.get(lifecycle, "prevent_destroy", null) == true
}

# The same reasoning one level down: a bucket-lock rule is what stops an object
# from being deleted before its retention expires, so a lock resource that is
# declared and then disabled is worse than none, it reads as protection.
deny contains msg if {
	some lock in r2.resources_of_type("cloudflare_r2_bucket_lock")
	some rule in hcl.blocks(object.get(lock.body, "rules", null))
	object.get(rule, "enabled", null) == false
	msg := sprintf(
		"%s: %s declares a bucket lock rule with enabled = false, which protects nothing; drop the rule or enable it",
		[lock.path, hcl.address(lock)],
	)
}
