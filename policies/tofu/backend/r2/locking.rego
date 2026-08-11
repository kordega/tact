package main

import data.lib.hcl
import data.lib.r2
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# Without a lock, two applies that overlap both read the same state, both write
# it, and the second silently drops whatever the first created. Nothing in the
# plan output hints at it. On AWS the lock came from a DynamoDB table; against
# R2 it comes from use_lockfile, which takes the lock through a conditional
# write on the state object itself.

deny contains hcl.finding(r2.backend_file(directory), message) if {
	some directory in r2.roots
	some body in hcl.set_for(r2.backend_bodies, directory)
	object.get(body, "use_lockfile", null) != true
	message := sprintf(
		"%s: R2 backend must set use_lockfile = true (got %v), otherwise two applies write the same state with no lock between them",
		[directory, object.get(body, "use_lockfile", "<unset>")],
	)
}

deny contains hcl.finding(r2.backend_file(directory), message) if {
	some directory in r2.roots
	some body in hcl.set_for(r2.backend_bodies, directory)
	object.get(body, "dynamodb_table", null) != null
	message := sprintf(
		"%s: R2 backend must not set dynamodb_table, there is no DynamoDB behind R2; locking comes from use_lockfile = true",
		[directory],
	)
}
