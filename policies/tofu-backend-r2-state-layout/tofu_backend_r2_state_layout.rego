package main

import data.lib.hcl
import data.lib.r2
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# Where each root keeps its state object. bucket and key have no defaults worth
# inheriting, and two roots pointed at one object destroy each other's
# resources on every apply while both plans look clean, which is the reason
# this policy reads the whole repository at once rather than one root at a time.

deny contains msg if {
	some d in r2.roots
	some body in hcl.set_for(r2.backend_bodies, d)
	some setting in {"bucket", "key"}
	object.get(body, setting, "") == ""
	msg := sprintf("%s: R2 backend must set %s", [d, setting])
}

state_objects[location] contains d if {
	some d in r2.roots
	some body in hcl.set_for(r2.backend_bodies, d)
	bucket := object.get(body, "bucket", "")
	key := object.get(body, "key", "")
	bucket != ""
	key != ""
	location := sprintf("%s/%s", [bucket, key])
}

deny contains msg if {
	some location, dirs in state_objects
	count(dirs) > 1
	msg := sprintf(
		"R2 state object %q is claimed by more than one root (%s): give each root its own key",
		[location, concat(", ", sort(dirs))],
	)
}
