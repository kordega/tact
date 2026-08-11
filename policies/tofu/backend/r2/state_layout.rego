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

deny contains hcl.finding(r2.backend_file(directory), message) if {
	some directory in r2.roots
	some body in hcl.set_for(r2.backend_bodies, directory)
	some setting in {"bucket", "key"}
	object.get(body, setting, "") == ""
	message := sprintf("%s: R2 backend must set %s", [directory, setting])
}

state_objects[location] contains directory if {
	some directory in r2.roots
	some body in hcl.set_for(r2.backend_bodies, directory)
	bucket := object.get(body, "bucket", "")
	bucket != ""
	key := object.get(body, "key", "")
	key != ""
	location := sprintf("%s/%s", [bucket, key])
}

# The collision belongs to every root that claims the object, so there is no
# one file it happened in. It anchors to the first of them and names the rest
# in the message, which at least puts the finding next to one of the two
# backends that have to change.
deny contains hcl.finding(r2.backend_file(min(directories)), message) if {
	some location, directories in state_objects
	count(directories) > 1
	message := sprintf(
		"R2 state object %q is claimed by more than one root (%s): give each root its own key",
		[location, concat(", ", sort(directories))],
	)
}
