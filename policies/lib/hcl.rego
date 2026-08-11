# Helpers shared by the policies in this bundle. Everything here is about the
# shape hcl2json produces for a conftest --combine run, not about any single
# rule.
#
# Nothing here is evaluated at policy time: conftest only reads deny and warn
# out of package main.
package lib.hcl

import rego.v1

# roots/prd-tfstate/versions.tf -> roots/prd-tfstate
directory(path) := concat("/", array.slice(segments, 0, count(segments) - 1)) if {
	segments := split(path, "/")
}

# hcl2json renders any expression it cannot resolve statically as "${...}".
deref(value) := trim_suffix(trim_prefix(value, "${"), "}")

unresolved(value) if {
	is_string(value)
	startswith(value, "${")
}

set_for(collection, key) := object.get(collection, key, set())

# A rule about a directory has no file of its own to point a finding at, so it
# borrows one of the files the directory declares the thing in. Directories
# that split a declaration across files get the first by name, chosen the same
# way every run so that one problem is not reported once per file.
first_file(files_by_directory, directory) := min(set_for(files_by_directory, directory))

# Every terraform{} block in the combined input, carried with the file it was
# written in and the directory that file belongs to. Every library that reads
# the terraform block - the backend, the encryption block, required_providers -
# starts from this one walk.
#
# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
terraform_blocks contains entry if {
	some file in input
	some block in object.get(file.contents, "terraform", [])
	entry := {
		"path": file.path,
		"directory": directory(file.path),
		"block": block,
	}
}

# A root is the directory that gets applied, and the only one that owns the
# state. Matching on the state storage rather than on a roots/ path prefix is
# what makes this survive the action's chroot-directory input, which can leave
# the prefix out of the paths the policies ever see.
roots contains entry.directory if {
	some entry in terraform_blocks
	declares_state_storage(entry.block)
}

# backend{} is the classic spelling and state_store{} the pluggable one
# OpenTofu 1.11 added. Either makes the directory a root.
declares_state_storage(block) if object.get(block, "backend", null) != null

declares_state_storage(block) if object.get(block, "state_store", null) != null

# hcl2json renders `foo { ... }` blocks as a list of objects and `foo = { ... }`
# attributes as a bare object. Rules that accept both spellings normalise here.
blocks(value) := [value] if is_object(value)

blocks(value) := [element | some element in value; is_object(element)] if is_array(value)

blocks(value) := [] if {
	not is_object(value)
	not is_array(value)
}

# Flattens `resource "type" "name" { ... }` across every file in the combined
# input into {path, type, name, body} records.
resources(files) := {resource |
	some file in files
	some resource_type, by_name in object.get(file.contents, "resource", {})
	some resource_name, bodies in by_name
	some body in blocks(bodies)
	resource := {
		"path": file.path,
		"type": resource_type,
		"name": resource_name,
		"body": body,
	}
}

resources_of_type(files, resource_type) := {resource |
	some resource in resources(files)
	resource.type == resource_type
}

address(resource) := sprintf("%s.%s", [resource.type, resource.name])

# conftest reads _loc out of a finding and anchors its annotation to that file,
# which is the difference between a comment on the pull request diff and a line
# at the bottom of the run. The path stays in the message too, because every
# other output format ignores _loc.
#
# The key is spelled _loc as of conftest 0.68.2 and loc on its main branch, so
# raising conftest-version without revisiting this quietly drops the anchor.
#
# The line is always 1. hcl2json resolves the configuration into JSON and drops
# the offsets on the way, so there is no real line to report, and an annotation
# without one is not addressed to anywhere in the file.
finding(path, message) := {"msg": message, "_loc": {"file": path, "line": 1}}
