# Helpers shared by the policies in this bundle. Everything here is about the
# shape hcl2json produces for a conftest --combine run, not about any single
# rule.
package lib.hcl

import rego.v1

# roots/prd-tfstate/versions.tf -> roots/prd-tfstate
directory(path) := d if {
	parts := split(path, "/")
	d := concat("/", array.slice(parts, 0, count(parts) - 1))
}

# hcl2json renders any expression it cannot resolve statically as "${...}".
deref(v) := trim_suffix(trim_prefix(v, "${"), "}")

unresolved(v) if {
	is_string(v)
	startswith(v, "${")
}

set_for(collection, key) := object.get(collection, key, set())

# hcl2json renders `foo { ... }` blocks as a list of objects and `foo = { ... }`
# attributes as a bare object. Rules that accept both spellings normalise here.
blocks(v) := [v] if is_object(v)

blocks(v) := [x | some x in v; is_object(x)] if is_array(v)

blocks(v) := [] if {
	not is_object(v)
	not is_array(v)
}

# Flattens `resource "type" "name" { ... }` across every file in the combined
# input into {path, type, name, body} records.
resources(files) := {r |
	some file in files
	some rtype, by_name in object.get(file.contents, "resource", {})
	some rname, bodies in by_name
	some body in blocks(bodies)
	r := {
		"path": file.path,
		"type": rtype,
		"name": rname,
		"body": body,
	}
}

address(resource) := sprintf("%s.%s", [resource.type, resource.name])
