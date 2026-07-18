package main

import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.

directory(path) := d if {
	parts := split(path, "/")
	d := concat("/", array.slice(parts, 0, count(parts) - 1))
}

terraform_blocks[d] contains block if {
	some file in input
	d := directory(file.path)
	some block in object.get(file.contents, "terraform", [])
}

roots contains d if {
	some d, blocks in terraform_blocks
	some block in blocks
	has_state_storage(block)
}

has_state_storage(block) if object.get(block, "backend", null) != null

has_state_storage(block) if object.get(block, "state_store", null) != null

encryption_blocks[d] contains enc if {
	some d in roots
	some block in terraform_blocks[d]
	some enc in object.get(block, "encryption", [])
}

plan_blocks[d] contains p if {
	some d in roots
	some enc in encryption_blocks[d]
	some p in object.get(enc, "plan", [])
}

declared_methods[d] contains ref if {
	some d in roots
	some enc in encryption_blocks[d]
	some mtype, by_name in object.get(enc, "method", {})
	some mname, _ in by_name
	ref := sprintf("method.%s.%s", [mtype, mname])
}

declared_key_providers[d] contains ref if {
	some d in roots
	some enc in encryption_blocks[d]
	some ktype, by_name in object.get(enc, "key_provider", {})
	some kname, _ in by_name
	ref := sprintf("key_provider.%s.%s", [ktype, kname])
}

# hcl2json renders any expression it cannot resolve statically as "${...}".
deref(v) := trim_suffix(trim_prefix(v, "${"), "}")

set_for(collection, d) := object.get(collection, d, set())

deny contains msg if {
	some d in roots
	count(set_for(encryption_blocks, d)) == 0
	msg := sprintf(
		"%s: terraform.encryption block is missing, so plan files are written in plaintext",
		[d],
	)
}

deny contains msg if {
	some d in roots
	count(set_for(encryption_blocks, d)) > 0
	count(set_for(plan_blocks, d)) == 0
	msg := sprintf("%s: terraform.encryption is declared but has no plan{} sub-block", [d])
}

deny contains msg if {
	some d in roots
	some p in set_for(plan_blocks, d)
	not p.method
	msg := sprintf("%s: terraform.encryption.plan must set method", [d])
}

# A literal `true` parses to a JSON boolean. `enforced = var.foo` arrives as
# "${var.foo}" and is rejected: it cannot be proven statically.
deny contains msg if {
	some d in roots
	some p in set_for(plan_blocks, d)
	object.get(p, "enforced", null) != true
	msg := sprintf(
		"%s: terraform.encryption.plan must set enforced = true (got %v)",
		[d, object.get(p, "enforced", "<unset>")],
	)
}

deny contains msg if {
	some d in roots
	some p in set_for(plan_blocks, d)
	ref := deref(p.method)
	not ref in set_for(declared_methods, d)
	msg := sprintf(
		"%s: terraform.encryption.plan.method references %q, which is not a declared method block",
		[d, ref],
	)
}

deny contains msg if {
	some d in roots
	some enc in set_for(encryption_blocks, d)
	some mtype, by_name in object.get(enc, "method", {})
	some mname, bodies in by_name
	some body in bodies
	ref := deref(object.get(body, "keys", ""))
	not ref in set_for(declared_key_providers, d)
	msg := sprintf(
		"%s: method.%s.%s keys references %q, which is not a declared key_provider block",
		[d, mtype, mname, ref],
	)
}
