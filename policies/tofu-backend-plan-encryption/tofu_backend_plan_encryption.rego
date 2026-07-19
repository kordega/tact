package main

import data.lib.hcl
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.

terraform_blocks[d] contains block if {
	some file in input
	d := hcl.directory(file.path)
	some block in object.get(file.contents, "terraform", [])
}

roots contains d if {
	some d, blocks in terraform_blocks
	some block in blocks
	has_state_storage(block)
}

# The files each root spells a terraform block out in. A root is a directory
# and has no file of its own to point a finding at, so it borrows one of these.
# Roots that split the block across files get the first by name, chosen the
# same way every run so that one problem is not reported once per file.
root_files[d] contains file.path if {
	some file in input
	d := hcl.directory(file.path)
	some _ in object.get(file.contents, "terraform", [])
}

root_file(d) := min(hcl.set_for(root_files, d))

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

deny contains hcl.finding(root_file(d), msg) if {
	some d in roots
	count(hcl.set_for(encryption_blocks, d)) == 0
	msg := sprintf(
		"%s: terraform.encryption block is missing, so plan files are written in plaintext",
		[d],
	)
}

deny contains hcl.finding(root_file(d), msg) if {
	some d in roots
	count(hcl.set_for(encryption_blocks, d)) > 0
	count(hcl.set_for(plan_blocks, d)) == 0
	msg := sprintf("%s: terraform.encryption is declared but has no plan{} sub-block", [d])
}

deny contains hcl.finding(root_file(d), msg) if {
	some d in roots
	some p in hcl.set_for(plan_blocks, d)
	not p.method
	msg := sprintf("%s: terraform.encryption.plan must set method", [d])
}

# A literal `true` parses to a JSON boolean. `enforced = var.foo` arrives as
# "${var.foo}" and is rejected: it cannot be proven statically.
deny contains hcl.finding(root_file(d), msg) if {
	some d in roots
	some p in hcl.set_for(plan_blocks, d)
	object.get(p, "enforced", null) != true
	msg := sprintf(
		"%s: terraform.encryption.plan must set enforced = true (got %v)",
		[d, object.get(p, "enforced", "<unset>")],
	)
}

deny contains hcl.finding(root_file(d), msg) if {
	some d in roots
	some p in hcl.set_for(plan_blocks, d)
	ref := hcl.deref(p.method)
	not ref in hcl.set_for(declared_methods, d)
	msg := sprintf(
		"%s: terraform.encryption.plan.method references %q, which is not a declared method block",
		[d, ref],
	)
}

deny contains hcl.finding(root_file(d), msg) if {
	some d in roots
	some enc in hcl.set_for(encryption_blocks, d)
	some mtype, by_name in object.get(enc, "method", {})
	some mname, bodies in by_name
	some body in bodies
	ref := hcl.deref(object.get(body, "keys", ""))
	not ref in hcl.set_for(declared_key_providers, d)
	msg := sprintf(
		"%s: method.%s.%s keys references %q, which is not a declared key_provider block",
		[d, mtype, mname, ref],
	)
}
