package main

import data.lib.encryption
import data.lib.hcl
import rego.v1

# Reading the terraform.encryption block lives in data.lib.encryption, shared
# with state_encryption.rego next to it. This file is only the argument about
# plan files: a plan is an artifact that leaves the runner, so an unencrypted
# one hands every value it resolved to whatever ends up storing it.

plan_blocks(d) := encryption.sub_blocks(d, "plan")

warn contains hcl.finding(encryption.root_file(d), msg) if {
	some d in encryption.roots
	count(hcl.set_for(encryption.blocks, d)) == 0
	msg := sprintf(
		"%s: terraform.encryption block is missing, so plan files are written in plaintext",
		[d],
	)
}

warn contains hcl.finding(encryption.root_file(d), msg) if {
	some d in encryption.roots
	count(hcl.set_for(encryption.blocks, d)) > 0
	count(plan_blocks(d)) == 0
	msg := sprintf("%s: terraform.encryption is declared but has no plan{} sub-block", [d])
}

warn contains hcl.finding(encryption.root_file(d), msg) if {
	some d in encryption.roots
	some p in plan_blocks(d)
	not p.method
	msg := sprintf("%s: terraform.encryption.plan must set method", [d])
}

# A literal `true` parses to a JSON boolean. `enforced = var.foo` arrives as
# "${var.foo}" and is rejected: it cannot be proven statically.
warn contains hcl.finding(encryption.root_file(d), msg) if {
	some d in encryption.roots
	some p in plan_blocks(d)
	object.get(p, "enforced", null) != true
	msg := sprintf(
		"%s: terraform.encryption.plan must set enforced = true (got %v)",
		[d, object.get(p, "enforced", "<unset>")],
	)
}

warn contains hcl.finding(encryption.root_file(d), msg) if {
	some d in encryption.roots
	some p in plan_blocks(d)
	ref := hcl.deref(p.method)
	not ref in hcl.set_for(encryption.declared_methods, d)
	msg := sprintf(
		"%s: terraform.encryption.plan.method references %q, which is not a declared method block",
		[d, ref],
	)
}

# Follows the chain plan{} actually depends on rather than auditing every
# method in the root, so that this policy only speaks about plan encryption.
# A method shared with state{} produces the identical message from both
# policies, and warn is a set, so the root is still reported once.
warn contains hcl.finding(encryption.root_file(d), msg) if {
	some d in encryption.roots
	some p in plan_blocks(d)
	some enc in hcl.set_for(encryption.blocks, d)
	some mtype, by_name in object.get(enc, "method", {})
	some mname, bodies in by_name
	hcl.deref(p.method) == sprintf("method.%s.%s", [mtype, mname])
	some body in bodies
	ref := hcl.deref(object.get(body, "keys", ""))
	not ref in hcl.set_for(encryption.declared_key_providers, d)
	msg := sprintf(
		"%s: method.%s.%s keys references %q, which is not a declared key_provider block",
		[d, mtype, mname, ref],
	)
}
