package main

import data.lib.encryption
import data.lib.hcl
import rego.v1

# Reading the terraform.encryption block lives in data.lib.encryption, shared
# with state_encryption.rego next to it. This file is only the argument about
# plan files: a plan is an artifact that leaves the runner, so an unencrypted
# one hands every value it resolved to whatever ends up storing it.

plan_blocks(directory) := encryption.sub_blocks(directory, "plan")

warn contains hcl.finding(encryption.root_file(directory), message) if {
	some directory in hcl.roots
	count(hcl.set_for(encryption.blocks, directory)) == 0
	message := sprintf(
		"%s: terraform.encryption block is missing, so plan files are written in plaintext",
		[directory],
	)
}

warn contains hcl.finding(encryption.root_file(directory), message) if {
	some directory in hcl.roots
	count(hcl.set_for(encryption.blocks, directory)) > 0
	count(plan_blocks(directory)) == 0
	message := sprintf("%s: terraform.encryption is declared but has no plan{} sub-block", [directory])
}

warn contains hcl.finding(encryption.root_file(directory), message) if {
	some directory in hcl.roots
	some plan_block in plan_blocks(directory)
	not plan_block.method
	message := sprintf("%s: terraform.encryption.plan must set method", [directory])
}

# A literal `true` parses to a JSON boolean. `enforced = var.foo` arrives as
# "${var.foo}" and is rejected: it cannot be proven statically.
warn contains hcl.finding(encryption.root_file(directory), message) if {
	some directory in hcl.roots
	some plan_block in plan_blocks(directory)
	object.get(plan_block, "enforced", null) != true
	message := sprintf(
		"%s: terraform.encryption.plan must set enforced = true (got %v)",
		[directory, object.get(plan_block, "enforced", "<unset>")],
	)
}

warn contains hcl.finding(encryption.root_file(directory), message) if {
	some directory in hcl.roots
	some plan_block in plan_blocks(directory)
	reference := hcl.deref(plan_block.method)
	not reference in hcl.set_for(encryption.declared_methods, directory)
	message := sprintf(
		"%s: terraform.encryption.plan.method references %q, which is not a declared method block",
		[directory, reference],
	)
}

# Follows the chain plan{} actually depends on rather than auditing every
# method in the root, so that this policy only speaks about plan encryption.
# A method shared with state{} produces the identical message from both
# policies, and warn is a set, so the root is still reported once.
warn contains hcl.finding(encryption.root_file(directory), message) if {
	some directory in hcl.roots
	some plan_block in plan_blocks(directory)
	some method in encryption.method_key_refs(directory, hcl.deref(plan_block.method))
	not method.keys in hcl.set_for(encryption.declared_key_providers, directory)
	message := sprintf(
		"%s: method.%s keys references %q, which is not a declared key_provider block",
		[directory, method.name, method.keys],
	)
}
