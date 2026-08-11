package main

import data.lib.encryption
import data.lib.hcl
import rego.v1

# Reading the terraform.encryption block lives in data.lib.encryption, shared
# with plan_encryption.rego next to it. This file is only the argument about
# state files: state outlives every run and holds the resolved value of everything
# the configuration ever touched, so an unencrypted one is a standing copy of
# those secrets in the bucket, readable by anyone who can read the bucket.

state_blocks(directory) := encryption.sub_blocks(directory, "state")

warn contains hcl.finding(encryption.root_file(directory), message) if {
	some directory in hcl.roots
	count(hcl.set_for(encryption.blocks, directory)) == 0
	message := sprintf(
		"%s: terraform.encryption block is missing, so state is written in plaintext",
		[directory],
	)
}

warn contains hcl.finding(encryption.root_file(directory), message) if {
	some directory in hcl.roots
	count(hcl.set_for(encryption.blocks, directory)) > 0
	count(state_blocks(directory)) == 0
	message := sprintf("%s: terraform.encryption is declared but has no state{} sub-block", [directory])
}

warn contains hcl.finding(encryption.root_file(directory), message) if {
	some directory in hcl.roots
	some state_block in state_blocks(directory)
	not state_block.method
	message := sprintf("%s: terraform.encryption.state must set method", [directory])
}

# A literal `true` parses to a JSON boolean. `enforced = var.foo` arrives as
# "${var.foo}" and is rejected: it cannot be proven statically.
#
# Without enforced, OpenTofu still reads and writes unencrypted state rather
# than failing, so a root that loses its key provider silently degrades to
# plaintext instead of stopping.
warn contains hcl.finding(encryption.root_file(directory), message) if {
	some directory in hcl.roots
	some state_block in state_blocks(directory)
	object.get(state_block, "enforced", null) != true
	message := sprintf(
		"%s: terraform.encryption.state must set enforced = true (got %v)",
		[directory, object.get(state_block, "enforced", "<unset>")],
	)
}

warn contains hcl.finding(encryption.root_file(directory), message) if {
	some directory in hcl.roots
	some state_block in state_blocks(directory)
	reference := hcl.deref(state_block.method)
	not reference in hcl.set_for(encryption.declared_methods, directory)
	message := sprintf(
		"%s: terraform.encryption.state.method references %q, which is not a declared method block",
		[directory, reference],
	)
}

# Follows the chain state{} actually depends on rather than auditing every
# method in the root, so that this policy only speaks about state encryption.
# A method shared with plan{} produces the identical message from both
# policies, and warn is a set, so the root is still reported once.
warn contains hcl.finding(encryption.root_file(directory), message) if {
	some directory in hcl.roots
	some state_block in state_blocks(directory)
	some method in encryption.method_key_refs(directory, hcl.deref(state_block.method))
	not method.keys in hcl.set_for(encryption.declared_key_providers, directory)
	message := sprintf(
		"%s: method.%s keys references %q, which is not a declared key_provider block",
		[directory, method.name, method.keys],
	)
}
