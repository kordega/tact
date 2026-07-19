package main

import data.lib.encryption
import data.lib.hcl
import rego.v1

# Reading the terraform.encryption block lives in data.lib.encryption, shared
# with tofu/backend/plan/encryption. This file is only the argument about state
# files: state outlives every run and holds the resolved value of everything
# the configuration ever touched, so an unencrypted one is a standing copy of
# those secrets in the bucket, readable by anyone who can read the bucket.

state_blocks(d) := encryption.sub_blocks(d, "state")

warn contains hcl.finding(encryption.root_file(d), msg) if {
	some d in encryption.roots
	count(hcl.set_for(encryption.blocks, d)) == 0
	msg := sprintf(
		"%s: terraform.encryption block is missing, so state is written in plaintext",
		[d],
	)
}

warn contains hcl.finding(encryption.root_file(d), msg) if {
	some d in encryption.roots
	count(hcl.set_for(encryption.blocks, d)) > 0
	count(state_blocks(d)) == 0
	msg := sprintf("%s: terraform.encryption is declared but has no state{} sub-block", [d])
}

warn contains hcl.finding(encryption.root_file(d), msg) if {
	some d in encryption.roots
	some s in state_blocks(d)
	not s.method
	msg := sprintf("%s: terraform.encryption.state must set method", [d])
}

# A literal `true` parses to a JSON boolean. `enforced = var.foo` arrives as
# "${var.foo}" and is rejected: it cannot be proven statically.
#
# Without enforced, OpenTofu still reads and writes unencrypted state rather
# than failing, so a root that loses its key provider silently degrades to
# plaintext instead of stopping.
warn contains hcl.finding(encryption.root_file(d), msg) if {
	some d in encryption.roots
	some s in state_blocks(d)
	object.get(s, "enforced", null) != true
	msg := sprintf(
		"%s: terraform.encryption.state must set enforced = true (got %v)",
		[d, object.get(s, "enforced", "<unset>")],
	)
}

warn contains hcl.finding(encryption.root_file(d), msg) if {
	some d in encryption.roots
	some s in state_blocks(d)
	ref := hcl.deref(s.method)
	not ref in hcl.set_for(encryption.declared_methods, d)
	msg := sprintf(
		"%s: terraform.encryption.state.method references %q, which is not a declared method block",
		[d, ref],
	)
}

# Follows the chain state{} actually depends on rather than auditing every
# method in the root, so that this policy only speaks about state encryption.
# A method shared with plan{} produces the identical message from both
# policies, and warn is a set, so the root is still reported once.
warn contains hcl.finding(encryption.root_file(d), msg) if {
	some d in encryption.roots
	some s in state_blocks(d)
	some enc in hcl.set_for(encryption.blocks, d)
	some mtype, by_name in object.get(enc, "method", {})
	some mname, bodies in by_name
	hcl.deref(s.method) == sprintf("method.%s.%s", [mtype, mname])
	some body in bodies
	ref := hcl.deref(object.get(body, "keys", ""))
	not ref in hcl.set_for(encryption.declared_key_providers, d)
	msg := sprintf(
		"%s: method.%s.%s keys references %q, which is not a declared key_provider block",
		[d, mtype, mname, ref],
	)
}
