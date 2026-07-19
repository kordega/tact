# The shape of the terraform.encryption block, read once for every policy that
# has an opinion about it. Only the parsing lives here: what a plaintext plan
# file costs and what a plaintext state file costs are different arguments, so
# each policy spells its own warnings out rather than sharing a rule template.
#
# Nothing here is evaluated at policy time: conftest only reads deny and warn
# out of package main.
package lib.encryption

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

blocks[d] contains enc if {
	some d in roots
	some block in terraform_blocks[d]
	some enc in object.get(block, "encryption", [])
}

# The plan{} or state{} sub-blocks of a root, by kind. A root that declares
# neither gets the empty set, which is what the "sub-block is missing" rules
# key off.
sub_blocks(d, kind) := {sub |
	some enc in hcl.set_for(blocks, d)
	some sub in object.get(enc, kind, [])
}

declared_methods[d] contains ref if {
	some d in roots
	some enc in blocks[d]
	some mtype, by_name in object.get(enc, "method", {})
	some mname, _ in by_name
	ref := sprintf("method.%s.%s", [mtype, mname])
}

declared_key_providers[d] contains ref if {
	some d in roots
	some enc in blocks[d]
	some ktype, by_name in object.get(enc, "key_provider", {})
	some kname, _ in by_name
	ref := sprintf("key_provider.%s.%s", [ktype, kname])
}
