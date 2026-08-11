# The shape of the terraform.encryption block, read once for every policy that
# has an opinion about it. Only the parsing lives here: what a plaintext plan
# file costs and what a plaintext state file costs are different arguments, so
# each policy spells its own warnings out rather than sharing a rule template.
#
# Which directories are roots is data.lib.hcl's answer, shared with every other
# library that has to tell a root from a module.
#
# Nothing here is evaluated at policy time: conftest only reads deny and warn
# out of package main.
package lib.encryption

import data.lib.hcl
import rego.v1

# The files each root spells a terraform block out in, for hcl.first_file to
# pick a finding's anchor from.
root_files[entry.directory] contains entry.path if {
	some entry in hcl.terraform_blocks
	entry.directory in hcl.roots
}

root_file(directory) := hcl.first_file(root_files, directory)

blocks[entry.directory] contains encryption_block if {
	some entry in hcl.terraform_blocks
	entry.directory in hcl.roots
	some encryption_block in object.get(entry.block, "encryption", [])
}

# The plan{} or state{} sub-blocks of a root, by kind. A root that declares
# neither gets the empty set, which is what the "sub-block is missing" rules
# key off.
sub_blocks(directory, kind) := {sub_block |
	some encryption_block in hcl.set_for(blocks, directory)
	some sub_block in object.get(encryption_block, kind, [])
}

declared_methods[directory] contains reference if {
	some directory in hcl.roots
	some encryption_block in hcl.set_for(blocks, directory)
	some method_type, by_name in object.get(encryption_block, "method", {})
	some method_name, _ in by_name
	reference := sprintf("method.%s.%s", [method_type, method_name])
}

declared_key_providers[directory] contains reference if {
	some directory in hcl.roots
	some encryption_block in hcl.set_for(blocks, directory)
	some provider_type, by_name in object.get(encryption_block, "key_provider", {})
	some provider_name, _ in by_name
	reference := sprintf("key_provider.%s.%s", [provider_type, provider_name])
}

# The key_provider each method{} named by `method_reference` points at, as
# {name, keys} where name is the "type.name" of the method. A plan{} or state{}
# sub-block depends on the one method it names, so following the chain from
# that reference is what keeps each policy speaking only about its own
# artifact rather than auditing every method in the root.
method_key_refs(directory, method_reference) := {key_reference |
	some encryption_block in hcl.set_for(blocks, directory)
	some method_type, by_name in object.get(encryption_block, "method", {})
	some method_name, bodies in by_name
	method_reference == sprintf("method.%s.%s", [method_type, method_name])
	some body in bodies
	key_reference := {
		"name": sprintf("%s.%s", [method_type, method_name]),
		"keys": hcl.deref(object.get(body, "keys", "")),
	}
}
