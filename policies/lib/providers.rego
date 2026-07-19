# Which directories declare which provider version constraints, and which of
# those directories are roots. Only the reading lives here: what a wrong
# constraint costs is the policy's argument, and it differs by side.
#
# Nothing here is evaluated at policy time: conftest only reads deny and warn
# out of package main.
package lib.providers

import data.lib.hcl
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.

terraform_blocks[d] contains block if {
	some file in input
	d := hcl.directory(file.path)
	some block in object.get(file.contents, "terraform", [])
}

# A root is the directory that gets applied, and the only one that owns a
# backend. Matching on the backend rather than on a roots/ path prefix is what
# makes this survive the action's chroot-directory input, which can leave the
# prefix out of the paths this policy ever sees.
#
# data.lib.encryption reads the same shape to answer a different question. The
# walk is three lines and repeating it keeps each library one concern wide.
roots contains d if {
	some d, blocks in terraform_blocks
	some block in blocks
	object.get(block, "backend", null) != null
}

# Everything else that declares providers: the reusable modules and stacks a
# root composes. A directory only counts once it has something to say about
# provider versions, so a module without required_providers is not one.
modules contains d if {
	some d, _ in requirements
	not d in roots
}

# `required_providers { ... }` is a block, so hcl2json renders it as a list of
# objects mapping a local provider name to its requirements.
requirements[d] contains req if {
	some d, blocks in terraform_blocks
	some block in blocks
	some rp in hcl.blocks(object.get(block, "required_providers", null))
	some name, spec in rp
	req := {"name": name, "version": version(spec)}
}

# The documented spelling is an object with source and version. The bare string
# `cloudflare = ">= 5.0.0"` is the older shorthand and still parses, so it is
# read rather than passed over as unconstrained.
version(spec) := object.get(spec, "version", "") if is_object(spec)

version(spec) := spec if is_string(spec)

version(spec) := "" if {
	not is_object(spec)
	not is_string(spec)
}

# `version = ">= 5.1.0, < 6.0.0"` is one attribute holding two constraints, and
# the operator that matters can be either of them.
operators(v) := {op |
	some part in split(v, ",")
	op := operator(trim_space(part))
}

# Longest match first, so that ">= 5.0.0" is not read as ">". A part with no
# operator at all, such as "5.0.0", yields nothing and drops out of the set.
operator(part) := found[0] if {
	found := regex.find_n(`^(~>|>=|<=|!=|=|>|<)`, part, 1)
	count(found) == 1
}

# The files each directory declares its providers in. A finding is about a
# directory and has no file of its own to point at, so it borrows one of these.
# Directories that split the terraform block across files get the first by
# name, chosen the same way every run so that one problem is not reported once
# per file.
declaration_files[d] contains file.path if {
	some file in input
	d := hcl.directory(file.path)
	some block in object.get(file.contents, "terraform", [])
	object.get(block, "required_providers", null) != null
}

declaration_file(d) := min(hcl.set_for(declaration_files, d))
