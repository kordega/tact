# Which directories declare which provider version constraints, and which of
# those are modules rather than roots. Only the reading lives here: what a
# wrong constraint costs is the policy's argument, and it differs by side.
#
# Which directories are roots is data.lib.hcl's answer, shared with every other
# library that has to tell a root from a module. Reading it from one place is
# what keeps a root that stores its state in a state_store{} block from being
# audited as if it were a module.
#
# Nothing here is evaluated at policy time: conftest only reads deny and warn
# out of package main.
package lib.providers

import data.lib.hcl
import rego.v1

# Everything that declares providers and is not a root: the reusable modules
# and stacks a root composes. A directory only counts once it has something to
# say about provider versions, so a module without required_providers is not
# one.
modules contains directory if {
	some directory, _ in requirements
	not directory in hcl.roots
}

# `required_providers { ... }` is a block, so hcl2json renders it as a list of
# objects mapping a local provider name to its requirements.
requirements[entry.directory] contains requirement if {
	some entry in hcl.terraform_blocks
	some declaration in hcl.blocks(object.get(entry.block, "required_providers", null))
	some provider_name, specification in declaration
	requirement := {"name": provider_name, "version": version(specification)}
}

# The documented spelling is an object with source and version. The bare string
# `cloudflare = ">= 5.0.0"` is the older shorthand and still parses, so it is
# read rather than passed over as unconstrained.
version(specification) := object.get(specification, "version", "") if is_object(specification)

version(specification) := specification if is_string(specification)

version(specification) := "" if {
	not is_object(specification)
	not is_string(specification)
}

# `version = ">= 5.1.0, < 6.0.0"` is one attribute holding two constraints, and
# the operator that matters can be either of them.
operators(constraint) := {found |
	some part in split(constraint, ",")
	found := operator(trim_space(part))
}

# Longest match first, so that ">= 5.0.0" is not read as ">". A part with no
# operator at all, such as "5.0.0", yields nothing and drops out of the set.
operator(part) := matches[0] if {
	matches := regex.find_n(`^(~>|>=|<=|!=|=|>|<)`, part, 1)
	count(matches) == 1
}

# The files each directory declares its providers in, for hcl.first_file to
# pick a finding's anchor from.
declaration_files[entry.directory] contains entry.path if {
	some entry in hcl.terraform_blocks
	object.get(entry.block, "required_providers", null) != null
}

declaration_file(directory) := hcl.first_file(declaration_files, directory)
