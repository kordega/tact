package main

import data.lib.hcl
import data.lib.providers
import rego.v1

# Reading required_providers lives in data.lib.providers. This file is the
# argument for spelling the constraint differently on each side of the module
# boundary.
#
# A module is consumed, so its constraint is a floor and nothing else: the
# lowest provider version it is known to work against. An upper bound there is
# not the module's to set, because it is the root that resolves the version and
# the root that would be stuck on the wrong side of it.
#
# A root is applied, so its constraint is what actually decides which provider
# binary runs. `~>` holds the major and the minor still, which is the line a
# provider is allowed to change behaviour across, and leaves patch releases to
# arrive on their own. `>=` in a root means the next major lands unannounced in
# whichever plan runs first after it is published.
#
# These warn rather than deny: a wrong constraint is a drift risk to raise on
# the pull request, not a reason to stop the run.

warn contains hcl.finding(providers.declaration_file(d), msg) if {
	some d, reqs in providers.requirements
	some req in reqs
	req.version == ""
	msg := sprintf(
		"%s: provider %q is declared without a version constraint, so every run is free to resolve a different one",
		[d, req.name],
	)
}

warn contains hcl.finding(providers.declaration_file(d), msg) if {
	some d in providers.roots
	some req in hcl.set_for(providers.requirements, d)
	req.version != ""
	not "~>" in providers.operators(req.version)
	msg := sprintf(
		"%s: root pins provider %q with %q; a root must use ~> so a new major cannot arrive on its own",
		[d, req.name, req.version],
	)
}

warn contains hcl.finding(providers.declaration_file(d), msg) if {
	some d in providers.modules
	some req in hcl.set_for(providers.requirements, d)
	"~>" in providers.operators(req.version)
	msg := sprintf(
		"%s: module constrains provider %q with %q; ~> caps every root that consumes it, which is the root's call to make",
		[d, req.name, req.version],
	)
}

# Only the missing floor is reported here. A module that writes an explicit
# upper bound with < or <= has the same effect on its consumers as ~>, but it
# has also been written out deliberately, and that is a conversation rather
# than a mistake.
warn contains hcl.finding(providers.declaration_file(d), msg) if {
	some d in providers.modules
	some req in hcl.set_for(providers.requirements, d)
	req.version != ""
	ops := providers.operators(req.version)
	not "~>" in ops
	not ">=" in ops
	msg := sprintf(
		"%s: module constrains provider %q with %q; a module states the lowest version it works against, with >=",
		[d, req.name, req.version],
	)
}
