package main

import data.lib.hcl
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# A cloudflare_api_token grants a set of permission groups over a set of
# resources. The resources map is where breadth hides: a key ending in ".*"
# mapped to "*" grants the permission over every resource of that class - every
# zone in the account, or every account - rather than the named few. A token
# that broad is one leaked secret away from acting on everything it could name,
# so least privilege wants the resources listed out.
#
# Only the unambiguous class wildcard is reported. A key such as
# "com.cloudflare.api.account.<id>" mapped to "*" cannot be told apart from a
# single named account once the id is a variable, and permission group ids are
# opaque, so neither is judged here - reporting them would flag scoped tokens.

api_tokens := hcl.resources_of_type(input, "cloudflare_api_token")

# Every resource key granted the literal "*", at any depth, whose name ends in
# ".*" and so covers a whole class rather than one named resource. walk descends
# the nested "account -> { zone.* = "*" }" spelling as well as the flat one.
# A value of "${var.x}" is not "*", so a grant whose breadth is a variable is
# passed over rather than guessed at.
class_wildcards(resources) := {key |
	walk(resources, [path, "*"])
	count(path) > 0
	key := path[count(path) - 1]
	endswith(key, ".*")
}

# effect defaults to "allow" in the provider, so a statement that omits it still
# grants; a statement that resolves to anything other than "allow" (an explicit
# "deny", or a variable this policy cannot read) is left alone.
warn contains hcl.finding(token.path, msg) if {
	some token in api_tokens
	some policy in hcl.blocks(object.get(token.body, "policies", null))
	object.get(policy, "effect", "allow") == "allow"
	some key in class_wildcards(object.get(policy, "resources", {}))
	msg := sprintf(
		"%s: %s grants %q = \"*\", which covers every resource of that class rather than the ones the token needs; list them",
		[token.path, hcl.address(token), key],
	)
}
