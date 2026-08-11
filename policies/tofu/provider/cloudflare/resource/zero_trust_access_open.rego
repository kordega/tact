package main

import data.lib.hcl
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# A cloudflare_zero_trust_access_policy is the rule that decides who reaches an
# application behind Access. include matchers are OR'd, so an include of everyone
# is the whole internet, and a decision of "allow" on that admits it. The
# resource exists to gate the application, and this is the shape that gates
# nothing while still looking like a policy in a diff.
#
# require matchers are AND'd on top of include, so everyone AND a require (an
# MFA method, a device posture, a gateway) still narrows to that require. A
# policy carrying one is a deliberate "anyone who also satisfies X", not an open
# door, so the presence of any require stands the rule down. decision is read as
# a literal: "${var.x}" is not "allow", so a decision left to a variable is not
# reported.

access_policies := hcl.resources_of_type(input, "cloudflare_zero_trust_access_policy")

deny contains hcl.finding(policy.path, message) if {
	some policy in access_policies
	policy.body.decision == "allow"
	some include_matcher in hcl.blocks(object.get(policy.body, "include", null))
	"everyone" in object.keys(include_matcher)
	count(hcl.blocks(object.get(policy.body, "require", null))) == 0
	message := sprintf(
		"%s: %s decides \"allow\" for an include of everyone with no require, so it admits the entire internet to the application; add a require, or narrow the include",
		[policy.path, hcl.address(policy)],
	)
}
