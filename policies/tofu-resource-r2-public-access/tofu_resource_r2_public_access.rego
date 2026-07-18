package main

import data.lib.hcl
import data.lib.r2
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# An R2 bucket is private until something in the configuration opens it. There
# are only a few such switches, they are one line each, and none of them looks
# dangerous in a diff.

# The managed r2.dev domain publishes the whole bucket read-only to anyone.
# Cloudflare rate limits it and documents it as a development convenience, so a
# custom domain in front of the CDN is the production answer.
deny contains msg if {
	some domain in r2.resources_of_type("cloudflare_r2_managed_domain")
	object.get(domain.body, "enabled", null) == true
	msg := sprintf(
		"%s: %s enables the managed r2.dev domain, which serves bucket %v to anonymous callers; put a cloudflare_r2_custom_domain in front instead",
		[domain.path, hcl.address(domain), object.get(domain.body, "bucket_name", "<unset>")],
	)
}

deny contains msg if {
	some cors in r2.resources_of_type("cloudflare_r2_bucket_cors")
	some rule in hcl.blocks(object.get(cors.body, "rules", null))
	some allowed in hcl.blocks(object.get(rule, "allowed", null))
	"*" in object.get(allowed, "origins", [])
	msg := sprintf(
		"%s: %s allows CORS origin \"*\", which lets any page in a browser read the bucket with the caller's credentials; list the origins",
		[cors.path, hcl.address(cors)],
	)
}

# A wildcard header allowlist hands the browser whatever the caller asks for,
# including Authorization, which is how a permissive CORS rule turns into a
# credential relay.
deny contains msg if {
	some cors in r2.resources_of_type("cloudflare_r2_bucket_cors")
	some rule in hcl.blocks(object.get(cors.body, "rules", null))
	some allowed in hcl.blocks(object.get(rule, "allowed", null))
	"*" in object.get(allowed, "headers", [])
	msg := sprintf(
		"%s: %s allows CORS header \"*\"; list the headers the browser actually needs",
		[cors.path, hcl.address(cors)],
	)
}
