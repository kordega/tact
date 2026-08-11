package main

import data.lib.hcl
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# cors_headers on a cloudflare_zero_trust_access_application controls what the
# browser is told it may do cross-origin. allow_all_origins reflects whatever
# Origin the request carried, and allow_credentials tells the browser to send
# cookies with it. Together they let any page the user visits make credentialed
# requests to the application and read the responses - the same credential relay
# the R2 bucket CORS rule denies, one layer up.
#
# Both are read as literals. A value of "${var.x}" is not true, so a setting left
# to a variable is passed over rather than assumed to be on.

access_apps := hcl.resources_of_type(input, "cloudflare_zero_trust_access_application")

deny contains hcl.finding(app.path, message) if {
	some app in access_apps
	some cors in hcl.blocks(object.get(app.body, "cors_headers", null))
	cors.allow_all_origins == true
	cors.allow_credentials == true
	message := sprintf(
		"%s: %s sets cors_headers with allow_all_origins and allow_credentials both true, which reflects any origin while forwarding credentials; name the allowed origins, or drop credentials",
		[app.path, hcl.address(app)],
	)
}
