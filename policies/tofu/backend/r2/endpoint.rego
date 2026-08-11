package main

import data.lib.hcl
import data.lib.r2
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# The endpoint is what points the s3 backend at Cloudflare instead of AWS, and
# it is the one setting the rest of the tofu/backend/r2/* policies key off. These
# rules keep it reachable over TLS, free of secrets, and statically readable.

deny contains hcl.finding(r2.backend_file(directory), message) if {
	some directory in r2.roots
	some url in hcl.set_for(r2.account_endpoints, directory)
	not startswith(url, "https://")
	message := sprintf(
		"%s: R2 backend endpoint %q must use https://, the S3 credentials travel on every request",
		[directory, url],
	)
}

# https://key:secret@account.r2.cloudflarestorage.com hides a credential pair
# in a setting nobody reads as one, and it leaks into state and logs.
deny contains hcl.finding(r2.backend_file(directory), message) if {
	some directory in r2.roots
	some url in hcl.set_for(r2.account_endpoints, directory)
	contains(regex.replace(url, `^https?://`, ""), "@")
	message := sprintf(
		"%s: R2 backend endpoint must not carry credentials in the URL; pass AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY instead",
		[directory],
	)
}

# A backend block is evaluated before variables exist, so an endpoint written
# as an expression never resolves. It also hides the root from every other
# tofu/backend/r2/* policy, because R2 is recognised by the endpoint host.
deny contains hcl.finding(r2.backend_file(directory), message) if {
	some directory, urls in r2.endpoints
	some url in urls
	hcl.unresolved(url)
	message := sprintf(
		"%s: s3 backend endpoint is %q, but a backend block cannot interpolate variables; write the endpoint literally",
		[directory, url],
	)
}
