package main

import data.lib.hcl
import data.lib.r2
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# The s3 backend defaults to talking to AWS: it validates credentials against
# STS, falls back to instance metadata, checks the region name and appends a
# trailing checksum. R2 answers none of that. Every setting below has to be
# turned off explicitly or the backend fails, usually on the first plan and
# with an error that names AWS rather than R2.

# The value is the reason, so the operator does not have to look the flag up.
required_true_settings := {
	"skip_credentials_validation": "R2 has no STS, so the AWS credential pre-flight call has nothing to answer it",
	"skip_metadata_api_check": "there is no EC2 instance metadata service to fall back to for credentials",
	"skip_region_validation": "\"auto\" is not a valid AWS region name and validation rejects it",
	"skip_requesting_account_id": "R2 has no IAM account id to resolve",
	"skip_s3_checksum": "R2 rejects the trailing checksum the AWS SDK adds to uploads by default",
	"use_path_style": "R2 serves buckets path-style underneath the account endpoint",
}

# A literal `true` parses to a JSON boolean. Anything else - unset, false, or
# an expression hcl2json rendered as "${...}" - cannot be proven correct here.
deny contains hcl.finding(r2.backend_file(directory), message) if {
	some directory in r2.roots
	some body in hcl.set_for(r2.backend_bodies, directory)
	some setting, reason in required_true_settings
	object.get(body, setting, null) != true
	message := sprintf(
		"%s: R2 backend must set %s = true (got %v): %s",
		[directory, setting, object.get(body, setting, "<unset>"), reason],
	)
}

deny contains hcl.finding(r2.backend_file(directory), message) if {
	some directory in r2.roots
	some body in hcl.set_for(r2.backend_bodies, directory)
	object.get(body, "region", null) != "auto"
	message := sprintf(
		"%s: R2 backend must set region = \"auto\" (got %v), R2 has no regional endpoints",
		[directory, object.get(body, "region", "<unset>")],
	)
}
