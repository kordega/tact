package main

import data.lib.hcl
import data.lib.r2
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# A backend block is read before variables, locals or providers exist, so it
# cannot interpolate anything. Whatever is written here is a literal, and a
# literal R2 access key is a credential committed to git. Credentials belong in
# the environment; anything that pins them to one machine belongs nowhere.

secret_settings := {
	"access_key": "AWS_ACCESS_KEY_ID",
	"secret_key": "AWS_SECRET_ACCESS_KEY",
	"token": "AWS_SESSION_TOKEN",
}

# Not secrets, but they resolve against the developer's own disk and make the
# root unusable in CI.
machine_local_settings := {"profile", "shared_credentials_files", "shared_config_files"}

deny contains hcl.finding(r2.backend_file(d), msg) if {
	some d in r2.roots
	some body in hcl.set_for(r2.backend_bodies, d)
	some setting, env in secret_settings
	object.get(body, setting, null) != null
	msg := sprintf(
		"%s: R2 backend must not set %s, a backend block cannot read variables so this value is a committed secret; pass %s instead",
		[d, setting, env],
	)
}

deny contains hcl.finding(r2.backend_file(d), msg) if {
	some d in r2.roots
	some body in hcl.set_for(r2.backend_bodies, d)
	some setting in machine_local_settings
	object.get(body, setting, null) != null
	msg := sprintf(
		"%s: R2 backend must not set %s, it resolves against one developer's filesystem and is not reproducible in CI",
		[d, setting],
	)
}
