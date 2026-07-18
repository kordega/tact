# Fixtures shared by the R2 unit tests. Every policy directory asserts on its
# own rule, but they all need the same compliant starting point, so the builder
# lives here instead of being copied eight times.
#
# Nothing here is evaluated at policy time: conftest only reads deny and warn
# out of package main.
package lib.testdata

import rego.v1

# The fixtures below describe real roots, so the tofu-backend-plan-encryption
# policy sees them too. Without a valid encryption block a bare
# count(deny) == 0 assertion would be reporting somebody else's rule.
encryption := {
	"key_provider": {"pbkdf2": {"plan": [{"passphrase": "${var.encryption_passphrase}"}]}},
	"method": {"aes_gcm": {"plan": [{"keys": "${key_provider.pbkdf2.plan}"}]}},
	"plan": [{
		"enforced": true,
		"method": "${method.aes_gcm.plan}",
	}],
}

# An R2 backend that passes every tofu-backend-r2-* policy.
backend := {
	"bucket": "tofu-state",
	"key": "roots/example/terraform.tfstate",
	"region": "auto",
	"endpoints": {"s3": "https://0123456789abcdef.r2.cloudflarestorage.com"},
	"use_lockfile": true,
	"skip_credentials_validation": true,
	"skip_metadata_api_check": true,
	"skip_region_validation": true,
	"skip_requesting_account_id": true,
	"skip_s3_checksum": true,
	"use_path_style": true,
}

root_at(path, backend_body) := [{
	"path": path,
	"contents": {"terraform": [{
		"backend": {"s3": [backend_body]},
		"encryption": [encryption],
	}]},
}]

root(backend_body) := root_at("roots/example/versions.tf", backend_body)

# The compliant backend with `patch` merged over it.
root_with(patch) := root(object.union(backend, patch))

# The compliant backend with JSON pointers such as "/region" dropped.
root_without(pointers) := root(json.remove(backend, pointers))

# An R2 bucket that passes every tofu-resource-r2-* policy.
bucket := {
	"account_id": "${var.account_id}",
	"name": "tofu-state",
	"location": "weur",
	"jurisdiction": "eu",
	"storage_class": "Standard",
	"lifecycle": [{"prevent_destroy": true}],
}

resource_file(rtype, rname, body) := [{
	"path": "roots/example/r2.tf",
	"contents": {"resource": {rtype: {rname: [body]}}},
}]

bucket_file(body) := resource_file("cloudflare_r2_bucket", "state", body)

bucket_with(patch) := bucket_file(object.union(bucket, patch))

bucket_without(pointers) := bucket_file(json.remove(bucket, pointers))
