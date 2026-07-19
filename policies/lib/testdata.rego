# Fixtures shared by the R2 unit tests. Every policy directory asserts on its
# own rule, but they all need the same compliant starting point, so the builder
# lives here instead of being copied eight times.
#
# Nothing here is evaluated at policy time: conftest only reads deny and warn
# out of package main.
package lib.testdata

import rego.v1

# The fixtures below describe real roots, so the tofu-backend-plan-encryption
# and tofu-backend-state-encryption policies see them too. Those policies warn
# rather than deny, so they no longer reach a count(deny) == 0 assertion, but a
# fixture without a valid encryption block would still put their warnings in
# front of anyone reading a failing test.
#
# state and plan get their own key provider and method rather than sharing one:
# they protect artifacts with different lifetimes, and the encryption policy
# tests need a root where the two chains can be broken independently.
encryption := {
	"key_provider": {"pbkdf2": {
		"plan": [{"passphrase": "${var.encryption_passphrase}"}],
		"state": [{"passphrase": "${var.encryption_passphrase}"}],
	}},
	"method": {"aes_gcm": {
		"plan": [{"keys": "${key_provider.pbkdf2.plan}"}],
		"state": [{"keys": "${key_provider.pbkdf2.state}"}],
	}},
	"plan": [{
		"enforced": true,
		"method": "${method.aes_gcm.plan}",
	}],
	"state": [{
		"enforced": true,
		"method": "${method.aes_gcm.state}",
	}],
}

# Builders for the two encryption policies. They share package main, so a
# root_with() in each test file would be one name defined twice, and they also
# have to agree on what a compliant root looks like: every assertion in either
# file reads the same warn set, and a fixture that satisfies only one policy
# would carry the other one's warnings into it.
#
# The backend here is the bare minimum that marks a directory as a root. The
# tofu-backend-r2-* policies have nothing to say about it because they only
# look at resource blocks and at backends that are already spelled out.
encryption_backend := {"s3": [{"bucket": "tofu-state"}]}

encryption_root(terraform_body) := [{
	"path": "roots/example/versions.tf",
	"contents": {"terraform": [terraform_body]},
}]

# A compliant root with `patch` merged over its encryption block, which is how
# each test breaks exactly one thing.
encryption_root_with(patch) := encryption_root({
	"backend": encryption_backend,
	"encryption": [object.union(encryption, patch)],
})

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
