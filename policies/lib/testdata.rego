# Fixtures shared by the R2 unit tests. Every policy directory asserts on its
# own rule, but they all need the same compliant starting point, so the builder
# lives here instead of being copied eight times.
#
# Nothing here is evaluated at policy time: conftest only reads deny and warn
# out of package main.
package lib.testdata

import rego.v1

# The fixtures below describe real roots, so the tofu/backend/encryption
# policies see them too. Those policies warn
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
# tofu/backend/r2/* policies have nothing to say about it because they only
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

# An R2 backend that passes every tofu/backend/r2/* policy.
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

# Fixtures for tofu/version-constraint. A root there needs a backend
# to be read as a root at all, and the encryption block that comes with it
# keeps the two encryption policies quiet, so that a warn set is only ever
# about provider versions.
provider_root(required_providers) := encryption_root({
	"backend": encryption_backend,
	"encryption": [encryption],
	"required_providers": [required_providers],
})

# A module is the same declaration without the backend, which is the only
# thing that tells the two apart.
provider_module(required_providers) := [{
	"path": "lib/modules/example/versions.tf",
	"contents": {"terraform": [{"required_providers": [required_providers]}]},
}]

# The documented spelling, so that the tests exercising the bare-string
# shorthand are visibly the exception.
provider(constraint) := {"cloudflare": {
	"source": "cloudflare/cloudflare",
	"version": constraint,
}}

# An R2 bucket that passes every
# tofu/provider/cloudflare/resource/r2/* policy.
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

# Fixtures for tofu/provider/cloudflare/resource/dns/dnssec. That policy pairs
# a zone with the resource signing it, so both have to be in the input, and the
# pairing is by root, so both have to be in the same directory. There is no
# backend here: a DNS root would have one, but adding it would put the two
# encryption policies' warnings into every assertion about DNSSEC.
zone := {
	"account": {"id": "${var.account_id}"},
	"name": "example.com",
	"type": "full",
}

signer := {
	"zone_id": "${cloudflare_zone.example.id}",
	"status": "active",
}

dns_file(resources) := [{
	"path": "roots/example/dns.tf",
	"contents": {"resource": resources},
}]

# A signed zone: one cloudflare_zone and the cloudflare_zone_dnssec pointing at
# it, with `patch` merged over the signer, which is how each test breaks
# exactly one thing.
signed_zone_with(patch) := dns_file({
	"cloudflare_zone": {"example": [zone]},
	"cloudflare_zone_dnssec": {"example": [object.union(signer, patch)]},
})

signed_zone := signed_zone_with({})

# The same signer with JSON pointers such as "/status" dropped.
signed_zone_without(pointers) := dns_file({
	"cloudflare_zone": {"example": [zone]},
	"cloudflare_zone_dnssec": {"example": [json.remove(signer, pointers)]},
})

bucket_with(patch) := bucket_file(object.union(bucket, patch))

bucket_without(pointers) := bucket_file(json.remove(bucket, pointers))

# Fixtures for tofu/provider/cloudflare/resource/zone/tls. In provider v5 each
# zone setting is its own resource carrying one setting_id and its value, so a
# fixture is a single such resource and each test names the pair it exercises.
zone_setting(setting_id, value) := resource_file(
	"cloudflare_zone_setting",
	"s",
	{
		"zone_id": "${cloudflare_zone.example.id}",
		"setting_id": setting_id,
		"value": value,
	},
)

# Fixtures for tofu/provider/cloudflare/resource/api-token/scope. A token holds
# a list of policy statements; the tests vary one statement's effect and the
# resources map it grants.
api_token(effect, resources) := resource_file(
	"cloudflare_api_token",
	"ci",
	{
		"name": "ci",
		"policies": [{
			"effect": effect,
			"permission_groups": [{"id": "${var.dns_edit}"}],
			"resources": resources,
		}],
	},
)

# Fixtures for tofu/provider/cloudflare/resource/zero-trust/access-open. An
# access policy admits whoever its include matchers name; the compliant base
# admits one email domain, and each test merges a patch that breaks one thing.
access_policy_base := {
	"name": "internal",
	"decision": "allow",
	"include": [{"email_domain": {"domain": "example.com"}}],
}

access_policy(body) := resource_file("cloudflare_zero_trust_access_policy", "p", body)

access_policy_with(patch) := access_policy(object.union(access_policy_base, patch))

# Fixtures for tofu/provider/cloudflare/resource/zero-trust/access-cors. The
# tests vary the cors_headers object on an access application.
access_app_cors(cors) := resource_file(
	"cloudflare_zero_trust_access_application",
	"app",
	{
		"name": "internal",
		"domain": "app.example.com",
		"cors_headers": cors,
	},
)

# Fixtures for tofu/provider/cloudflare/resource/dns/spf. That policy reads the
# content of TXT records, so the base is one cloudflare_dns_record and each test
# supplies the content string it exercises. dns_record takes a whole body so the
# non-TXT and unresolved cases can vary type and content too.
dns_record(body) := [{
	"path": "roots/example/dns.tf",
	"contents": {"resource": {"cloudflare_dns_record": {"spf": [body]}}},
}]

spf_txt(content) := dns_record({
	"type": "TXT",
	"name": "example.com",
	"content": content,
})
