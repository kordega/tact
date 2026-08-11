# A single shared answer to "which parts of this repository are R2". Detection
# lives here so that every tofu/backend/r2/* and every
# tofu/provider/cloudflare/resource/r2_* policy agrees on what an R2 root is,
# and so that each of those policies can stay one concern wide.
#
# Nothing here is evaluated at policy time: conftest only reads deny and warn
# out of package main.
package lib.r2

import data.lib.hcl
import rego.v1

# The account endpoint every R2 bucket is served from. A root that reaches R2
# through a custom domain is not detected: nothing in that configuration marks
# it as R2.
host_suffix := ".r2.cloudflarestorage.com"

# Every s3 backend in the repository, R2 or not, keyed by root directory.
s3_backends[entry.directory] contains body if {
	some entry in hcl.terraform_blocks
	some body in object.get(object.get(entry.block, "backend", {}), "s3", [])
}

# `endpoints = { s3 = "..." }` is the documented spelling; hcl.blocks also
# accepts the `endpoints { s3 = "..." }` block form.
endpoints[directory] contains url if {
	some directory, bodies in s3_backends
	some body in bodies
	some endpoint_block in hcl.blocks(object.get(body, "endpoints", null))
	url := endpoint_block.s3
	is_string(url)
}

# The single-endpoint attribute the s3 backend still accepts.
endpoints[directory] contains url if {
	some directory, bodies in s3_backends
	some body in bodies
	url := body.endpoint
	is_string(url)
}

# The endpoints served from the R2 account host, which is what marks a root as
# R2 in the first place.
account_endpoints[directory] contains url if {
	some directory, urls in endpoints
	some url in urls
	contains(url, host_suffix)
}

roots contains directory if {
	some directory, _ in account_endpoints
}

backend_bodies[directory] contains body if {
	some directory in roots
	some body in hcl.set_for(s3_backends, directory)
}

# The files each root spells its backend out in, for hcl.first_file to pick a
# finding's anchor from.
backend_files[entry.directory] contains entry.path if {
	some entry in hcl.terraform_blocks
	some _ in object.get(object.get(entry.block, "backend", {}), "s3", [])
}

backend_file(directory) := hcl.first_file(backend_files, directory)

resources_of_type(resource_type) := hcl.resources_of_type(input, resource_type)

buckets := resources_of_type("cloudflare_r2_bucket")
