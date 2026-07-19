# A single shared answer to "which parts of this repository are R2". Detection
# lives here so that every tofu-backend-r2-* and tofu-resource-r2-* policy
# agrees on what an R2 root is, and so that each policy directory can stay one
# concern wide.
package lib.r2

import data.lib.hcl
import rego.v1

# The account endpoint every R2 bucket is served from. A root that reaches R2
# through a custom domain is not detected: nothing in that configuration marks
# it as R2.
host_suffix := ".r2.cloudflarestorage.com"

# Every s3 backend in the repository, R2 or not, keyed by root directory.
s3_backends[d] contains body if {
	some file in input
	d := hcl.directory(file.path)
	some block in object.get(file.contents, "terraform", [])
	some body in object.get(object.get(block, "backend", {}), "s3", [])
}

# `endpoints = { s3 = "..." }` is the documented spelling; hcl.blocks also
# accepts the `endpoints { s3 = "..." }` block form.
endpoints[d] contains url if {
	some d, bodies in s3_backends
	some body in bodies
	some e in hcl.blocks(object.get(body, "endpoints", null))
	url := e.s3
	is_string(url)
}

# The single-endpoint attribute the s3 backend still accepts.
endpoints[d] contains url if {
	some d, bodies in s3_backends
	some body in bodies
	url := body.endpoint
	is_string(url)
}

r2_endpoints[d] contains url if {
	some d, urls in endpoints
	some url in urls
	contains(url, host_suffix)
}

roots contains d if {
	some d, _ in r2_endpoints
}

backend_bodies[d] contains body if {
	some d in roots
	some body in hcl.set_for(s3_backends, d)
}

# The files each root spells its backend out in. A rule about a root has no
# file of its own to point at, because a root is a directory, so it borrows the
# one the backend is declared in.
backend_files[d] contains file.path if {
	some file in input
	d := hcl.directory(file.path)
	some block in object.get(file.contents, "terraform", [])
	some _ in object.get(object.get(block, "backend", {}), "s3", [])
}

# One file per root, chosen the same way every run: a finding that anchored to
# each of them in turn would report the same problem several times over. Roots
# that split the backend across files are the reason this has to pick rather
# than iterate.
backend_file(d) := min(hcl.set_for(backend_files, d))

resources_of_type(rtype) := {r |
	some r in hcl.resources(input)
	r.type == rtype
}

buckets := resources_of_type("cloudflare_r2_bucket")
