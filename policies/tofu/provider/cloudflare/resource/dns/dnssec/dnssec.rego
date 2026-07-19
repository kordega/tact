package main

import data.lib.hcl
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# DNSSEC is what lets a resolver reject a forged answer for a zone. Nothing
# about an unsigned zone looks wrong: it resolves exactly like a signed one
# right up until someone hands a resolver a different answer, and by then the
# traffic is already gone. On Cloudflare it is one resource and one argument,
# and this file is about the ways that resource ends up not signing anything.

dnssec_zones := hcl.resources_of_type(input, "cloudflare_zone")

dnssec_signers := hcl.resources_of_type(input, "cloudflare_zone_dnssec")

# A zone and the resource that signs it are applied together, so the pair is
# looked for within one root. Reaching across roots would credit a zone with a
# signer that a separate apply owns and can remove without this one noticing.
deny contains hcl.finding(zone.path, msg) if {
	some zone in dnssec_zones
	not dnssec_signed(zone)
	not dnssec_unprovable_signer(hcl.directory(zone.path))
	msg := sprintf(
		"%s: %s has no cloudflare_zone_dnssec resource in %s, so the zone is served unsigned and a forged answer for it validates",
		[zone.path, hcl.address(zone), hcl.directory(zone.path)],
	)
}

dnssec_signed(zone) if {
	some signer in dnssec_signers
	hcl.directory(signer.path) == hcl.directory(zone.path)
	startswith(dnssec_zone_ref(signer), sprintf("%s.", [hcl.address(zone)]))
}

# `zone_id = cloudflare_zone.example.id` is the reference the pairing reads,
# which hcl2json renders as "${cloudflare_zone.example.id}".
dnssec_zone_ref(signer) := hcl.deref(zone_id) if {
	zone_id := object.get(signer.body, "zone_id", "")
	is_string(zone_id)
}

# A signer whose zone_id is anything else - a variable, a data source, a module
# output - could be pointing at any zone in the root, and this policy only
# reports what it can prove. One of those stands the rule down for that root
# rather than reporting every zone in it.
dnssec_unprovable_signer(d) if {
	some signer in dnssec_signers
	hcl.directory(signer.path) == d
	not startswith(dnssec_zone_ref(signer), "cloudflare_zone.")
}

# status is optional in the provider, and a resource without it asserts
# nothing: whatever the zone was in before the apply, it stays in. For a zone
# imported from a registrar move that is usually unsigned.
deny contains hcl.finding(signer.path, msg) if {
	some signer in dnssec_signers
	object.get(signer.body, "status", null) == null
	msg := sprintf(
		"%s: %s must set status = \"active\", a cloudflare_zone_dnssec without one leaves the zone in whatever state it was already in",
		[signer.path, hcl.address(signer)],
	)
}

# Only literals can be checked; hcl2json renders `status = var.dnssec` as
# "${var.dnssec}", which says nothing about the value it will take.
deny contains hcl.finding(signer.path, msg) if {
	some signer in dnssec_signers
	status := object.get(signer.body, "status", null)
	is_string(status)
	not hcl.unresolved(status)
	status != "active"
	msg := sprintf(
		"%s: %s sets status = %q; the only value that signs the zone is \"active\"",
		[signer.path, hcl.address(signer), status],
	)
}

# Cloudflare answers a non-existent name with compact denial of existence
# (RFC 9824), signed at request time and not walkable, so NSEC3 buys nothing
# against zone enumeration on a zone Cloudflare signs itself. It costs more to
# serve, it is Enterprise-only, and the case it exists for is a pre-signed zone
# transferred in with NSEC3 records already in it. A compliance requirement is
# the other reason, which is why this is a warning rather than a denial.
#
# https://developers.cloudflare.com/dns/dnssec/enable-nsec3/
warn contains hcl.finding(signer.path, msg) if {
	some signer in dnssec_signers
	object.get(signer.body, "dnssec_use_nsec3", null) == true
	object.get(signer.body, "dnssec_presigned", null) != true
	msg := sprintf(
		"%s: %s enables dnssec_use_nsec3 on a zone Cloudflare signs itself, where NSEC already prevents zone walking; NSEC3 belongs to a pre-signed zone or to a compliance requirement",
		[signer.path, hcl.address(signer)],
	)
}

# Multi-signer is what allows DNSKEY records Cloudflare did not generate to be
# added to the zone, which is the point when the set of keys that can sign for
# the zone stops being Cloudflare's alone. That is a deliberate multi-provider
# setup, and it reads as a one-line boolean in a diff.
#
# https://developers.cloudflare.com/dns/dnssec/multi-signer-dnssec/
warn contains hcl.finding(signer.path, msg) if {
	some signer in dnssec_signers
	object.get(signer.body, "dnssec_multi_signer", null) == true
	msg := sprintf(
		"%s: %s enables dnssec_multi_signer, which lets DNSKEY records from outside Cloudflare sign for the zone; leave it off unless a second provider serves this zone",
		[signer.path, hcl.address(signer)],
	)
}
