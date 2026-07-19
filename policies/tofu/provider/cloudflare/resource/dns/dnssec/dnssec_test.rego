package main

import data.lib.testdata
import rego.v1

test_signed_zone_is_allowed if {
	count(deny) == 0 with input as testdata.signed_zone
	count(warn) == 0 with input as testdata.signed_zone
}

test_zone_without_a_dnssec_resource_is_denied if {
	msgs := deny with input as testdata.dns_file({"cloudflare_zone": {"example": [testdata.zone]}})
	some m in msgs
	contains(m.msg, "roots/example/dns.tf: cloudflare_zone.example has no cloudflare_zone_dnssec resource in roots/example")
	contains(m.msg, "the zone is served unsigned")
}

test_a_dnssec_resource_in_another_root_does_not_count if {
	msgs := deny with input as array.concat(
		testdata.dns_file({"cloudflare_zone": {"example": [testdata.zone]}}),
		[{
			"path": "roots/other/dns.tf",
			"contents": {"resource": {"cloudflare_zone_dnssec": {"example": [testdata.signer]}}},
		}],
	)
	some m in msgs
	contains(m.msg, "cloudflare_zone.example has no cloudflare_zone_dnssec resource in roots/example")
}

# `zone_id = cloudflare_zone.other.id` names a different zone, so it leaves the
# one declared here unsigned.
test_a_dnssec_resource_for_another_zone_does_not_count if {
	msgs := deny with input as testdata.dns_file({
		"cloudflare_zone": {"example": [testdata.zone]},
		"cloudflare_zone_dnssec": {"other": [{
			"zone_id": "${cloudflare_zone.other.id}",
			"status": "active",
		}]},
	})
	some m in msgs
	contains(m.msg, "cloudflare_zone.example has no cloudflare_zone_dnssec resource")
}

# A prefix of another zone's name is not that zone: cloudflare_zone.example is
# not signed by a resource pointing at cloudflare_zone.example_two.
test_a_zone_name_prefix_is_not_read_as_a_match if {
	msgs := deny with input as testdata.dns_file({
		"cloudflare_zone": {"example": [testdata.zone]},
		"cloudflare_zone_dnssec": {"example_two": [{
			"zone_id": "${cloudflare_zone.example_two.id}",
			"status": "active",
		}]},
	})
	some m in msgs
	contains(m.msg, "cloudflare_zone.example has no cloudflare_zone_dnssec resource")
}

# `zone_id = var.zone_id` could be pointing at any zone in the root, and this
# policy only reports what it can prove.
test_a_dnssec_resource_from_a_variable_stands_the_rule_down if {
	msgs := deny with input as testdata.dns_file({
		"cloudflare_zone": {"example": [testdata.zone]},
		"cloudflare_zone_dnssec": {"example": [{
			"zone_id": "${var.zone_id}",
			"status": "active",
		}]},
	})
	every m in msgs {
		not contains(m.msg, "has no cloudflare_zone_dnssec resource")
	}
}

test_each_unsigned_zone_is_reported_separately if {
	msgs := deny with input as testdata.dns_file({"cloudflare_zone": {
		"example": [testdata.zone],
		"other": [testdata.zone],
	}})
	count(msgs) == 2
	some m in msgs
	contains(m.msg, "cloudflare_zone.other has no cloudflare_zone_dnssec")
}

test_a_zone_without_resources_is_ignored if {
	count(deny) == 0 with input as testdata.dns_file({"cloudflare_record": {"apex": [{"name": "@"}]}})
}

test_dnssec_without_status_is_denied if {
	msgs := deny with input as testdata.signed_zone_without(["/status"])
	some m in msgs
	contains(m.msg, "cloudflare_zone_dnssec.example must set status = \"active\"")
	contains(m.msg, "leaves the zone in whatever state it was already in")
}

test_dnssec_disabled_is_denied if {
	msgs := deny with input as testdata.signed_zone_with({"status": "disabled"})
	some m in msgs
	contains(m.msg, "cloudflare_zone_dnssec.example sets status = \"disabled\"")
	contains(m.msg, "the only value that signs the zone is \"active\"")
}

test_dnssec_status_from_a_variable_is_allowed if {
	count(deny) == 0 with input as testdata.signed_zone_with({"status": "${var.dnssec_status}"})
}

test_nsec3_on_a_cloudflare_signed_zone_is_warned_about if {
	msgs := warn with input as testdata.signed_zone_with({"dnssec_use_nsec3": true})
	some m in msgs
	contains(m.msg, "cloudflare_zone_dnssec.example enables dnssec_use_nsec3 on a zone Cloudflare signs itself")
}

test_nsec3_on_a_presigned_zone_is_allowed if {
	count(warn) == 0 with input as testdata.signed_zone_with({
		"dnssec_presigned": true,
		"dnssec_use_nsec3": true,
	})
}

test_multi_signer_is_warned_about if {
	msgs := warn with input as testdata.signed_zone_with({"dnssec_multi_signer": true})
	some m in msgs
	contains(m.msg, "cloudflare_zone_dnssec.example enables dnssec_multi_signer")
	contains(m.msg, "lets DNSKEY records from outside Cloudflare sign for the zone")
}

test_multi_signer_set_to_false_is_allowed if {
	count(warn) == 0 with input as testdata.signed_zone_with({
		"dnssec_multi_signer": false,
		"dnssec_use_nsec3": false,
	})
}
