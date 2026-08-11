package main

import data.lib.hcl
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# In provider v5 each zone setting is its own resource: one cloudflare_zone_setting
# carries a setting_id and the value it is pinned to. A wrong value here is one
# line and changes nothing anyone sees - the site still loads - while it quietly
# moves traffic onto a plaintext leg or re-admits a TLS version retired for being
# breakable. This file is about the handful of those settings where the value
# decides whether a request is encrypted end to end.
#
# Only literal values are judged. hcl2json renders `value = var.x` as "${var.x}",
# which asserts nothing about the value an apply resolves, so a comparison against
# a literal passes over it on its own. Absence is not judged either: a setting
# this repository does not declare may be managed elsewhere, and inventing a
# default would report a zone that is fine.

zone_settings := hcl.resources_of_type(input, "cloudflare_zone_setting")

zone_settings_with_id(setting_id) := {setting |
	some setting in zone_settings
	setting.body.setting_id == setting_id
}

# ssl = "off" serves the edge over cleartext; ssl = "flexible" encrypts the
# browser leg but fetches from the origin over plain HTTP, which anyone on the
# path between Cloudflare and the origin can read or rewrite. Both leave a leg
# unencrypted, so both are denied. "full" and "strict" are the encrypted modes.
deny contains hcl.finding(setting.path, message) if {
	some setting in zone_settings_with_id("ssl")
	value := setting.body.value
	value in {"off", "flexible"}
	message := sprintf(
		"%s: %s sets ssl = %q, which serves at least one leg (browser or origin) over cleartext; use \"strict\", or \"full\" only where the origin certificate cannot be validated",
		[setting.path, hcl.address(setting), value],
	)
}

# "full" encrypts the origin leg but does not validate the certificate on it, so
# a machine-in-the-middle presenting any certificate is trusted. It is a real
# encrypted mode, unlike off/flexible, which is why this warns rather than
# denies: some origins genuinely cannot present a validatable certificate.
warn contains hcl.finding(setting.path, message) if {
	some setting in zone_settings_with_id("ssl")
	setting.body.value == "full"
	message := sprintf(
		"%s: %s sets ssl = \"full\", which encrypts the origin leg without validating its certificate; \"strict\" validates it",
		[setting.path, hcl.address(setting)],
	)
}

# 1.0 and 1.1 are withdrawn (RFC 8996) and carry the downgrade-enabling
# weaknesses that retirement was about. Pinning min_tls_version to one of them
# re-admits a client that will only speak the broken version, so it is denied.
# This fires on the literal downgrade only; 1.2 and 1.3 are fine.
deny contains hcl.finding(setting.path, message) if {
	some setting in zone_settings_with_id("min_tls_version")
	value := setting.body.value
	value in {"1.0", "1.1"}
	message := sprintf(
		"%s: %s sets min_tls_version = %q, which admits a client negotiating a TLS version withdrawn as breakable (RFC 8996); the floor is \"1.2\"",
		[setting.path, hcl.address(setting), value],
	)
}

# With always_use_https off, a plaintext request is answered over plaintext
# rather than redirected to HTTPS, so the first request of a session can be read
# in full. This is redirect hygiene rather than a proven cleartext origin leg -
# the encrypted site still exists next to it - so it warns.
warn contains hcl.finding(setting.path, message) if {
	some setting in zone_settings_with_id("always_use_https")
	setting.body.value == "off"
	message := sprintf(
		"%s: %s sets always_use_https = \"off\", so a plaintext request is served rather than redirected to HTTPS; turn it on",
		[setting.path, hcl.address(setting)],
	)
}

# Turning tls_1_3 off drops the one TLS version without the legacy handshake
# weaknesses and denies clients its faster, safer negotiation. Nothing breaks
# without it, so it warns.
warn contains hcl.finding(setting.path, message) if {
	some setting in zone_settings_with_id("tls_1_3")
	setting.body.value == "off"
	message := sprintf(
		"%s: %s sets tls_1_3 = \"off\", which disables the only TLS version free of the legacy handshake weaknesses; leave it on",
		[setting.path, hcl.address(setting)],
	)
}
