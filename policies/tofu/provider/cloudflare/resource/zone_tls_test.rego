package main

import data.lib.testdata
import rego.v1

test_ssl_off_is_denied if {
	msgs := deny with input as testdata.zone_setting("ssl", "off")
	some m in msgs
	contains(m.msg, "cloudflare_zone_setting.example sets ssl = \"off\"")
	contains(m.msg, "cleartext")
}

test_ssl_flexible_is_denied if {
	msgs := deny with input as testdata.zone_setting("ssl", "flexible")
	some m in msgs
	contains(m.msg, "cloudflare_zone_setting.example sets ssl = \"flexible\"")
}

test_ssl_full_is_warned_about if {
	msgs := warn with input as testdata.zone_setting("ssl", "full")
	some m in msgs
	contains(m.msg, "sets ssl = \"full\"")
	contains(m.msg, "without validating its certificate")
}

test_ssl_strict_is_allowed if {
	count(deny) == 0 with input as testdata.zone_setting("ssl", "strict")
	count(warn) == 0 with input as testdata.zone_setting("ssl", "strict")
}

# `ssl = var.mode` renders as "${var.mode}", which says nothing about the value
# the apply resolves, so neither the deny nor the warn fires.
test_ssl_from_a_variable_stands_the_rule_down if {
	count(deny) == 0 with input as testdata.zone_setting("ssl", "${var.mode}")
	count(warn) == 0 with input as testdata.zone_setting("ssl", "${var.mode}")
}

test_min_tls_10_is_denied if {
	msgs := deny with input as testdata.zone_setting("min_tls_version", "1.0")
	some m in msgs
	contains(m.msg, "min_tls_version = \"1.0\"")
	contains(m.msg, "RFC 8996")
}

test_min_tls_11_is_denied if {
	msgs := deny with input as testdata.zone_setting("min_tls_version", "1.1")
	some m in msgs
	contains(m.msg, "min_tls_version = \"1.1\"")
}

test_min_tls_12_is_allowed if {
	count(deny) == 0 with input as testdata.zone_setting("min_tls_version", "1.2")
}

test_always_use_https_off_is_warned_about if {
	msgs := warn with input as testdata.zone_setting("always_use_https", "off")
	some m in msgs
	contains(m.msg, "always_use_https = \"off\"")
}

test_always_use_https_on_is_allowed if {
	count(warn) == 0 with input as testdata.zone_setting("always_use_https", "on")
}

test_tls_1_3_off_is_warned_about if {
	msgs := warn with input as testdata.zone_setting("tls_1_3", "off")
	some m in msgs
	contains(m.msg, "tls_1_3 = \"off\"")
}

test_tls_1_3_on_is_allowed if {
	count(warn) == 0 with input as testdata.zone_setting("tls_1_3", "on")
}
