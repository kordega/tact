package main

import data.lib.testdata
import rego.v1

# A well-formed record ending in a hardfail is the shape every other test breaks
# exactly one thing away from.
test_hardfail_record_is_allowed if {
	count(deny) == 0 with input as testdata.spf_txt("v=spf1 include:_spf.google.com ip4:192.0.2.0/24 -all")
	count(warn) == 0 with input as testdata.spf_txt("v=spf1 include:_spf.google.com ip4:192.0.2.0/24 -all")
}

test_a_bare_v_spf1_hardfail_is_allowed if {
	count(deny) == 0 with input as testdata.spf_txt("v=spf1 -all")
	count(warn) == 0 with input as testdata.spf_txt("v=spf1 -all")
}

# A record that delegates its whole policy with redirect and never writes an all
# is complete: the terminal lives at the target.
test_redirect_without_all_is_allowed if {
	count(deny) == 0 with input as testdata.spf_txt("v=spf1 redirect=_spf.example.com")
	count(warn) == 0 with input as testdata.spf_txt("v=spf1 redirect=_spf.example.com")
}

test_uppercase_mechanisms_are_allowed if {
	count(deny) == 0 with input as testdata.spf_txt("V=SPF1 INCLUDE:_spf.google.com -ALL")
}

# A non-SPF TXT record is not held to the SPF grammar.
test_a_dkim_txt_record_is_ignored if {
	count(deny) == 0 with input as testdata.spf_txt("v=DKIM1; k=rsa; p=MIGf")
	count(warn) == 0 with input as testdata.spf_txt("v=DKIM1; k=rsa; p=MIGf")
}

# v=spf1 must stand as the version tag, not be the prefix of another word.
test_a_lookalike_version_tag_is_ignored if {
	count(deny) == 0 with input as testdata.spf_txt("v=spf10 something")
}

# Only TXT records carry SPF; the same string on another type says nothing.
test_a_non_txt_record_is_ignored if {
	count(deny) == 0 with input as testdata.dns_record({
		"type": "CNAME",
		"name": "example.com",
		"content": "v=spf1 +all",
	})
}

# A content built from a variable is not a literal this policy can judge.
test_unresolved_content_is_ignored if {
	count(deny) == 0 with input as testdata.spf_txt("${var.spf_record}")
	count(warn) == 0 with input as testdata.spf_txt("${var.spf_record}")
}

test_a_record_without_content_is_ignored if {
	count(deny) == 0 with input as testdata.dns_record({"type": "TXT", "name": "example.com"})
}

test_a_malformed_term_is_denied if {
	msgs := deny with input as testdata.spf_txt("v=spf1 include:_spf.google.com mailfrom example.com -all")
	some m in msgs
	contains(m.msg, "the term \"example.com\" is not a valid SPF mechanism or modifier")
	contains(m.msg, "receivers fall back to treating the domain as unprotected")
}

test_each_malformed_term_is_reported_separately if {
	msgs := deny with input as testdata.spf_txt("v=spf1 foo bar -all")
	count(msgs) == 2
}

# A malformed record is denied for the typo, not additionally judged on its all.
test_a_malformed_record_is_not_also_judged_on_security if {
	msgs := deny with input as testdata.spf_txt("v=spf1 foo +all")
	every m in msgs {
		not contains(m.msg, "authorises every host")
	}
}

test_plus_all_is_denied if {
	msgs := deny with input as testdata.spf_txt("v=spf1 include:_spf.google.com +all")
	some m in msgs
	contains(m.msg, "ends its SPF record in \"+all\"")
	contains(m.msg, "authorises every host on the internet to send as this domain")
}

# A bare all defaults to +all and is denied the same way.
test_bare_all_is_denied if {
	msgs := deny with input as testdata.spf_txt("v=spf1 include:_spf.google.com all")
	some m in msgs
	contains(m.msg, "ends its SPF record in \"+all\"")
}

test_neutral_all_is_denied if {
	msgs := deny with input as testdata.spf_txt("v=spf1 include:_spf.google.com ?all")
	some m in msgs
	contains(m.msg, "ends its SPF record in \"?all\"")
	contains(m.msg, "a forged sender is neither passed nor rejected")
}

# Terms allow-listed but no terminal: neutral for everyone else.
test_a_record_with_no_terminal_is_denied if {
	msgs := deny with input as testdata.spf_txt("v=spf1 include:_spf.google.com ip4:192.0.2.0/24")
	some m in msgs
	contains(m.msg, "no terminating \"all\" mechanism and no \"redirect\" modifier")
	contains(m.msg, "the domain stays spoofable")
}

# A version tag on its own lists nobody and ends nothing.
test_a_version_tag_alone_is_denied if {
	msgs := deny with input as testdata.spf_txt("v=spf1")
	some m in msgs
	contains(m.msg, "no terminating \"all\" mechanism and no \"redirect\" modifier")
}

test_softfail_all_is_warned_about if {
	count(deny) == 0 with input as testdata.spf_txt("v=spf1 include:_spf.google.com ~all")
	msgs := warn with input as testdata.spf_txt("v=spf1 include:_spf.google.com ~all")
	some m in msgs
	contains(m.msg, "ends its SPF record in \"~all\" (softfail)")
	contains(m.msg, "\"-all\" (hardfail) is the stronger terminal")
}

# The first all decides; a trailing +all after a -all never runs.
test_only_the_first_all_is_judged if {
	count(deny) == 0 with input as testdata.spf_txt("v=spf1 -all +all")
}

test_too_many_lookups_is_warned_about if {
	content := "v=spf1 include:a include:b include:c include:d include:e include:f include:g include:h include:i include:j include:k -all"
	msgs := warn with input as testdata.spf_txt(content)
	some m in msgs
	contains(m.msg, "uses 11 DNS-lookup mechanisms")
	contains(m.msg, "over the limit of 10 in RFC 7208")
}

# Exactly ten lookups is within the limit; ip4 and all do not count.
test_ten_lookups_is_allowed if {
	content := "v=spf1 include:a include:b include:c include:d include:e include:f include:g include:h include:i include:j ip4:192.0.2.0/24 -all"
	count(warn) == 0 with input as testdata.spf_txt(content)
}

# The full mechanism and modifier grammar parses without a malformed finding.
test_the_full_grammar_parses if {
	content := "v=spf1 a mx a:mail.example.com/24 mx:alt.example.com ptr ptr:example.com exists:%{i}.example.com ip6:2001:db8::/32 exp=why.example.com -all"
	count(deny) == 0 with input as testdata.spf_txt(content)
}
