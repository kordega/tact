package main

import data.lib.hcl
import rego.v1

# Input is conftest --combine over the whole repository:
# [{path, contents}, ...] with repository-relative paths.
#
# An SPF record is the TXT record at a domain that says which hosts are allowed
# to send mail as that domain. A receiver reads it to decide whether a message
# claiming to be from the domain is forged. The record only helps if it is both
# well formed and ends in a decision: a version tag with a typo in it, or one
# that ends by authorising everyone, reads to a receiver as "no opinion" and the
# domain is spoofable exactly as if the record were absent. Nothing about either
# looks wrong in a diff - the record is present and starts with v=spf1 - which is
# the case this file is about.
#
# The trigger is deliberately the v=spf1 prefix, not the record's name: a string
# that announces itself as SPF is held to being a correct SPF record, and a TXT
# record that is anything else (DKIM's v=DKIM1, a verification token) is passed
# over. Only literal content is judged; hcl2json renders `content = var.x` as
# "${var.x}", which asserts nothing about the value an apply resolves.

# A directive is [qualifier]mechanism; a modifier is name=value. These accept the
# RFC 7208 mechanism set with a lenient domain-spec (\S+), which is enough to
# tell a real term from a typo without reimplementing the macro grammar.
spf_directive := `^[-+?~]?(all|(include|exists):\S+|(ip4|ip6):\S+|ptr(:\S+)?|(a|mx)(:\S+)?(/\d{1,3})?(//\d{1,3})?)$`

spf_modifier := `^[a-z][a-z0-9._-]*=\S*$`

# Every TXT record whose literal content announces itself as SPF, carried
# together with the terms that follow the version tag so each rule reads them
# without re-parsing.
spf_records contains record if {
	some dns_record in hcl.resources_of_type(input, "cloudflare_dns_record")
	is_txt_type(dns_record)
	content := object.get(dns_record.body, "content", "")
	is_string(content)
	not hcl.unresolved(content)
	normalised := lower(trim_space(content))
	regex.match(`^v=spf1(\s|$)`, normalised)
	parts := regex.split(`\s+`, normalised)
	record := {
		"path": dns_record.path,
		"address": hcl.address(dns_record),
		"terms": array.slice(parts, 1, count(parts)),
	}
}

# Mechanism names and qualifiers are case-insensitive (RFC 7208 s4.6.1), so the
# type is matched the same way rather than assuming Cloudflare's uppercase TXT.
is_txt_type(dns_record) if lower(object.get(dns_record.body, "type", "")) == "txt"

# A term the mechanism and modifier grammars both reject is a typo - a bare
# domain, "v=spf1 mailfrom ...", a stray word. One is enough to make the record
# unparseable, at which point a receiver returns permerror and, in practice,
# stops checking SPF for the message: the domain is left spoofable.
deny contains hcl.finding(record.path, message) if {
	some record in spf_records
	some term in record.terms
	not valid_term(term)
	message := sprintf(
		"%s: %s is a TXT record beginning v=spf1 but the term %q is not a valid SPF mechanism or modifier, so the record does not parse and receivers fall back to treating the domain as unprotected",
		[record.path, record.address, term],
	)
}

valid_term(term) if regex.match(spf_directive, term)

valid_term(term) if regex.match(spf_modifier, term)

# "+all" authorises every host on the internet to send as the domain, and a bare
# "all" defaults to the same "+". "?all" is neutral, which asserts nothing about
# the sender either way. Both hand a receiver a record that ends by declining to
# reject anyone, so the domain is as spoofable as one with no record at all. The
# record is only judged once it parses, so this speaks to a formed record.
deny contains hcl.finding(record.path, message) if {
	some record in spf_records
	well_formed(record)
	all_qualifier := operative_all_qualifier(record.terms)
	all_qualifier in {"+", "?"}
	message := sprintf(
		"%s: %s ends its SPF record in %q, which %s; end it in \"-all\" so mail from any host it does not list is rejected",
		[record.path, record.address, sprintf("%sall", [all_qualifier]), all_reason(all_qualifier)],
	)
}

all_reason("+") := "authorises every host on the internet to send as this domain"

all_reason("?") := "leaves the result neutral, so a forged sender is neither passed nor rejected"

# No "all" and no "redirect=" means the record lists some senders and then says
# nothing about the rest: the default result is neutral, so it authorises the
# hosts it names and blocks nobody. A record that only allow-lists a provider
# and forgets the terminal is the common shape of this, and it protects nothing.
deny contains hcl.finding(record.path, message) if {
	some record in spf_records
	well_formed(record)
	not has_all(record.terms)
	not has_redirect(record.terms)
	message := sprintf(
		"%s: %s has no terminating \"all\" mechanism and no \"redirect\" modifier, so its result is neutral for every host it does not list and the domain stays spoofable; end it in \"-all\"",
		[record.path, record.address],
	)
}

# "~all" (softfail) is a real, secure terminal - mail from an unlisted host is
# accepted but marked suspicious - and plenty of domains run it deliberately
# while they watch reports before committing. It is the weaker of the two safe
# endings, so it is surfaced rather than denied: "-all" is the one that rejects.
warn contains hcl.finding(record.path, message) if {
	some record in spf_records
	well_formed(record)
	operative_all_qualifier(record.terms) == "~"
	message := sprintf(
		"%s: %s ends its SPF record in \"~all\" (softfail), which marks mail from an unlisted host rather than rejecting it; \"-all\" (hardfail) is the stronger terminal",
		[record.path, record.address],
	)
}

# SPF caps the mechanisms that each cost a DNS lookup - include, a, mx, ptr,
# exists and redirect - at ten (RFC 7208 s4.6.4). A resolver that reaches the
# eleventh stops and returns permerror, which discards the whole record, so a
# record over the limit is one include away from silently protecting nothing.
# The record itself is well formed and secure in intent, hence a warning.
warn contains hcl.finding(record.path, message) if {
	some record in spf_records
	well_formed(record)
	lookups := lookup_count(record.terms)
	lookups > 10
	message := sprintf(
		"%s: %s uses %d DNS-lookup mechanisms (include/a/mx/ptr/exists/redirect), over the limit of 10 in RFC 7208; a receiver stops at the tenth and returns permerror, discarding the record",
		[record.path, record.address, lookups],
	)
}

well_formed(record) if {
	every term in record.terms {
		valid_term(term)
	}
}

has_all(terms) if {
	some term in terms
	regex.match(`^[-+?~]?all$`, term)
}

has_redirect(terms) if {
	some term in terms
	regex.match(`^redirect=\S+$`, term)
}

# The first "all" is the operative one: SPF evaluates left to right and stops at
# the first match, so any "all" after it never decides anything.
operative_all_qualifier(terms) := qualifier(terms[first_all]) if {
	first_all := min({index |
		some index, term in terms
		regex.match(`^[-+?~]?all$`, term)
	})
}

qualifier(term) := normalise_qualifier(submatches[0][1]) if {
	submatches := regex.find_all_string_submatch_n(`^([-+?~]?)all$`, term, 1)
}

# An "all" with no qualifier defaults to "+" (RFC 7208 s4.6.2).
normalise_qualifier("") := "+"

normalise_qualifier(found) := found if found != ""

lookup_count(terms) := count([term |
	some term in terms
	causes_lookup(term)
])

causes_lookup(term) if regex.match(`^[-+?~]?(include|exists|ptr|mx|a)(:|/|$)`, term)

causes_lookup(term) if regex.match(`^redirect=`, term)
