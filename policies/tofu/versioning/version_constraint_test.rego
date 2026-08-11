package main

import data.lib.testdata
import rego.v1

test_root_pinned_with_pessimistic_operator_is_allowed if {
	count(warn) == 0 with input as testdata.provider_root(testdata.provider("~> 5.0"))
}

test_module_with_a_floor_is_allowed if {
	count(warn) == 0 with input as testdata.provider_module(testdata.provider(">= 5.0.0"))
}

test_root_with_a_floor_is_warned_about if {
	msgs := warn with input as testdata.provider_root(testdata.provider(">= 5.0.0"))
	count(msgs) == 1
	some m in msgs
	contains(m.msg, "a root must use ~>")
}

test_module_with_a_pessimistic_pin_is_warned_about if {
	msgs := warn with input as testdata.provider_module(testdata.provider("~> 5.0"))
	count(msgs) == 1
	some m in msgs
	contains(m.msg, "caps every root that consumes it")
}

# The pin is the one thing wrong with it, so the missing floor is not also
# reported: two findings would read as two things to fix.
test_module_with_a_pessimistic_pin_is_not_also_told_to_add_a_floor if {
	msgs := warn with input as testdata.provider_module(testdata.provider("~> 5.0"))
	every m in msgs {
		not contains(m.msg, "with >=")
	}
}

test_module_with_an_exact_version_is_warned_about if {
	msgs := warn with input as testdata.provider_module(testdata.provider("5.0.0"))
	count(msgs) == 1
	some m in msgs
	contains(m.msg, "the lowest version it works against")
}

test_root_with_an_exact_version_is_warned_about if {
	msgs := warn with input as testdata.provider_root(testdata.provider("5.0.0"))
	count(msgs) == 1
	some m in msgs
	contains(m.msg, "a root must use ~>")
}

# ">= 5.0.0" must not be read as ">" followed by "= 5.0.0", which would leave
# the module looking like it had stated an exact version.
test_greater_or_equal_is_not_read_as_greater_than if {
	count(warn) == 0 with input as testdata.provider_module(testdata.provider(">= 5.0.0"))
}

# A root may carry a floor alongside the pin. The pin is what the policy is
# about, and it is present.
test_root_pin_combined_with_a_floor_is_allowed if {
	count(warn) == 0 with input as testdata.provider_root(testdata.provider(">= 5.1.0, ~> 5.0"))
}

# An explicit upper bound in a module is deliberate rather than accidental, and
# the floor it is paired with is what the policy asks for.
test_module_with_an_explicit_upper_bound_is_allowed if {
	count(warn) == 0 with input as testdata.provider_module(testdata.provider(">= 5.0.0, < 6.0.0"))
}

test_provider_without_a_version_is_warned_about if {
	msgs := warn with input as testdata.provider_root({"cloudflare": {"source": "cloudflare/cloudflare"}})
	count(msgs) == 1
	some m in msgs
	contains(m.msg, "declared without a version constraint")
}

# The older `cloudflare = "~> 5.0"` shorthand carries the same constraint and
# is read the same way.
test_bare_string_shorthand_is_read_as_a_constraint if {
	count(warn) == 0 with input as testdata.provider_root({"cloudflare": "~> 5.0"})
}

test_bare_string_shorthand_is_checked_in_a_module_too if {
	msgs := warn with input as testdata.provider_module({"cloudflare": "~> 5.0"})
	count(msgs) == 1
	some m in msgs
	contains(m.msg, "caps every root that consumes it")
}

# Every provider in the block is read, not just the first.
test_each_provider_is_checked_independently if {
	msgs := warn with input as testdata.provider_root({
		"cloudflare": {"source": "cloudflare/cloudflare", "version": "~> 5.0"},
		"github": {"source": "integrations/github", "version": ">= 6.13.0"},
	})
	count(msgs) == 1
	some m in msgs
	contains(m.msg, "github")
}

# A root is whatever owns the state, backend{} or state_store{}. Reading only
# backend{} left a state_store root looking like a module, which turned the
# pin every root is asked for into the pin no module may have.
test_a_state_store_root_is_read_as_a_root_not_a_module if {
	count(warn) == 0 with input as testdata.provider_state_store_root(testdata.provider("~> 5.0"))
}

test_a_state_store_root_is_still_asked_for_a_pin if {
	msgs := warn with input as testdata.provider_state_store_root(testdata.provider(">= 5.0.0"))
	count(msgs) == 1
	some m in msgs
	contains(m.msg, "a root must use ~>")
}

# A directory with neither a backend nor required_providers is neither side of
# this policy and has nothing to answer for.
test_directory_without_required_providers_is_ignored if {
	count(warn) == 0 with input as testdata.provider_module({})
}

test_finding_is_anchored_to_the_declaring_file if {
	msgs := warn with input as testdata.provider_module(testdata.provider("~> 5.0"))
	some m in msgs
	m._loc == {"file": "lib/modules/example/versions.tf", "line": 1}
}
