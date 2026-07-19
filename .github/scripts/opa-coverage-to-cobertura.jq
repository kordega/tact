# Converts the JSON report of `opa test --coverage --format json` into a
# Cobertura XML report, which is the only format the coverage upload accepts.
#
# OPA reports coverage as line ranges per file, Cobertura wants one <line> per
# line, grouped into a <class> per file and a <package> per directory. A row
# that shows up in both lists counts as covered.
#
# The _test.rego files are dropped: the assertions run themselves by
# definition, so leaving them in only pads the number with lines that cannot
# be uncovered.
#
# Takes the report on stdin and needs no arguments.

def xml_escape:
	gsub("&"; "&amp;") | gsub("<"; "&lt;") | gsub(">"; "&gt;") | gsub("\""; "&quot;");

# OPA leaves the key out entirely when a file has nothing in that bucket.
def rows($ranges): [($ranges // [])[] | range(.start.row; .end.row + 1)];

# Cobertura reads the rates as floats between 0 and 1. A file with no
# reportable line is vacuously fully covered, and dividing by zero would render
# as null.
def rate($covered; $valid): (if $valid == 0 then 1 else $covered / $valid end)
	| . * 10000 | round / 10000 | tostring;

def classes:
	map(
		"        <class name=\"\(.name | xml_escape)\" filename=\"\(.file | xml_escape)\" line-rate=\"\(rate(.covered; .valid))\" branch-rate=\"1\" complexity=\"0\">",
		"          <methods/>",
		"          <lines>",
		(.lines[] | "            <line number=\"\(.number)\" hits=\"\(.hits)\" branch=\"false\"/>"),
		"          </lines>",
		"        </class>"
	) | .[];

def packages:
	map(
		"    <package name=\"\(.name | xml_escape)\" line-rate=\"\(rate(.covered; .valid))\" branch-rate=\"1\" complexity=\"0\">",
		"      <classes>",
		(.classes | classes),
		"      </classes>",
		"    </package>"
	) | .[];

[
	.files
	| to_entries[]
	| select(.key | endswith("_test.rego") | not)
	| (.key | split("/")) as $parts
	| {
		file: .key,
		name: $parts[-1],
		package: ($parts[:-1] | join(".")),
		lines: (
			[rows(.value.not_covered)[] | {number: ., hits: 0}]
			+ [rows(.value.covered)[] | {number: ., hits: 1}]
			| group_by(.number)
			| map({number: .[0].number, hits: (map(.hits) | max)})
		),
	}
	| .valid = (.lines | length)
	| .covered = ([.lines[] | select(.hits > 0)] | length)
]
| group_by(.package)
| map({
	name: .[0].package,
	classes: .,
	valid: (map(.valid) | add),
	covered: (map(.covered) | add),
}) as $packages
| ($packages | map(.valid) | add // 0) as $valid
| ($packages | map(.covered) | add // 0) as $covered
| [
	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
	"<!DOCTYPE coverage SYSTEM \"http://cobertura.sourceforge.net/xml/coverage-04.dtd\">",
	"<coverage line-rate=\"\(rate($covered; $valid))\" branch-rate=\"1\" lines-covered=\"\($covered)\" lines-valid=\"\($valid)\" branches-covered=\"0\" branches-valid=\"0\" complexity=\"0\" version=\"opa\" timestamp=\"\(now | floor)\">",
	"  <sources>",
	"    <source>.</source>",
	"  </sources>",
	"  <packages>",
	($packages | packages),
	"  </packages>",
	"</coverage>"
]
| join("\n")
