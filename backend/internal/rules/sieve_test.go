package rules

import (
	"fmt"
	"strings"
	"testing"
)

// wantCondition describes the expected shape of one parsed Condition,
// including (via group) the nested conditions of a Condition.Group so
// success-case subtests can assert group contents, not just the top level.
type wantCondition struct {
	negate     bool
	field      string
	comparator string
	value      string
	group      []wantCondition // non-nil => Condition.Group expected, checked recursively
}

// assertConditions compares got against want field-by-field (Negate, Field,
// Comparator, Value), recursing into Condition.Group when want.group is set.
// A bug like a comparator tag being silently defaulted instead of read from
// the actual Sieve source would previously slip past TestParseRuleText,
// which only checked len(Match.Conditions); this catches it.
func assertConditions(t *testing.T, path string, got []Condition, want []wantCondition) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: len = %d, want %d (%+v)", path, len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		item := fmt.Sprintf("%s[%d]", path, i)
		if w.group != nil {
			if g.Group == nil {
				t.Fatalf("%s: Group = nil, want a nested group %+v", item, w.group)
			}
			assertConditions(t, item+".Group", g.Group.Conditions, w.group)
			continue
		}
		if g.Group != nil {
			t.Fatalf("%s: Group = %+v, want a leaf condition", item, g.Group)
		}
		if g.Negate != w.negate {
			t.Errorf("%s: Negate = %v, want %v", item, g.Negate, w.negate)
		}
		if g.Field != w.field {
			t.Errorf("%s: Field = %q, want %q", item, g.Field, w.field)
		}
		if g.Comparator != w.comparator {
			t.Errorf("%s: Comparator = %q, want %q", item, g.Comparator, w.comparator)
		}
		if g.Value != w.value {
			t.Errorf("%s: Value = %q, want %q", item, g.Value, w.value)
		}
	}
}

func TestParseRuleText(t *testing.T) {
	tests := []struct {
		name       string
		script     string
		wantOp     string
		wantConds  []wantCondition
		wantAction []Action
	}{
		{
			name:   "simple header contains with fileinto",
			script: "require [\"fileinto\"];\n\nif allof(header :contains [\"from\"] \"acme\") {\n    fileinto \"Archive/Acme\";\n}\n",
			wantOp: "allof",
			wantConds: []wantCondition{
				{field: "from", comparator: "contains", value: "acme"},
			},
			wantAction: []Action{{Type: "move", Value: "Archive/Acme"}},
		},
		{
			name:   "anyof with not and hasflag",
			script: "require [\"kymail\", \"imap4flags\"];\nif anyof(not header :is [\"subject\"] \"spam\", hasflag :is \"VIP\") {\n    archive;\n    stop;\n}\n",
			wantOp: "anyof",
			wantConds: []wantCondition{
				{negate: true, field: "subject", comparator: "is", value: "spam"},
				{field: "keyword", comparator: "is", value: "VIP"},
			},
			wantAction: []Action{{Type: "archive"}, {Type: "stop"}},
		},
		{
			name:   "keep produces no actions",
			script: "if allof(body :contains \"unsubscribe\") {\n    keep;\n}\n",
			wantOp: "allof",
			wantConds: []wantCondition{
				{field: "body", comparator: "contains", value: "unsubscribe"},
			},
			wantAction: nil,
		},
		{
			name:   "comments are stripped",
			script: "# a leading comment\nif allof(header :contains [\"from\"] \"acme\") { # inline comment\n    /* block\n       comment */\n    fileinto \"X\";\n}\n",
			wantOp: "allof",
			wantConds: []wantCondition{
				{field: "from", comparator: "contains", value: "acme"},
			},
			wantAction: []Action{{Type: "move", Value: "X"}},
		},
		{
			// A header/address test with more than one field name becomes a
			// nested anyof Condition.Group (see fieldsToCondition); this
			// exercises assertConditions' recursion into .group, and also
			// covers the new valid-field-name path (both names are in
			// validHeaderAddressFields) alongside Issue 1's rejection path.
			name:   "header test with multiple fields becomes nested anyof group",
			script: "if allof(header :is [\"from\", \"to\"] \"acme\") {\n    keep;\n}\n",
			wantOp: "allof",
			wantConds: []wantCondition{
				{group: []wantCondition{
					{field: "from", comparator: "is", value: "acme"},
					{field: "to", comparator: "is", value: "acme"},
				}},
			},
			wantAction: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRuleText(tc.script, Rule{ID: "rule-1", Name: "kept"})
			if err != nil {
				t.Fatalf("ParseRuleText: %v", err)
			}
			if got.ID != "rule-1" || got.Name != "kept" {
				t.Fatalf("expected non-Match/Actions fields to pass through, got %+v", got)
			}
			if got.Match.Op != tc.wantOp {
				t.Fatalf("Match.Op = %q, want %q", got.Match.Op, tc.wantOp)
			}
			assertConditions(t, "Match.Conditions", got.Match.Conditions, tc.wantConds)
			if len(got.Actions) != len(tc.wantAction) {
				t.Fatalf("Actions = %+v, want %+v", got.Actions, tc.wantAction)
			}
			for i, want := range tc.wantAction {
				if got.Actions[i] != want {
					t.Errorf("Actions[%d] = %+v, want %+v", i, got.Actions[i], want)
				}
			}
		})
	}
}

func TestParseRuleText_Errors(t *testing.T) {
	tests := []struct {
		name       string
		script     string
		wantSubstr string
	}{
		{
			name:       "unknown test",
			script:     "if bogustest([\"from\"] \"x\") {\n  keep;\n}\n",
			wantSubstr: "unknown test",
		},
		{
			name:       "unknown action",
			script:     "if allof(header :contains [\"from\"] \"x\") {\n  bogusaction;\n}\n",
			wantSubstr: "unknown action",
		},
		{
			name:       "unbalanced braces",
			script:     "if allof(header :contains [\"from\"] \"x\") {\n  keep;\n",
			wantSubstr: "unbalanced braces",
		},
		{
			name:       "unsupported require capability",
			script:     "require [\"nonexistent\"];\nif allof(header :contains [\"from\"] \"x\") {\n  keep;\n}\n",
			wantSubstr: "unsupported require capability",
		},
		{
			// Regression test for Issue 1: "keyword" and "body" are only
			// valid as their own dedicated Sieve test types (hasflag / body
			// test), not as a field name inside a header/address field list.
			// Before this fix, this parsed successfully to
			// Condition{Field:"keyword", ...}, which CompileRule then
			// silently re-emits as a hasflag test — a different Sieve test
			// with different semantics, with no error anywhere.
			name:       "header test with keyword field name is rejected",
			script:     "if allof(header :is [\"keyword\"] \"urgent\") {\n  keep;\n}\n",
			wantSubstr: "unsupported header/address field \"keyword\"",
		},
		{
			// Regression test for the sibling of Issue 1: the exists test
			// path had the identical hazard as header/address. Before this
			// fix, exists ["body"] parsed successfully to
			// Condition{Field:"body", Comparator:"exists", Value:""}, which
			// CompileRule then silently re-emits as `body :is ""` — an
			// always-near-true body-contains-empty-string test, not an
			// existence check — a completely different Sieve test with no
			// error anywhere.
			name:       "exists test with body field name is rejected",
			script:     "if exists [\"body\"] {\n  keep;\n}\n",
			wantSubstr: "unsupported exists field \"body\"",
		},
		{
			name:       "exists test with keyword field name is rejected",
			script:     "if exists [\"keyword\"] {\n  keep;\n}\n",
			wantSubstr: "unsupported exists field \"keyword\"",
		},
		{
			// Regression test for the unbounded-recursion issue found in the
			// final whole-branch review: parseTest used to recurse on
			// not/allof/anyof with no depth limit, so a script nesting
			// allof(allof(allof(...))) deeply (bounded only by the 1 MiB
			// request-body limit in rules_handlers.go) could drive parser
			// recursion into the hundreds of thousands of stack frames — and,
			// once such a rule parsed successfully and was stored, force
			// engine.go's matchGroup/conditionMatches to re-walk that same
			// deep tree on every message the poller evaluates thereafter.
			// This nests allof() 50 levels deep, well past maxTestNestingDepth
			// (32), and expects a clear rejection rather than success, a
			// crash, or an unreasonably long parse.
			name: "excessive allof nesting is rejected",
			script: "if " + strings.Repeat("allof(", 50) +
				`header :contains ["from"] "x"` +
				strings.Repeat(")", 50) +
				" {\n  keep;\n}\n",
			wantSubstr: "test nesting exceeds maximum depth",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRuleText(tc.script, Rule{})
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tc.wantSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantSubstr)
			}
		})
	}
}

// TestParseRuleText_ReasonableNestingStillParses confirms maxTestNestingDepth
// (32) doesn't affect any realistic hand-written rule: a script nesting
// allof/anyof/not five keywords deep (four nested MatchGroup levels plus one
// negation) — deeper than anything the flat GUI builder or a typical
// hand-edited rule would ever produce, but nowhere near the new limit —
// still parses successfully into the expected nested
// MatchGroup/Condition.Group tree.
func TestParseRuleText_ReasonableNestingStillParses(t *testing.T) {
	script := "if allof(anyof(not allof(anyof(header :contains [\"from\"] \"acme\")))) {\n  keep;\n}\n"
	got, err := ParseRuleText(script, Rule{})
	if err != nil {
		t.Fatalf("ParseRuleText: unexpected error for a reasonably-nested (4 level) rule: %v", err)
	}

	// Walk down the tree confirming the expected shape at each of the 4
	// nested levels, ending on the negated leaf condition.
	if got.Match.Op != "allof" || len(got.Match.Conditions) != 1 {
		t.Fatalf("level 1 (allof): Match = %+v", got.Match)
	}
	level2 := got.Match.Conditions[0]
	if level2.Group == nil || level2.Group.Op != "anyof" || len(level2.Group.Conditions) != 1 {
		t.Fatalf("level 2 (anyof): %+v", level2)
	}
	level3 := level2.Group.Conditions[0]
	if !level3.Negate || level3.Group == nil || level3.Group.Op != "allof" || len(level3.Group.Conditions) != 1 {
		t.Fatalf("level 3 (not allof): %+v", level3)
	}
	level4 := level3.Group.Conditions[0]
	if level4.Group == nil || level4.Group.Op != "anyof" || len(level4.Group.Conditions) != 1 {
		t.Fatalf("level 4 (anyof): %+v", level4)
	}
	leaf := level4.Group.Conditions[0]
	if leaf.Field != "from" || leaf.Comparator != "contains" || leaf.Value != "acme" {
		t.Fatalf("leaf condition: %+v", leaf)
	}
}

// flatMatchGroup builds a single-level "anyof" MatchGroup with n leaf
// conditions, used to test ValidateMatchShape's width bound independent of
// nesting depth.
func flatMatchGroup(n int) MatchGroup {
	conds := make([]Condition, 0, n)
	for i := 0; i < n; i++ {
		conds = append(conds, Condition{Field: "subject", Comparator: "contains", Value: fmt.Sprintf("v%d", i)})
	}
	return MatchGroup{Op: "anyof", Conditions: conds}
}

func TestValidateMatchShapeRejectsTooManyConditions(t *testing.T) {
	m := flatMatchGroup(maxMatchConditions + 1)
	err := ValidateMatchShape(m)
	if err == nil {
		t.Fatal("expected an error for a flat tree exceeding maxMatchConditions")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("more than %d", maxMatchConditions)) {
		t.Fatalf("error = %q, want it to mention the %d limit", err.Error(), maxMatchConditions)
	}
}

func TestValidateMatchShapeAcceptsExactlyAtLimit(t *testing.T) {
	m := flatMatchGroup(maxMatchConditions)
	if err := ValidateMatchShape(m); err != nil {
		t.Fatalf("expected exactly maxMatchConditions (%d) to be accepted, got: %v", maxMatchConditions, err)
	}
}

// TestValidateMatchShapeStillEnforcesDepth confirms a deep-but-narrow tree
// (few total conditions, but many nesting levels) is still rejected on
// depth grounds — the new width counter must not have displaced the
// existing depth check.
func TestValidateMatchShapeStillEnforcesDepth(t *testing.T) {
	// Build maxTestNestingDepth+1 levels of nested single-condition allof
	// groups — well under maxMatchConditions in total leaf count.
	leaf := Condition{Field: "subject", Comparator: "contains", Value: "x"}
	group := MatchGroup{Op: "allof", Conditions: []Condition{leaf}}
	for i := 0; i < maxTestNestingDepth+1; i++ {
		group = MatchGroup{Op: "allof", Conditions: []Condition{{Group: &group}}}
	}

	err := ValidateMatchShape(group)
	if err == nil {
		t.Fatal("expected an error for a tree exceeding maxTestNestingDepth")
	}
	if !strings.Contains(err.Error(), "nesting exceeds maximum depth") {
		t.Fatalf("error = %q, want a nesting-depth error", err.Error())
	}
}

// TestValidateMatchShapeCountsAcrossGroupBoundaries confirms the leaf
// counter accumulates correctly through nested groups, not just within one
// flat group — a tree with several nested groups each holding conditions
// under the limit individually must still be rejected once their combined
// total exceeds maxMatchConditions.
func TestValidateMatchShapeCountsAcrossGroupBoundaries(t *testing.T) {
	perGroup := 10
	numGroups := maxMatchConditions/perGroup + 1 // total leaves > maxMatchConditions
	top := MatchGroup{Op: "allof"}
	for g := 0; g < numGroups; g++ {
		inner := flatMatchGroup(perGroup)
		top.Conditions = append(top.Conditions, Condition{Group: &inner})
	}

	err := ValidateMatchShape(top)
	if err == nil {
		t.Fatalf("expected an error: %d groups of %d conditions (%d total) exceeds the %d limit",
			numGroups, perGroup, numGroups*perGroup, maxMatchConditions)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("more than %d", maxMatchConditions)) {
		t.Fatalf("error = %q, want it to mention the %d limit", err.Error(), maxMatchConditions)
	}
}

// TestRoundTrip verifies CompileRule(mustParse(CompileRule(r))) is
// semantically equivalent to CompileRule(r) for every GUI-producible rule
// shape (flat allof/anyof of leaf conditions, one condition per field).
func TestRoundTrip(t *testing.T) {
	fixtures := []Rule{
		{
			Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "from", Comparator: "contains", Value: "acme"}}},
			Actions: []Action{{Type: "move", Value: "Archive/Acme"}},
		},
		{
			Match: MatchGroup{Op: "anyof", Conditions: []Condition{
				{Field: "subject", Comparator: "is", Value: "spam", Negate: true},
				{Field: "keyword", Comparator: "contains", Value: "vip"},
				{Field: "body", Comparator: "matches", Value: "*unsubscribe*"},
			}},
			Actions: []Action{{Type: "keyword", Value: "Flagged"}, {Type: "unkeyword", Value: "Unread"}, {Type: "stop"}},
		},
		{
			Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "cc", Comparator: "exists"}}},
			Actions: []Action{{Type: "read"}, {Type: "archive"}, {Type: "spam"}, {Type: "delete"}},
		},
		{
			Match: MatchGroup{Op: "allof", Conditions: []Condition{{Field: "to", Comparator: "regex", Value: "^a.*z$"}}},
		},
	}

	for i, rule := range fixtures {
		first, err := CompileRule(rule)
		if err != nil {
			t.Fatalf("fixture %d: CompileRule: %v", i, err)
		}
		parsed, err := ParseRuleText(first, Rule{})
		if err != nil {
			t.Fatalf("fixture %d: ParseRuleText(%q): %v", i, first, err)
		}
		second, err := CompileRule(parsed)
		if err != nil {
			t.Fatalf("fixture %d: CompileRule(parsed): %v", i, err)
		}
		if first != second {
			t.Fatalf("fixture %d: round trip mismatch:\nfirst:\n%s\nsecond:\n%s", i, first, second)
		}
	}
}

func TestCompileRule(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
		want string
	}{
		{
			name: "single condition with move action",
			rule: Rule{
				Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "from", Comparator: "contains", Value: "acme"}}},
				Actions: []Action{{Type: "move", Value: "Archive/Acme"}},
			},
			want: "require [\"fileinto\"];\n\nif allof(header :contains [\"from\"] \"acme\") {\n    fileinto \"Archive/Acme\";\n}\n",
		},
		{
			name: "anyof with negate and stop",
			rule: Rule{
				Match: MatchGroup{Op: "anyof", Conditions: []Condition{
					{Field: "subject", Comparator: "is", Value: "spam", Negate: true},
					{Field: "keyword", Comparator: "is", Value: "VIP"},
				}},
				Actions: []Action{{Type: "archive"}, {Type: "stop"}},
			},
			want: "require [\"imap4flags\", \"kymail\"];\n\nif anyof(not header :is [\"subject\"] \"spam\", hasflag :is \"VIP\") {\n    archive;\n    stop;\n}\n",
		},
		{
			name: "no actions renders keep",
			rule: Rule{
				Match: MatchGroup{Op: "allof", Conditions: []Condition{{Field: "body", Comparator: "contains", Value: "unsubscribe"}}},
			},
			want: "require [\"body\"];\n\nif allof(body :contains \"unsubscribe\") {\n    keep;\n}\n",
		},
		{
			name: "regex comparator",
			rule: Rule{
				Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "subject", Comparator: "regex", Value: "^Re:.*invoice$"}}},
				Actions: []Action{{Type: "delete"}},
			},
			want: "require [\"regex\"];\n\nif allof(header :regex [\"subject\"] \"^Re:.*invoice$\") {\n    discard;\n}\n",
		},
		{
			name: "addflag and removeflag",
			rule: Rule{
				Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "to", Comparator: "is", Value: "me@example.com"}}},
				Actions: []Action{{Type: "keyword", Value: "Personal"}, {Type: "unkeyword", Value: "Unread"}},
			},
			want: "require [\"imap4flags\"];\n\nif allof(header :is [\"to\"] \"me@example.com\") {\n    addflag \"Personal\";\n    removeflag \"Unread\";\n}\n",
		},
		{
			name: "exists comparator",
			rule: Rule{
				Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "cc", Comparator: "exists"}}},
				Actions: []Action{{Type: "read"}},
			},
			want: "require [\"kymail\"];\n\nif allof(exists [\"cc\"]) {\n    markread;\n}\n",
		},
		{
			name: "markspam",
			rule: Rule{
				Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "bcc", Comparator: "matches", Value: "*@spam.example"}}},
				Actions: []Action{{Type: "spam"}},
			},
			want: "require [\"kymail\"];\n\nif allof(header :matches [\"bcc\"] \"*@spam.example\") {\n    markspam;\n}\n",
		},
		{
			// Covers the Condition.Group recursion path: a nested anyof group
			// (with an internal Negate:true leaf) sits alongside a plain leaf
			// condition inside a top-level allof, and the whole nested group
			// condition is itself negated. Also exercises the
			// matchGroupUsesField/matchGroupUsesComparator recursion into
			// Group, since the nested group is what supplies the "keyword"
			// field (imap4flags) and "regex" comparator (regex) capabilities.
			name: "nested group with negate",
			rule: Rule{
				Match: MatchGroup{Op: "allof", Conditions: []Condition{
					{Field: "from", Comparator: "contains", Value: "acme"},
					{
						Negate: true,
						Group: &MatchGroup{Op: "anyof", Conditions: []Condition{
							{Field: "subject", Comparator: "regex", Value: "^Re:", Negate: true},
							{Field: "keyword", Comparator: "is", Value: "VIP"},
						}},
					},
				}},
				Actions: []Action{{Type: "move", Value: "Archive/Important"}},
			},
			want: "require [\"fileinto\", \"regex\", \"imap4flags\"];\n\nif allof(header :contains [\"from\"] \"acme\", not anyof(not header :regex [\"subject\"] \"^Re:\", hasflag :is \"VIP\")) {\n    fileinto \"Archive/Important\";\n}\n",
		},
		{
			// Covers the zero-capability path: subject/contains and stop are
			// both capability-free constructs, so the `if len(caps) > 0`
			// guard around the require line must take its false branch and
			// emit no require statement at all.
			name: "no capabilities used renders no require line",
			rule: Rule{
				Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "subject", Comparator: "contains", Value: "X"}}},
				Actions: []Action{{Type: "stop"}},
			},
			want: "if allof(header :contains [\"subject\"] \"X\") {\n    stop;\n}\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CompileRule(tc.rule)
			if err != nil {
				t.Fatalf("CompileRule: %v", err)
			}
			if got != tc.want {
				t.Fatalf("CompileRule() =\n%q\nwant\n%q", got, tc.want)
			}
			if !strings.Contains(tc.want, "require") && strings.Contains(got, "require") {
				t.Fatalf("CompileRule() unexpectedly emitted a require line:\n%q", got)
			}
		})
	}
}

// TestValidateMatchShapeBoundsConditionValue is run-7 finding F5.
//
// maxMatchConditions bounded how many conditions run; nothing bounded what each
// one cost. matchesValue compiles Value as a regex per condition per evaluation,
// so 300 conditions x a few KB of alternation — well inside every count cap —
// measured at ~37s per message, inside the capacity-1 instance-wide poll
// semaphore, uninterruptible because Evaluate takes no context.
//
// This is the "cap :regex pattern length" item run-4's remediation asked for.
func TestValidateMatchShapeBoundsConditionValue(t *testing.T) {
	oversized := MatchGroup{
		Op: "anyof",
		Conditions: []Condition{
			{Field: "subject", Comparator: "regex", Value: strings.Repeat("(?:aa|bb)", 400)},
		},
	}
	if err := ValidateMatchShape(oversized); err == nil {
		t.Fatal("a multi-kilobyte regex condition value was accepted; 300 of these per rule is " +
			"tens of seconds of uninterruptible CPU per message on the shared poller")
	}

	// A realistic rule must still pass.
	ok := MatchGroup{
		Op: "allof",
		Conditions: []Condition{
			{Field: "from", Comparator: "contains", Value: "newsletter@example.com"},
			{Field: "subject", Comparator: "regex", Value: "^\\[ANN\\] .*"},
		},
	}
	if err := ValidateMatchShape(ok); err != nil {
		t.Fatalf("an ordinary rule was rejected: %v", err)
	}
}
