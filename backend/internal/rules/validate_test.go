package rules

import (
	"strings"
	"testing"
)

func ruleWithActions(actions ...Action) Rule {
	return Rule{
		Name:    "r",
		Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "from", Comparator: "contains", Value: "x"}}},
		Actions: actions,
	}
}

func TestValidateRule_AcceptsOrdinaryRules(t *testing.T) {
	cases := []struct {
		name    string
		actions []Action
	}{
		{"no actions", nil},
		{"keywords only", []Action{{Type: "keyword", Value: "VIP"}, {Type: "unkeyword", Value: "Old"}}},
		{"keyword then archive", []Action{{Type: "keyword", Value: "VIP"}, {Type: "archive"}}},
		{"archive then stop", []Action{{Type: "archive"}, {Type: "stop"}}},
		{"keyword, move, stop", []Action{{Type: "keyword", Value: "VIP"}, {Type: "move", Value: "Later"}, {Type: "stop"}}},
		{"stop alone", []Action{{Type: "stop"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateRule(ruleWithActions(tc.actions...)); err != nil {
				t.Fatalf("ValidateRule rejected a legitimate rule: %v", err)
			}
		})
	}
}

// The finding this exists for: nothing validated Actions on any write path, so
// a type the engine cannot execute was stored happily and then failed on every
// matching message — as a RETRYABLE failure, which deferred each message for
// the full maxDeferralAttempts window (~3h) before retiring it unlabelled.
func TestValidateRule_RejectsUnknownActionType(t *testing.T) {
	err := ValidateRule(ruleWithActions(Action{Type: "addflag", Value: "X"}))
	if err == nil {
		t.Fatal("expected an unknown action type to be rejected")
	}
	if !strings.Contains(err.Error(), "addflag") {
		t.Fatalf("error should name the offending type, got %q", err)
	}
}

func TestValidateRule_RejectsUnboundedActionList(t *testing.T) {
	actions := make([]Action, maxActionsPerRule+1)
	for i := range actions {
		actions[i] = Action{Type: "keyword", Value: "K"}
	}
	if err := ValidateRule(ruleWithActions(actions...)); err == nil {
		t.Fatalf("expected more than %d actions to be rejected", maxActionsPerRule)
	}
	if err := ValidateRule(ruleWithActions(actions[:maxActionsPerRule]...)); err != nil {
		t.Fatalf("exactly %d actions must be allowed, got %v", maxActionsPerRule, err)
	}
}

func TestValidateRule_BoundsNamesAndValues(t *testing.T) {
	long := strings.Repeat("a", maxRuleNameBytes+1)
	r := ruleWithActions(Action{Type: "keyword", Value: "K"})
	r.Name = long
	if err := ValidateRule(r); err == nil {
		t.Fatal("expected an oversized rule name to be rejected")
	}

	r = ruleWithActions(Action{Type: "keyword", Value: strings.Repeat("k", maxActionValueBytes+1)})
	if err := ValidateRule(r); err == nil {
		t.Fatal("expected an oversized action value to be rejected")
	}

	r = ruleWithActions(Action{Type: "keyword", Value: "  "})
	if err := ValidateRule(r); err == nil {
		t.Fatal("expected a keyword action with no value to be rejected")
	}

	r = ruleWithActions(Action{Type: "keyword", Value: "K"})
	r.Name = "   "
	if err := ValidateRule(r); err == nil {
		t.Fatal("expected a blank rule name to be rejected")
	}
}

// Two visibility-changing actions cannot both be honoured: whichever runs first
// takes the message out of the poller's UNSEEN-INBOX retry query, so if the
// second fails there is no tick that can come back for it.
func TestValidateRule_RejectsMultipleVisibilityChangingActions(t *testing.T) {
	pairs := [][]Action{
		{{Type: "read"}, {Type: "archive"}},
		{{Type: "archive"}, {Type: "move", Value: "Later"}},
		{{Type: "spam"}, {Type: "delete"}},
	}
	for _, actions := range pairs {
		if err := ValidateRule(ruleWithActions(actions...)); err == nil {
			t.Fatalf("expected %q + %q to be rejected", actions[0].Type, actions[1].Type)
		}
	}
}

// The ordering half. "archive; keyword" is the shape that made the promised
// retry impossible: archive succeeds, the keyword fails, and the message is
// already out of INBOX.
func TestValidateRule_RequiresVisibilityChangingActionLast(t *testing.T) {
	bad := [][]Action{
		{{Type: "archive"}, {Type: "keyword", Value: "VIP"}},
		{{Type: "read"}, {Type: "unkeyword", Value: "Old"}},
		{{Type: "move", Value: "Later"}, {Type: "stop"}, {Type: "keyword", Value: "VIP"}},
	}
	for _, actions := range bad {
		if err := ValidateRule(ruleWithActions(actions...)); err == nil {
			t.Fatalf("expected %q before a non-stop action to be rejected", actions[0].Type)
		}
	}
}

func TestValidateRule_AppliesMatchShapeCap(t *testing.T) {
	conds := make([]Condition, maxMatchConditions+1)
	for i := range conds {
		conds[i] = Condition{Field: "from", Comparator: "contains", Value: "x"}
	}
	r := Rule{Name: "r", Match: MatchGroup{Op: "allof", Conditions: conds}}
	if err := ValidateRule(r); err == nil {
		t.Fatal("ValidateRule must still enforce the match-shape cap")
	}
}

// rules.json predates this contract, so the write boundaries cannot be the only
// gate: both consumers act on the file with move, spam and delete.
func TestFilterRunnable_SkipsUnexecutableRulesAndKeepsTheRest(t *testing.T) {
	good := ruleWithActions(Action{Type: "keyword", Value: "VIP"})
	good.Name = "good"
	bad := ruleWithActions(Action{Type: "explode"})
	bad.Name = "bad"
	worse := ruleWithActions(Action{Type: "archive"}, Action{Type: "keyword", Value: "VIP"})
	worse.Name = "worse"

	out, rejected := FilterRunnable([]Rule{good, bad, worse})
	if len(out) != 1 || out[0].Name != "good" {
		t.Fatalf("runnable set = %+v, want only the valid rule", out)
	}
	if len(rejected) != 2 {
		t.Fatalf("rejected = %+v, want both invalid rules reported", rejected)
	}
	for _, why := range rejected {
		if !strings.HasPrefix(why, "bad: ") && !strings.HasPrefix(why, "worse: ") {
			t.Fatalf("rejection %q should name the rule it came from", why)
		}
	}
}
