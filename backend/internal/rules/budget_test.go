package rules

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// expensiveRuleSet builds a rule set that is entirely legal — every value is
// inside maxConditionValueBytes, every match tree inside maxMatchConditions,
// and the rule count inside maxRulesPerUser — and yet costs seconds per message.
//
// That is the finding: the caps bound the SHAPE of a match tree and never its
// cost. The ~8.9us/condition figure the caps were chosen against is documented
// in sieve.go as being for the `contains` comparator; a legal alternation
// compiles to hundreds of instructions and matches far more slowly.
func expensiveRuleSet(t *testing.T, rules, conditions int) []Rule {
	t.Helper()
	var alts []string
	for i := 0; i < 25; i++ {
		alts = append(alts, fmt.Sprintf("wo%02drd[0-9a-z]+", i))
	}
	pattern := "(" + strings.Join(alts, "|") + ")"
	if len(pattern) > maxConditionValueBytes {
		t.Fatalf("test pattern must be legal: %d > %d", len(pattern), maxConditionValueBytes)
	}
	out := make([]Rule, 0, rules)
	for r := 0; r < rules; r++ {
		conds := make([]Condition, 0, conditions)
		for c := 0; c < conditions; c++ {
			conds = append(conds, Condition{Field: "body", Comparator: "regex", Value: pattern})
		}
		rule := Rule{
			Name:    fmt.Sprintf("rule-%d", r),
			Enabled: true,
			Order:   r,
			Match:   MatchGroup{Op: "anyof", Conditions: conds},
			Actions: []Action{{Type: "delete"}},
		}
		if err := ValidateRule(rule); err != nil {
			t.Fatalf("test rule must be legal: %v", err)
		}
		out = append(out, rule)
	}
	return out
}

// TestEvaluateIsBoundedByAWallClockBudget pins the bound that the structural
// caps do not provide.
//
// ctx is threaded through Evaluate, but the only thing that cancels it is the
// CLIENT DISCONNECTING — and an attacker holds the connection open. So on
// POST /api/rules/run a maximum legal configuration runs to completion however
// long that takes, and on the shared poller it consumes the whole per-message
// budget. Evaluation has to bound its own cost.
func TestEvaluateIsBoundedByAWallClockBudget(t *testing.T) {
	prev := maxEvaluationBudget
	maxEvaluationBudget = 150 * time.Millisecond
	t.Cleanup(func() { maxEvaluationBudget = prev })

	rules := expensiveRuleSet(t, 100, 300)
	input := EvalInput{Folder: "INBOX", Body: strings.Repeat("harmless filler text ", 5000)}

	start := time.Now()
	Evaluate(context.Background(), input, rules)
	elapsed := time.Since(start)

	if elapsed > 20*maxEvaluationBudget {
		t.Fatalf("evaluation ran for %s against a %s budget; a legal rule set is "+
			"unbounded CPU on an endpoint a client cannot cancel", elapsed, maxEvaluationBudget)
	}
}
