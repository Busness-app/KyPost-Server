package rules

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// manyRegexRules builds n rules of conditions each, all regex comparators with
// distinct 512-byte patterns — the shape the audit pushed through the real
// POST /api/rules, all accepted.
func manyRegexRules(n, conditions int) []Rule {
	out := make([]Rule, 0, n)
	for i := 0; i < n; i++ {
		group := MatchGroup{Op: "anyof"}
		for j := 0; j < conditions; j++ {
			// Distinct per (rule, condition) and padded to the 512-byte cap
			// validateMatchGroupShape enforces.
			pattern := fmt.Sprintf("r%dc%d", i, j) + strings.Repeat("|zzzz", 100)
			group.Conditions = append(group.Conditions, Condition{
				Field: "subject", Comparator: "regex", Value: pattern,
			})
		}
		out = append(out, Rule{Name: fmt.Sprintf("r%d", i), Enabled: true, Order: i, Match: group})
	}
	return out
}

// TestRegexPatternsAreCompiledOnce is run-8 finding F9.
//
// run-7 F5's remediation had three items — cap Condition.Value, pre-compile the
// leaf regexes, thread a context. 42dea4a shipped only the first. matchesValue
// went on calling regexp.Compile on every evaluation of every condition, so the
// 512-byte cap bounded pattern LENGTH and not recompilation: 30,000 compilations
// per message at 65.2 µs each is 1.96 s, while matching the same already-compiled
// expression 30,000 times costs 60 µs — 0.003% of it.
//
// The second evaluation of the same rule set must therefore be dramatically
// cheaper than the first. A ratio rather than an absolute figure, because the
// absolute is the machine's; 5x is far below the ~30,000x the mechanism gives
// and far above any plausible timing noise.
func TestRegexPatternsAreCompiledOnce(t *testing.T) {
	resetPatternCache()
	rules := manyRegexRules(20, 100)
	input := EvalInput{Subject: "nothing matches this", Folder: "INBOX"}

	start := time.Now()
	Evaluate(context.Background(), input, rules)
	cold := time.Since(start)

	start = time.Now()
	for i := 0; i < 5; i++ {
		Evaluate(context.Background(), input, rules)
	}
	warm := time.Since(start) / 5

	if warm*5 > cold {
		t.Fatalf("warm evaluation (%v) is not materially cheaper than cold (%v); every "+
			"condition is still being recompiled on every message", warm, cold)
	}
}

// The cache is caller-controlled in size — a user may hold thousands of
// distinct patterns and it is process-wide across every account — so it must
// not grow without bound.
func TestPatternCacheIsBounded(t *testing.T) {
	resetPatternCache()
	for i := 0; i < maxCompiledPatterns+100; i++ {
		compilePattern(fmt.Sprintf("pattern-%d", i))
	}
	compiledMu.RLock()
	size := len(compiled)
	compiledMu.RUnlock()
	if size > maxCompiledPatterns {
		t.Fatalf("cache holds %d patterns, past the %d cap", size, maxCompiledPatterns)
	}
}

// An uncompilable pattern must not occupy a slot: failures are cheap to redo,
// and caching them would let invalid input evict valid entries.
func TestUncompilablePatternsAreNotCached(t *testing.T) {
	resetPatternCache()
	if re := compilePattern("([unclosed"); re != nil {
		t.Fatal("an invalid pattern compiled")
	}
	compiledMu.RLock()
	size := len(compiled)
	compiledMu.RUnlock()
	if size != 0 {
		t.Fatalf("an invalid pattern was cached (%d entries)", size)
	}
}

// TestEvaluateStopsOnAContext is the third of run-7 F5's items, still unshipped
// before this. rules.Evaluate took no context and handleRulesRun's scan loop
// never consulted r.Context(), so POST /api/rules/run with limit 500 was 11.5
// minutes of uninterruptible CPU per request — reachable under withMailAuth
// with no rate limit, and the poller's tickSem has capacity 1 instance-wide, so
// every account's polling stretched behind it.
//
// Note the body-path cost is MATCH time, not compile time, so the cache above
// does not subsume this.
func TestEvaluateStopsOnACancelledContext(t *testing.T) {
	resetPatternCache()
	rules := manyRegexRules(50, 200)
	// A body large enough that matching itself is the cost.
	input := EvalInput{Body: strings.Repeat("lorem ipsum dolor sit amet ", 4000), Folder: "INBOX"}
	for i := range rules {
		for j := range rules[i].Match.Conditions {
			rules[i].Match.Conditions[j].Field = "body"
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	outcome := Evaluate(ctx, input, rules)
	elapsed := time.Since(start)

	if len(outcome.Matched) != 0 {
		t.Fatalf("a cancelled evaluation reported %d matches; a rule that was not finished "+
			"being evaluated must not have its actions applied", len(outcome.Matched))
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("a cancelled evaluation still took %v; the scan is uninterruptible", elapsed)
	}
}

// resetPatternCache empties the process-wide cache so a test measures what it
// thinks it measures.
func resetPatternCache() {
	compiledMu.Lock()
	compiled = map[string]*regexp.Regexp{}
	compiledMu.Unlock()
}
