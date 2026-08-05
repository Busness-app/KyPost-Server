package rules

import (
	"regexp"
	"sync"
)

// compiledPatterns caches the regexps matchesValue derives from a rule's
// Comparator and Value.
//
// Compilation, not matching, is what made rule evaluation quadratic in the
// wrong variable. matchesValue called regexp.Compile on every evaluation of
// every condition, so a 512-byte pattern cost 65.2 µs each time; 100 rules ×
// 300 conditions is 30,000 compilations per message, 1.96 s — while matching
// the SAME already-compiled expression 30,000 times costs 60 µs, 0.003% of it.
// run-7 F5's remediation capped Condition.Value at 512 bytes, which bounds
// pattern LENGTH and does nothing about how many times each one is compiled.
//
// Keyed on the finished pattern string, so the two comparators that produce
// different patterns from the same Value ("matches" globs through
// wildcardToRegexp, "regex" verbatim) can share one cache without colliding.
//
// Bounded, because the key space is caller-controlled: a user may hold
// maxRulesPerUser × the per-rule condition cap distinct patterns, and this
// cache is process-wide across every account. Past the cap it is dropped
// wholesale rather than evicted one at a time — an LRU here would cost a
// second data structure and a write lock on the read path to defend against a
// case that only arises under abuse, where re-warming a few thousand entries
// is the correct outcome anyway.
const maxCompiledPatterns = 4096

var (
	compiledMu sync.RWMutex
	compiled   = map[string]*regexp.Regexp{}
)

// compilePattern returns the compiled form of pattern, or nil if it does not
// compile. A pattern that fails to compile is NOT cached: failures are cheap,
// and caching them would let an invalid pattern occupy a slot.
func compilePattern(pattern string) *regexp.Regexp {
	compiledMu.RLock()
	re, ok := compiled[pattern]
	compiledMu.RUnlock()
	if ok {
		return re
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	compiledMu.Lock()
	if len(compiled) >= maxCompiledPatterns {
		compiled = map[string]*regexp.Regexp{}
	}
	compiled[pattern] = re
	compiledMu.Unlock()
	return re
}
