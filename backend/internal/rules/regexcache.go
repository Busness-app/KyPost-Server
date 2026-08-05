package rules

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
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

// maxPatternProgramInsts bounds a pattern's COMPILED size, which is the
// quantity that actually costs memory and which nothing else bounds.
//
// maxCompiledPatterns is an entry count and maxConditionValueBytes is a SOURCE
// length; neither constrains how large a pattern compiles to. Go's regexp does
// not backtrack, so a bounded repeat is expanded: `(?:<494 chars>){1000}`, 504
// bytes and comfortably inside the source cap, compiles to a program of tens of
// megabytes. 300 of those — one rule at the condition cap — pins gigabytes in
// the process-global cache below, and 300 is far under 4096 so the wholesale
// flush never fires.
//
// The instruction count is the right proxy because it is what regexp/syntax
// actually allocates. re.String() would not work: it returns the SOURCE
// pattern, precisely the quantity that hides the blowup.
//
// 8192 leaves an enormous margin over realistic patterns (an alternation of a
// dozen alternatives with bounded repeats is low hundreds) while refusing the
// pathological expansions by three orders of magnitude.
const maxPatternProgramInsts = 8192

var (
	compiledMu sync.RWMutex
	compiled   = map[string]*regexp.Regexp{}
)

// patternFor returns the regexp source matchesValue evaluates for a given
// comparator and value, and whether that comparator uses a regexp at all.
//
// Single source of truth on purpose: validation must check the SAME string
// evaluation will compile, or a pattern could pass the gate and still blow up
// at match time.
func patternFor(comparator, value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(comparator)) {
	case "matches":
		return "(?is)^" + wildcardToRegexp(value) + "$", true
	case "regex":
		return "(?is)" + value, true
	default:
		return "", false
	}
}

// ValidatePattern reports why a comparator/value pair is unusable, or nil.
//
// Called from rule validation so both defects are refused at WRITE time rather
// than surfacing at evaluation:
//
//   - an uncompilable pattern, which compilePattern can only report as nil, and
//     which conditionMatches would otherwise invert into "matches everything"
//     under Negate;
//   - a pattern whose compiled program is disproportionate to its source.
//
// Rejecting the oversized case here rather than merely declining to cache it is
// deliberate: an uncached pattern is recompiled on every evaluation of every
// message, which trades a memory exhaustion for a CPU one.
func ValidatePattern(comparator, value string) error {
	pattern, ok := patternFor(comparator, value)
	if !ok {
		return nil
	}
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return fmt.Errorf("match condition value is not a valid regular expression: %w", err)
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return fmt.Errorf("match condition value is not a valid regular expression: %w", err)
	}
	if len(prog.Inst) > maxPatternProgramInsts {
		return fmt.Errorf("match condition value expands to %d regular-expression instructions, "+
			"exceeding the maximum of %d", len(prog.Inst), maxPatternProgramInsts)
	}
	return nil
}

// compilePattern returns the compiled form of pattern, or nil if it does not
// compile or is disproportionately large. A pattern that fails is NOT cached:
// failures are cheap, and caching them would let an invalid pattern occupy a
// slot.
//
// The size check is duplicated from ValidatePattern rather than trusted from it
// because rules reach the engine from disk as well as from the handlers, and a
// rules.json written by an older build (or by hand) has passed no gate at all.
func compilePattern(pattern string) *regexp.Regexp {
	compiledMu.RLock()
	re, ok := compiled[pattern]
	compiledMu.RUnlock()
	if ok {
		return re
	}

	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil || len(prog.Inst) > maxPatternProgramInsts {
		return nil
	}

	re, err = regexp.Compile(pattern)
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
