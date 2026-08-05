package rules

import (
	"fmt"
	"strconv"
	"strings"
)

// allowedCapabilities is the fixed set of "require" capability strings
// ParseRuleText (Task 4) accepts. Anything else fails loud (with a line
// number) — KyMail's Sieve subset is hand-rolled precisely so
// unsupported capabilities are never silently ignored.
var allowedCapabilities = map[string]bool{
	"fileinto":   true, // fileinto (RFC 5228 section 4.1)
	"body":       true, // body test (RFC 5173)
	"regex":      true, // :regex match comparator (RFC 3894)
	"imap4flags": true, // addflag/removeflag/hasflag (RFC 5232)
	"kymail":     true, // invented markread/archive/markspam actions
}

// CompileRule renders one Rule as a Sieve-subset script: an optional
// require statement followed by exactly one "if <test> { <actions> }"
// block. Rule metadata (Name/Enabled/Order/Scope) is GUI-only and never
// appears in the script.
func CompileRule(r Rule) (string, error) {
	var caps []string
	if usesCapability(r, "fileinto") {
		caps = append(caps, "fileinto")
	}
	if usesCapability(r, "body") {
		caps = append(caps, "body")
	}
	if usesCapability(r, "regex") {
		caps = append(caps, "regex")
	}
	if usesCapability(r, "imap4flags") {
		caps = append(caps, "imap4flags")
	}
	if usesCapability(r, "kymail") {
		caps = append(caps, "kymail")
	}

	var sb strings.Builder
	if len(caps) > 0 {
		quoted := make([]string, len(caps))
		for i, c := range caps {
			quoted[i] = strconv.Quote(c)
		}
		sb.WriteString("require [" + strings.Join(quoted, ", ") + "];\n\n")
	}

	testSrc, err := compileMatchGroup(r.Match)
	if err != nil {
		return "", err
	}
	sb.WriteString("if " + testSrc + " {\n")
	if len(r.Actions) == 0 {
		sb.WriteString("    keep;\n")
	}
	for _, a := range r.Actions {
		line, err := compileAction(a)
		if err != nil {
			return "", err
		}
		sb.WriteString("    " + line + "\n")
	}
	sb.WriteString("}\n")
	return sb.String(), nil
}

func usesCapability(r Rule, capability string) bool {
	switch capability {
	case "fileinto":
		for _, a := range r.Actions {
			if a.Type == "move" {
				return true
			}
		}
		return false
	case "imap4flags":
		for _, a := range r.Actions {
			if a.Type == "keyword" || a.Type == "unkeyword" {
				return true
			}
		}
		return matchGroupUsesField(r.Match, "keyword")
	case "kymail":
		for _, a := range r.Actions {
			if a.Type == "read" || a.Type == "archive" || a.Type == "spam" {
				return true
			}
		}
		return false
	case "body":
		return matchGroupUsesField(r.Match, "body")
	case "regex":
		return matchGroupUsesComparator(r.Match, "regex")
	default:
		return false
	}
}

func matchGroupUsesField(g MatchGroup, field string) bool {
	for _, c := range g.Conditions {
		if c.Group != nil {
			if matchGroupUsesField(*c.Group, field) {
				return true
			}
			continue
		}
		if strings.EqualFold(c.Field, field) {
			return true
		}
	}
	return false
}

func matchGroupUsesComparator(g MatchGroup, comparator string) bool {
	for _, c := range g.Conditions {
		if c.Group != nil {
			if matchGroupUsesComparator(*c.Group, comparator) {
				return true
			}
			continue
		}
		if c.Comparator == comparator {
			return true
		}
	}
	return false
}

func compileMatchGroup(g MatchGroup) (string, error) {
	op := strings.ToLower(strings.TrimSpace(g.Op))
	if op != "anyof" && op != "allof" {
		op = "allof"
	}
	parts := make([]string, 0, len(g.Conditions))
	for _, c := range g.Conditions {
		part, err := compileCondition(c)
		if err != nil {
			return "", err
		}
		parts = append(parts, part)
	}
	return op + "(" + strings.Join(parts, ", ") + ")", nil
}

func compileCondition(c Condition) (string, error) {
	var inner string
	var err error
	if c.Group != nil {
		inner, err = compileMatchGroup(*c.Group)
	} else {
		inner, err = compileLeafCondition(c)
	}
	if err != nil {
		return "", err
	}
	if c.Negate {
		return "not " + inner, nil
	}
	return inner, nil
}

func compileLeafCondition(c Condition) (string, error) {
	field := strings.ToLower(strings.TrimSpace(c.Field))
	switch field {
	case "from", "to", "cc", "bcc", "subject":
		if strings.EqualFold(c.Comparator, "exists") {
			return fmt.Sprintf("exists [%s]", strconv.Quote(field)), nil
		}
		return fmt.Sprintf("header :%s [%s] %s", comparatorTag(c.Comparator), strconv.Quote(field), strconv.Quote(c.Value)), nil
	case "body":
		return fmt.Sprintf("body :%s %s", comparatorTag(c.Comparator), strconv.Quote(c.Value)), nil
	case "keyword":
		return fmt.Sprintf("hasflag :%s %s", comparatorTag(c.Comparator), strconv.Quote(c.Value)), nil
	default:
		return "", fmt.Errorf("unsupported condition field %q", c.Field)
	}
}

func comparatorTag(comparator string) string {
	switch strings.ToLower(strings.TrimSpace(comparator)) {
	case "contains", "is", "matches", "regex":
		return strings.ToLower(comparator)
	default:
		return "is"
	}
}

func compileAction(a Action) (string, error) {
	switch a.Type {
	case "keyword":
		return fmt.Sprintf("addflag %s;", strconv.Quote(a.Value)), nil
	case "unkeyword":
		return fmt.Sprintf("removeflag %s;", strconv.Quote(a.Value)), nil
	case "move":
		return fmt.Sprintf("fileinto %s;", strconv.Quote(a.Value)), nil
	case "read":
		return "markread;", nil
	case "archive":
		return "archive;", nil
	case "spam":
		return "markspam;", nil
	case "delete":
		return "discard;", nil
	case "stop":
		return "stop;", nil
	default:
		return "", fmt.Errorf("unsupported action type %q", a.Type)
	}
}

// ---- Parser ----

// ParseRuleText hand-parses a Sieve-subset script (see CompileRule for the
// exact construct set understood) and returns existing with Match/Actions
// replaced — every other field (Name/Enabled/Order/Scope/ID/Rev/...) passes
// through untouched. Errors report a 1-based line number.
func ParseRuleText(text string, existing Rule) (Rule, error) {
	toks, err := lexSieve(text)
	if err != nil {
		return Rule{}, err
	}
	p := &sieveParser{toks: toks}

	for p.peek().kind == tokWord && strings.EqualFold(p.peek().text, "require") {
		reqTok := p.next()
		caps, err := p.parseStringList()
		if err != nil {
			return Rule{}, err
		}
		if err := p.expectSemicolon(); err != nil {
			return Rule{}, err
		}
		for _, c := range caps {
			key := strings.ToLower(strings.TrimSpace(c))
			if !allowedCapabilities[key] {
				return Rule{}, fmt.Errorf("line %d: unsupported require capability %q", reqTok.line, c)
			}
		}
	}

	if err := p.expectWord("if"); err != nil {
		return Rule{}, err
	}
	rootCond, err := p.parseTest()
	if err != nil {
		return Rule{}, err
	}
	if _, err := p.expect(tokLBrace, "{"); err != nil {
		return Rule{}, err
	}
	var actions []Action
	for p.peek().kind != tokRBrace {
		if p.peek().kind == tokEOF {
			return Rule{}, fmt.Errorf("line %d: unbalanced braces, missing }", p.peek().line)
		}
		a, err := p.parseAction()
		if err != nil {
			return Rule{}, err
		}
		if a.Type != "keep" {
			actions = append(actions, a)
		}
	}
	if _, err := p.expect(tokRBrace, "}"); err != nil {
		return Rule{}, err
	}
	if p.peek().kind != tokEOF {
		return Rule{}, fmt.Errorf("line %d: unexpected content after rule block", p.peek().line)
	}

	var match MatchGroup
	if rootCond.Group != nil {
		match = *rootCond.Group
	} else {
		match = MatchGroup{Op: "allof", Conditions: []Condition{rootCond}}
	}

	result := existing
	result.Match = match
	result.Actions = actions
	return result, nil
}

// maxTestNestingDepth bounds how many nested not/allof/anyof levels
// parseTest will descend before rejecting the script. Without this bound, a
// pathological script like allof(allof(allof(...))) nested ~1 MiB worth of
// parens (the only existing limit is the request-body io.LimitReader in
// rules_handlers.go) would drive parser recursion into the hundreds of
// thousands of stack frames — and, once such a rule parsed successfully and
// was stored, engine.go's matchGroup/conditionMatches mutual recursion would
// re-walk that same deep tree on every message the poller evaluates, forever.
// 32 is generous headroom past anything a human-written or GUI-round-tripped
// (which is always exactly one flat level) Sieve rule would ever need.
const maxTestNestingDepth = 32

// maxMatchConditions bounds the total number of leaf Conditions a Match tree
// may contain, independent of nesting depth: a single flat group with
// thousands of sibling conditions sails through the depth check above
// untouched (depth 1, no nesting at all) while still costing real CPU time
// on every poller tick for every message. Measured directly: 8,000
// conditions took ~71ms to evaluate against one message (~8.9µs/condition).
// 300 keeps a single rule's worst-case per-message cost under a few
// milliseconds — several orders of magnitude past anything a human-composed
// or GUI-round-tripped rule (realistically well under 20 conditions) would
// ever need.
//
// That ~8.9µs/condition figure is the `contains` comparator, and it is only
// true while a condition's COST is bounded too — see maxConditionValueBytes.
const maxMatchConditions = 300

// maxConditionValueBytes bounds a single leaf condition's Value.
//
// maxMatchConditions bounds how MANY conditions run; this bounds what each one
// costs. Without it the pair did not bound anything: the `matches` and `regex`
// comparators compile Value as a regular expression on every evaluation of every
// condition (engine.matchesValue), and Value was unbounded below the handler's
// 1 MiB body limit. A 3,200-byte alternation, 300 of them per rule, 100 rules —
// all within the counts above — measured at 37 SECONDS per message, against a
// documented budget of "a few milliseconds". Rule evaluation is not
// context-cancellable and runs inside the capacity-1 instance-wide poll
// semaphore, so that is every account's mail polling stalled by one user.
//
// 512 matches maxActionValueBytes and is far past any real pattern; the GUI's
// longest round-tripped value is a folder name.
const maxConditionValueBytes = 512

// ValidateMatchShape walks m (and any nested Condition.Group) and rejects it
// once its nesting depth exceeds maxTestNestingDepth or its total leaf-
// condition count exceeds maxMatchConditions, in one combined traversal —
// the depth bound is the exact same one sieveParser.enterTest/exitTest
// enforces while parsing a Sieve script; the condition-count bound has no
// script-parser equivalent since ParseRuleText's own token stream is what
// naturally limits how many conditions a hand-written script can contain
// within the request-body size limit, but the JSON path below has no such
// natural limit.
//
// This exists because ParseRuleText (the Sieve-script path) isn't the only
// way a Match tree reaches the store: rules_handlers.go's POST /api/rules and
// PUT /api/rules/{id} decode a MatchGroup straight from JSON and hand it to
// store.Upsert with no shape validation at all. Without this check, an
// authenticated caller could persist an arbitrarily deep or arbitrarily wide
// Match tree via those two endpoints (bounded only by the request-body size
// limit and Go's encoding/json nesting cap of 10000) that engine.go's
// evaluator would then walk on every poller tick forever — reproducing,
// via the JSON path, the exact resource-exhaustion issue the Sieve-parser
// depth check was added to close. Both entry points must share this one
// constant/function rather than each guessing their own limit.
func ValidateMatchShape(m MatchGroup) error {
	count := 0
	return validateMatchGroupShape(m, 1, &count)
}

func validateMatchGroupShape(m MatchGroup, depth int, count *int) error {
	if depth > maxTestNestingDepth {
		return fmt.Errorf("match nesting exceeds maximum depth of %d", maxTestNestingDepth)
	}
	for _, c := range m.Conditions {
		// Every node counts, group or leaf.
		//
		// Only leaves used to, which did NOT bypass the 300-condition cap —
		// count is a shared pointer across the recursion, so 400 leaves spread
		// over two groups are still rejected. What it left unbounded was the
		// group nodes themselves: a tree of nothing but empty groups, each with
		// its own Op string, passes a leaf count of zero at any width. Measured
		// at 24.2 ms/message, 1/57th of the in-cap leaf path, so this is a
		// storage bound rather than a CPU one — but it is one an account can
		// grow without limit inside a file the rules store rewrites whole.
		*count++
		if *count > maxMatchConditions {
			return fmt.Errorf("match has more than %d total conditions", maxMatchConditions)
		}
		if c.Group != nil {
			if err := validateMatchGroupShape(*c.Group, depth+1, count); err != nil {
				return err
			}
			continue
		}
		if len(c.Value) > maxConditionValueBytes {
			return fmt.Errorf("match condition value exceeds maximum length of %d bytes", maxConditionValueBytes)
		}
		// Source length bounds neither validity nor compiled size. Compile the
		// pattern here so an invalid or pathologically-expanding regex is
		// refused at write time, where the user can still fix it, instead of at
		// evaluation time where the only available answer is "no match" — which
		// Negate then inverts into "matches every message".
		if err := ValidatePattern(c.Comparator, c.Value); err != nil {
			return err
		}
	}
	return nil
}

type sieveParser struct {
	toks  []token
	pos   int
	depth int // current not/allof/anyof nesting depth, see maxTestNestingDepth
}

// enterTest records one more level of not/allof/anyof nesting and rejects
// the script once maxTestNestingDepth is exceeded. Pair with `defer
// p.exitTest()` at the call site so sibling tests (not just deeper ones)
// correctly see the depth restored once a nested group finishes parsing.
func (p *sieveParser) enterTest(line int) error {
	p.depth++
	if p.depth > maxTestNestingDepth {
		return fmt.Errorf("line %d: test nesting exceeds maximum depth of %d", line, maxTestNestingDepth)
	}
	return nil
}

func (p *sieveParser) exitTest() {
	p.depth--
}

func (p *sieveParser) peek() token { return p.toks[p.pos] }

func (p *sieveParser) next() token {
	t := p.toks[p.pos]
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}

func (p *sieveParser) expect(kind tokKind, what string) (token, error) {
	t := p.peek()
	if t.kind != kind {
		return token{}, fmt.Errorf("line %d: expected %s, got %q", t.line, what, tokenDisplay(t))
	}
	return p.next(), nil
}

func (p *sieveParser) expectWord(word string) error {
	t := p.peek()
	if t.kind != tokWord || !strings.EqualFold(t.text, word) {
		return fmt.Errorf("line %d: expected %q, got %q", t.line, word, tokenDisplay(t))
	}
	p.next()
	return nil
}

func (p *sieveParser) expectSemicolon() error {
	_, err := p.expect(tokSemicolon, ";")
	return err
}

func tokenDisplay(t token) string {
	if t.kind == tokEOF {
		return "end of input"
	}
	return t.text
}

func (p *sieveParser) parseStringList() ([]string, error) {
	if _, err := p.expect(tokLBracket, "["); err != nil {
		return nil, err
	}
	var out []string
	for p.peek().kind != tokRBracket {
		s, err := p.expect(tokString, "string")
		if err != nil {
			return nil, err
		}
		out = append(out, s.text)
		if p.peek().kind == tokComma {
			p.next()
			continue
		}
		break
	}
	if _, err := p.expect(tokRBracket, "]"); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeField(f string) string {
	return strings.ToLower(strings.TrimSpace(f))
}

// validHeaderAddressFields is the exact set of field names compileLeafCondition
// treats as header/address fields (its "from", "to", "cc", "bcc", "subject"
// case). "body" and "keyword" are deliberately excluded: compileLeafCondition
// special-cases those two into a completely different Sieve test (body /
// hasflag), so a header/address or exists test naming them would silently
// compile to the wrong test with no error. See sieve.go:166-181
// (compileLeafCondition). Used by both the header/address branch and the
// exists branch of parseTest, since both go through fieldsToCondition and
// are subject to the identical compileLeafCondition re-dispatch hazard.
var validHeaderAddressFields = map[string]bool{
	"from":    true,
	"to":      true,
	"cc":      true,
	"bcc":     true,
	"subject": true,
}

func (p *sieveParser) parseComparatorTag(defaultComparator string) (string, error) {
	if p.peek().kind != tokColonTag {
		return defaultComparator, nil
	}
	tag := p.next()
	switch strings.ToLower(tag.text) {
	case "contains":
		return "contains", nil
	case "is":
		return "is", nil
	case "matches":
		return "matches", nil
	case "regex":
		return "regex", nil
	default:
		return "", fmt.Errorf("line %d: unsupported comparator tag :%s", tag.line, tag.text)
	}
}

func (p *sieveParser) parseTest() (Condition, error) {
	t := p.peek()
	if t.kind != tokWord {
		return Condition{}, fmt.Errorf("line %d: expected a test, got %q", t.line, tokenDisplay(t))
	}
	switch {
	case strings.EqualFold(t.text, "not"):
		p.next()
		if err := p.enterTest(t.line); err != nil {
			return Condition{}, err
		}
		defer p.exitTest()
		inner, err := p.parseTest()
		if err != nil {
			return Condition{}, err
		}
		inner.Negate = !inner.Negate
		return inner, nil

	case strings.EqualFold(t.text, "allof") || strings.EqualFold(t.text, "anyof"):
		op := strings.ToLower(t.text)
		p.next()
		if err := p.enterTest(t.line); err != nil {
			return Condition{}, err
		}
		defer p.exitTest()
		if _, err := p.expect(tokLParen, "("); err != nil {
			return Condition{}, err
		}
		var conds []Condition
		for {
			c, err := p.parseTest()
			if err != nil {
				return Condition{}, err
			}
			conds = append(conds, c)
			if p.peek().kind == tokComma {
				p.next()
				continue
			}
			break
		}
		if _, err := p.expect(tokRParen, ")"); err != nil {
			return Condition{}, err
		}
		group := MatchGroup{Op: op, Conditions: conds}
		return Condition{Group: &group}, nil

	case strings.EqualFold(t.text, "header") || strings.EqualFold(t.text, "address"):
		p.next()
		comparator, err := p.parseComparatorTag("is")
		if err != nil {
			return Condition{}, err
		}
		fields, err := p.parseStringList()
		if err != nil {
			return Condition{}, err
		}
		valueTok, err := p.expect(tokString, "string value")
		if err != nil {
			return Condition{}, err
		}
		if len(fields) == 0 {
			return Condition{}, fmt.Errorf("line %d: header/address test requires at least one field", t.line)
		}
		for _, f := range fields {
			if !validHeaderAddressFields[normalizeField(f)] {
				return Condition{}, fmt.Errorf("line %d: unsupported header/address field %q", t.line, f)
			}
		}
		return fieldsToCondition(fields, comparator, valueTok.text), nil

	case strings.EqualFold(t.text, "exists"):
		p.next()
		fields, err := p.parseStringList()
		if err != nil {
			return Condition{}, err
		}
		if len(fields) == 0 {
			return Condition{}, fmt.Errorf("line %d: exists test requires at least one field", t.line)
		}
		for _, f := range fields {
			if !validHeaderAddressFields[normalizeField(f)] {
				return Condition{}, fmt.Errorf("line %d: unsupported exists field %q", t.line, f)
			}
		}
		return fieldsToCondition(fields, "exists", ""), nil

	case strings.EqualFold(t.text, "body"):
		p.next()
		comparator, err := p.parseComparatorTag("contains")
		if err != nil {
			return Condition{}, err
		}
		valueTok, err := p.expect(tokString, "string value")
		if err != nil {
			return Condition{}, err
		}
		return Condition{Field: "body", Comparator: comparator, Value: valueTok.text}, nil

	case strings.EqualFold(t.text, "hasflag"):
		p.next()
		comparator, err := p.parseComparatorTag("is")
		if err != nil {
			return Condition{}, err
		}
		valueTok, err := p.expect(tokString, "string value")
		if err != nil {
			return Condition{}, err
		}
		return Condition{Field: "keyword", Comparator: comparator, Value: valueTok.text}, nil

	default:
		return Condition{}, fmt.Errorf("line %d: unknown test %q", t.line, t.text)
	}
}

// fieldsToCondition builds a single leaf Condition for a one-item field
// list, or a nested anyof MatchGroup (one Condition per field) for a
// multi-item list — matching Sieve's "true if any listed header matches"
// semantics for header/address/exists tests with more than one field.
func fieldsToCondition(fields []string, comparator, value string) Condition {
	if len(fields) == 1 {
		return Condition{Field: normalizeField(fields[0]), Comparator: comparator, Value: value}
	}
	conds := make([]Condition, 0, len(fields))
	for _, f := range fields {
		conds = append(conds, Condition{Field: normalizeField(f), Comparator: comparator, Value: value})
	}
	group := MatchGroup{Op: "anyof", Conditions: conds}
	return Condition{Group: &group}
}

func (p *sieveParser) parseAction() (Action, error) {
	t := p.peek()
	if t.kind != tokWord {
		return Action{}, fmt.Errorf("line %d: expected an action, got %q", t.line, tokenDisplay(t))
	}
	name := strings.ToLower(t.text)
	p.next()
	switch name {
	case "fileinto":
		v, err := p.expect(tokString, "folder string")
		if err != nil {
			return Action{}, err
		}
		if err := p.expectSemicolon(); err != nil {
			return Action{}, err
		}
		return Action{Type: "move", Value: v.text}, nil
	case "discard":
		if err := p.expectSemicolon(); err != nil {
			return Action{}, err
		}
		return Action{Type: "delete"}, nil
	case "keep":
		if err := p.expectSemicolon(); err != nil {
			return Action{}, err
		}
		return Action{Type: "keep"}, nil
	case "stop":
		if err := p.expectSemicolon(); err != nil {
			return Action{}, err
		}
		return Action{Type: "stop"}, nil
	case "addflag":
		v, err := p.expect(tokString, "keyword string")
		if err != nil {
			return Action{}, err
		}
		if err := p.expectSemicolon(); err != nil {
			return Action{}, err
		}
		return Action{Type: "keyword", Value: v.text}, nil
	case "removeflag":
		v, err := p.expect(tokString, "keyword string")
		if err != nil {
			return Action{}, err
		}
		if err := p.expectSemicolon(); err != nil {
			return Action{}, err
		}
		return Action{Type: "unkeyword", Value: v.text}, nil
	case "markread":
		if err := p.expectSemicolon(); err != nil {
			return Action{}, err
		}
		return Action{Type: "read"}, nil
	case "archive":
		if err := p.expectSemicolon(); err != nil {
			return Action{}, err
		}
		return Action{Type: "archive"}, nil
	case "markspam":
		if err := p.expectSemicolon(); err != nil {
			return Action{}, err
		}
		return Action{Type: "spam"}, nil
	default:
		return Action{}, fmt.Errorf("line %d: unknown action %q", t.line, name)
	}
}

// ---- Lexer ----

type tokKind int

const (
	tokWord tokKind = iota
	tokString
	tokLBracket
	tokRBracket
	tokLParen
	tokRParen
	tokLBrace
	tokRBrace
	tokSemicolon
	tokComma
	tokColonTag
	tokEOF
)

type token struct {
	kind tokKind
	text string
	line int
}

type sieveLexer struct {
	src  []rune
	pos  int
	line int
}

func lexSieve(text string) ([]token, error) {
	l := &sieveLexer{src: []rune(text), line: 1}
	var out []token
	for {
		if err := l.skipWhitespaceAndComments(); err != nil {
			return nil, err
		}
		r, ok := l.peekRune()
		if !ok {
			out = append(out, token{kind: tokEOF, line: l.line})
			return out, nil
		}
		line := l.line
		switch {
		case r == '[':
			l.advance()
			out = append(out, token{kind: tokLBracket, text: "[", line: line})
		case r == ']':
			l.advance()
			out = append(out, token{kind: tokRBracket, text: "]", line: line})
		case r == '(':
			l.advance()
			out = append(out, token{kind: tokLParen, text: "(", line: line})
		case r == ')':
			l.advance()
			out = append(out, token{kind: tokRParen, text: ")", line: line})
		case r == '{':
			l.advance()
			out = append(out, token{kind: tokLBrace, text: "{", line: line})
		case r == '}':
			l.advance()
			out = append(out, token{kind: tokRBrace, text: "}", line: line})
		case r == ';':
			l.advance()
			out = append(out, token{kind: tokSemicolon, text: ";", line: line})
		case r == ',':
			l.advance()
			out = append(out, token{kind: tokComma, text: ",", line: line})
		case r == '"':
			l.advance()
			var sb strings.Builder
			closed := false
			for {
				c, ok := l.advance()
				if !ok {
					break
				}
				if c == '"' {
					closed = true
					break
				}
				if c == '\\' {
					if c2, ok2 := l.advance(); ok2 {
						sb.WriteRune(c2)
					}
					continue
				}
				sb.WriteRune(c)
			}
			if !closed {
				return nil, fmt.Errorf("line %d: unterminated string literal", line)
			}
			out = append(out, token{kind: tokString, text: sb.String(), line: line})
		case r == ':':
			l.advance()
			var sb strings.Builder
			for {
				c, ok := l.peekRune()
				if !ok || !isWordRune(c) {
					break
				}
				sb.WriteRune(c)
				l.advance()
			}
			out = append(out, token{kind: tokColonTag, text: sb.String(), line: line})
		default:
			if !isWordRune(r) {
				return nil, fmt.Errorf("line %d: unexpected character %q", line, string(r))
			}
			var sb strings.Builder
			for {
				c, ok := l.peekRune()
				if !ok || !isWordRune(c) {
					break
				}
				sb.WriteRune(c)
				l.advance()
			}
			out = append(out, token{kind: tokWord, text: sb.String(), line: line})
		}
	}
}

func (l *sieveLexer) peekRune() (rune, bool) {
	if l.pos >= len(l.src) {
		return 0, false
	}
	return l.src[l.pos], true
}

func (l *sieveLexer) advance() (rune, bool) {
	r, ok := l.peekRune()
	if !ok {
		return 0, false
	}
	l.pos++
	if r == '\n' {
		l.line++
	}
	return r, true
}

func (l *sieveLexer) skipWhitespaceAndComments() error {
	for {
		r, ok := l.peekRune()
		if !ok {
			return nil
		}
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			l.advance()
			continue
		}
		if r == '#' {
			for {
				c, ok := l.advance()
				if !ok || c == '\n' {
					break
				}
			}
			continue
		}
		if r == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*' {
			startLine := l.line
			l.advance()
			l.advance()
			closed := false
			for {
				c, ok := l.advance()
				if !ok {
					break
				}
				if c == '*' {
					if r2, ok2 := l.peekRune(); ok2 && r2 == '/' {
						l.advance()
						closed = true
						break
					}
				}
			}
			if !closed {
				return fmt.Errorf("line %d: unterminated block comment", startLine)
			}
			continue
		}
		return nil
	}
}

func isWordRune(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}
