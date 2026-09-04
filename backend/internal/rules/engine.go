package rules

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	imapadapter "github.com/Busness-app/kypost-server/backend/internal/adapters/imap"
)

// EvalInput is the message data a rule's Match tree is evaluated against.
// Body is only ever populated by callers that already fetched it (the
// poller always has it; the manual "run rules now" endpoint fetches it only
// when at least one enabled rule has a body-field condition).
type EvalInput struct {
	UID       int
	MessageID string
	From      string
	To        string
	CC        string
	BCC       string
	Subject   string
	Body      string
	Keywords  []string
	Folder    string
}

// Outcome is the result of evaluating a set of rules against one message.
// Matched holds the Name of every rule that matched (in evaluation order);
// Applied is the flattened, ordered list of actions from every matched rule
// (including any "stop" action, for ApplyOutcome/logging purposes — stop
// carries out no client call); Stopped reports whether a matched rule's
// actions included "stop", which halts the walk over remaining rules.
type Outcome struct {
	Matched []string
	Applied []Action
	Stopped bool
}

// ActionResult is the per-action outcome of ApplyOutcome, for callers that
// want to report partial failures (a folder that doesn't exist, etc).
type ActionResult struct {
	Action Action
	Err    error
}

// Evaluate walks activeRules in Order, skipping disabled rules and rules
// out of Scope for input.Folder. It is pure — no IMAP calls — so it can be
// unit tested without a fake mail client. A matched rule's "stop" action
// halts the walk entirely, mirroring Sieve's script-global stop;.
//
// ctx is checked between rules, and inside a rule's condition walk. Rule
// evaluation is unbounded CPU that a caller chooses the size of: 100 rules of
// 300 regex conditions each, measured against a 100 KiB body, cost 95 s PER
// MESSAGE, and POST /api/rules/run takes limit up to 500. Without a context
// that is 11.5 minutes of work the server keeps doing after the client has
// gone, on a host whose other job is running an LLM. Caching the compiled
// patterns removes the compile cost but not the match cost, so cancellation is
// a separate requirement, not a belt-and-braces addition.
//
// A cancelled walk returns whatever it had matched so far. Callers must treat
// that as incomplete — see handleRulesRun, which stops the scan rather than
// applying a partial outcome.
func Evaluate(ctx context.Context, input EvalInput, activeRules []Rule) Outcome {
	// Bound evaluation's own cost.
	//
	// ctx is threaded all the way down, but the only thing that cancels it on
	// the request path is the client going away — and an attacker holds the
	// connection open. The structural caps (maxRulesPerUser, maxMatchConditions,
	// maxConditionValueBytes) bound a match tree's SHAPE and say nothing about
	// what it costs to evaluate: the ~8.9us/condition budget they were chosen
	// against is documented in sieve.go as being for the `contains` comparator,
	// while a legal regex alternation is orders of magnitude dearer.
	//
	// A caller that already imposed a tighter deadline keeps it; this only adds
	// a ceiling where there was none.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, maxEvaluationBudget)
		defer cancel()
	}

	sorted := make([]Rule, len(activeRules))
	copy(sorted, activeRules)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Order < sorted[j].Order })

	var outcome Outcome
	for _, r := range sorted {
		if ctx.Err() != nil {
			return outcome
		}
		if !r.Enabled {
			continue
		}
		if !folderInScope(r.Scope, input.Folder) {
			continue
		}
		if !matchGroup(ctx, r.Match, input) {
			continue
		}
		outcome.Matched = append(outcome.Matched, r.Name)
		outcome.Applied = append(outcome.Applied, r.Actions...)
		for _, a := range r.Actions {
			if a.Type == "stop" {
				outcome.Stopped = true
			}
		}
		if outcome.Stopped {
			break
		}
	}
	return outcome
}

// ApplyOutcome runs outcome.Applied against c, in order, mapping each
// action to the matching imapadapter.Client call:
//
//	keyword    -> c.ApplyLabel
//	unkeyword  -> c.RemoveLabel
//	move       -> c.ApplyInboxAction(..., "move", mailbox, action.Value)
//	read       -> c.ApplyInboxAction(..., "read", mailbox, "")
//	archive    -> c.ApplyInboxAction(..., "archive", mailbox, "")
//	spam       -> c.ApplyInboxAction(..., "spam", mailbox, "")
//	delete     -> c.ApplyInboxAction(..., "delete", mailbox, "")
//	stop       -> pure control flow, no call
//
// Execution STOPS at the first failed action, and at a cancelled or expired
// ctx. Callers inspect the returned []ActionResult, which therefore ends at
// the failure: everything before it ran, nothing after it did.
//
// It used to run the whole list regardless, on the reasoning that a caller
// could report the partial failure. The caller that matters — the poller —
// responds by leaving the message for a later tick, and a later tick can only
// find it with an UNSEEN SEARCH over INBOX. So "keyword fails, archive
// succeeds" left the message archived, the keyword unwritten, and no tick that
// would ever look at it again: the retry the failure was reported for could not
// happen. Stopping here, plus ValidateRule requiring the one
// visibility-changing action last, keeps every failure retryable.
func ApplyOutcome(ctx context.Context, c imapadapter.Client, mailbox string, input EvalInput, outcome Outcome) []ActionResult {
	messageID := input.MessageID
	results := make([]ActionResult, 0, len(outcome.Applied))
	for _, action := range outcome.Applied {
		// A cancelled context fails every remaining call anyway; recording it
		// once and stopping keeps the tick from spending its shutdown on a list
		// of identical errors.
		if cerr := ctx.Err(); cerr != nil {
			results = append(results, ActionResult{Action: action, Err: cerr})
			return results
		}
		var err error
		switch action.Type {
		case "keyword":
			err = c.ApplyLabel(ctx, messageID, action.Value)
		case "unkeyword":
			err = c.RemoveLabel(ctx, messageID, action.Value)
		case "move":
			err = c.ApplyInboxAction(ctx, messageID, "move", mailbox, action.Value)
		case "read":
			err = c.ApplyInboxAction(ctx, messageID, "read", mailbox, "")
		case "archive":
			err = c.ApplyInboxAction(ctx, messageID, "archive", mailbox, "")
		case "spam":
			err = c.ApplyInboxAction(ctx, messageID, "spam", mailbox, "")
		case "delete":
			err = c.ApplyInboxAction(ctx, messageID, "delete", mailbox, "")
		case "stop":
			// pure control flow, no call.
		default:
			err = fmt.Errorf("unsupported action type %q", action.Type)
		}
		results = append(results, ActionResult{Action: action, Err: err})
		if err != nil {
			return results
		}
	}
	return results
}

func folderInScope(scope RuleScope, folder string) bool {
	if len(scope.Folders) == 0 {
		return true
	}
	for _, f := range scope.Folders {
		if strings.EqualFold(strings.TrimSpace(f), strings.TrimSpace(folder)) {
			return true
		}
	}
	return false
}

// matchGroup evaluates one group. A cancelled ctx makes it report NO match,
// whatever the op: a group that has not finished being evaluated has not
// matched, and returning true there would apply a rule's actions on the
// strength of a timeout.
func matchGroup(ctx context.Context, g MatchGroup, input EvalInput) bool {
	op := strings.ToLower(strings.TrimSpace(g.Op))
	if op == "anyof" {
		for _, c := range g.Conditions {
			if ctx.Err() != nil {
				return false
			}
			if conditionMatches(ctx, c, input) {
				return true
			}
		}
		return false
	}
	// "allof" (and any unrecognized/empty Op) is AND semantics; vacuously
	// true over zero conditions, matching boolean-algebra convention.
	for _, c := range g.Conditions {
		if ctx.Err() != nil {
			return false
		}
		if !conditionMatches(ctx, c, input) {
			return false
		}
	}
	return true
}

func conditionMatches(ctx context.Context, c Condition, input EvalInput) bool {
	var result bool
	// evaluable distinguishes "this condition was evaluated and did not match"
	// from "this condition could not be evaluated at all". Collapsing the two
	// into false is what let a mistyped regex become a rule that fires on every
	// message: compilePattern returns nil, matchesValue reported false, and
	// Negate inverted it to true. An unevaluable condition must not match in
	// either direction.
	evaluable := true
	if c.Group != nil {
		result = matchGroup(ctx, *c.Group, input)
	} else if strings.EqualFold(strings.TrimSpace(c.Field), "keyword") {
		result = false
		for _, kw := range input.Keywords {
			matched, ok := matchesValue(c.Comparator, kw, c.Value)
			if !ok {
				evaluable = false
				break
			}
			if matched {
				result = true
				break
			}
		}
	} else {
		result, evaluable = matchesValue(c.Comparator, fieldValue(input, c.Field), c.Value)
	}
	if !evaluable {
		return false
	}
	if c.Negate {
		return !result
	}
	return result
}

func fieldValue(input EvalInput, field string) string {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "from":
		return input.From
	case "to":
		return input.To
	case "cc":
		return input.CC
	case "bcc":
		return input.BCC
	case "subject":
		return input.Subject
	case "body":
		return input.Body
	default:
		return ""
	}
}

// matchesValue reports whether candidate matches value under comparator, and
// whether the condition could be evaluated at all.
//
// The second return exists because a pattern that does not compile (or that
// expands past maxPatternProgramInsts) has no truth value. Reporting it as
// "false" let conditionMatches's Negate branch invert it into "matches every
// message" — see TestUncompilableRegexUnderNegateDoesNotMatchEverything.
//
// Rules are validated on write and on load, so an unevaluable pattern should be
// unreachable here; this is the backstop for a rules.json that predates the
// validation or was edited by hand.
func matchesValue(comparator, candidate, value string) (matched bool, evaluable bool) {
	switch strings.ToLower(strings.TrimSpace(comparator)) {
	case "exists":
		return strings.TrimSpace(candidate) != "", true
	case "is":
		return strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(value)), true
	case "matches", "regex":
		pattern, _ := patternFor(comparator, value)
		re := compilePattern(pattern)
		if re == nil {
			return false, false
		}
		return re.MatchString(candidate), true
	case "contains":
		fallthrough
	default:
		return strings.Contains(strings.ToLower(candidate), strings.ToLower(value)), true
	}
}

// wildcardToRegexp converts a Sieve :matches-style glob (* = any run of
// characters, ? = exactly one character) into an equivalent regexp,
// escaping every other regexp metacharacter literally.
func wildcardToRegexp(pattern string) string {
	var sb strings.Builder
	for _, r := range pattern {
		switch r {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteString(".")
		default:
			sb.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return sb.String()
}

// maxEvaluationBudget is the wall-clock ceiling on one Evaluate call.
//
// Generous relative to any legitimate rule set — an ordinary configuration
// finishes in single-digit milliseconds — so this is a backstop against a
// pathological one, not a limit users will meet. A cancelled walk returns
// whatever it matched so far, and callers already treat that as incomplete
// (see handleRulesRun, which stops the scan rather than applying a partial
// outcome).
//
// A var, not a const, so tests can lower it; production never reassigns it.
var maxEvaluationBudget = 5 * time.Second
