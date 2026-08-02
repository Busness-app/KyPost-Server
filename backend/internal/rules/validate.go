package rules

import (
	"fmt"
	"strings"
)

// maxActionsPerRule bounds how many actions one rule may carry.
//
// Every action is one IMAP round trip, run per matching message, inside the
// poll tick that the instance-wide tick semaphore serialises — so an unbounded
// action list is not a per-user cost. 100 rules (maxRulesPerUser) whose actions
// were bounded only by the 1 MiB request body is roughly three million IMAP
// calls per message, which is one authenticated user stalling every other
// account's mail. 20 is well past any real filter: the visibility rules below
// mean a rule can only usefully carry a handful of keyword writes plus one
// terminal action.
const maxActionsPerRule = 20

// maxRuleNameBytes bounds a rule's Name. The name is echoed into Decision
// Detail ("rule(s) applied: ...") for every matching message, so an unbounded
// one is an audit row — and an API response — sized by whatever the client sent.
const maxRuleNameBytes = 200

// maxActionValueBytes bounds a keyword name or target folder. IMAP servers
// reject far shorter atoms than this; the cap exists so the value cannot be
// used as bulk storage inside rules.json.
const maxActionValueBytes = 512

// knownActionTypes is the exact set ApplyOutcome can execute. Anything else
// reaching the engine returns "unsupported action type" on every attempt —
// which the poller classifies as retryable, so a single typo'd action type used
// to defer every matching message for the full maxDeferralAttempts window
// (about three hours) before retiring it unlabelled.
var knownActionTypes = map[string]bool{
	"keyword":   true,
	"unkeyword": true,
	"move":      true,
	"read":      true,
	"archive":   true,
	"spam":      true,
	"delete":    true,
	"stop":      true,
}

// actionsNeedingValue is the subset whose Value carries the keyword name or
// target folder. The rest ignore Value entirely (see Action's doc comment).
var actionsNeedingValue = map[string]bool{
	"keyword":   true,
	"unkeyword": true,
	"move":      true,
}

// IsVisibilityChanging reports whether an action can remove a message from the
// poller's retry query.
//
// The poller retries a failed message by re-running ListUnreadInbox, which is
// an UNSEEN SEARCH over INBOX above the held checkpoint. Marking a message
// read takes it out of UNSEEN; moving, archiving, marking spam or deleting
// takes it out of INBOX. Either way the next tick cannot see the message, so
// anything still owed to it is lost rather than retried.
//
// That is why ValidateRule requires at most one of these per rule and requires
// it last: once one has run, no later action in the same rule can be retried.
func IsVisibilityChanging(actionType string) bool {
	switch strings.ToLower(strings.TrimSpace(actionType)) {
	case "read", "move", "archive", "spam", "delete":
		return true
	}
	return false
}

// ValidateRule is the one gate every rule must pass before it is stored or
// executed: the JSON create and update handlers, the Sieve script import, and
// the lists both rule consumers load from disk (see FilterRunnable).
//
// It checks the match tree's shape (ValidateMatchShape) plus everything about
// the action list that the engine assumes and nothing previously enforced:
// known types, bounded counts and sizes, and an ordering under which a failed
// action is always still retryable.
func ValidateRule(r Rule) error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if len(r.Name) > maxRuleNameBytes {
		return fmt.Errorf("name exceeds maximum length of %d bytes", maxRuleNameBytes)
	}
	if err := ValidateMatchShape(r.Match); err != nil {
		return err
	}
	if len(r.Actions) > maxActionsPerRule {
		return fmt.Errorf("rule has more than %d actions", maxActionsPerRule)
	}

	visibilityAt := -1
	for i, a := range r.Actions {
		t := strings.ToLower(strings.TrimSpace(a.Type))
		if !knownActionTypes[t] {
			return fmt.Errorf("unsupported action type %q", a.Type)
		}
		if len(a.Value) > maxActionValueBytes {
			return fmt.Errorf("action %q value exceeds maximum length of %d bytes", t, maxActionValueBytes)
		}
		if actionsNeedingValue[t] && strings.TrimSpace(a.Value) == "" {
			return fmt.Errorf("action %q requires a value", t)
		}
		if !IsVisibilityChanging(t) {
			continue
		}
		if visibilityAt >= 0 {
			return fmt.Errorf("rule has more than one action that changes message visibility (%q and %q)",
				r.Actions[visibilityAt].Type, a.Type)
		}
		visibilityAt = i
	}

	// Last, or second-to-last with a trailing "stop" — "archive; stop;" is the
	// common Sieve shape and stop performs no client call, so nothing is left
	// owed to a message the archive already made invisible.
	if visibilityAt >= 0 {
		last := len(r.Actions) - 1
		trailingStop := last == visibilityAt+1 &&
			strings.EqualFold(strings.TrimSpace(r.Actions[last].Type), "stop")
		if visibilityAt != last && !trailingStop {
			return fmt.Errorf(
				"action %q changes message visibility and must be the rule's last action (an optional trailing \"stop\" aside), "+
					"because a later action that fails cannot be retried once the message leaves the unread inbox",
				r.Actions[visibilityAt].Type)
		}
	}
	return nil
}

// FilterRunnable splits a stored rule list into the rules safe to execute and
// the reasons the rest were rejected (as "<rule name>: <error>" strings, for
// the caller to log).
//
// Validation at the write boundaries cannot cover rules.json: it is a plain
// file in the user's state directory, it predates these checks, and both
// consumers act on it with move, spam and delete. Enforcing the same contract
// at load means an unexecutable rule is skipped with a log line instead of
// failing per message forever.
func FilterRunnable(list []Rule) ([]Rule, []string) {
	out := make([]Rule, 0, len(list))
	var rejected []string
	for _, r := range list {
		if err := ValidateRule(r); err != nil {
			rejected = append(rejected, fmt.Sprintf("%s: %s", r.Name, err.Error()))
			continue
		}
		out = append(out, r)
	}
	return out, rejected
}
