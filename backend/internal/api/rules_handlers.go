package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/rules"
)

// maxRulesPerUser bounds how many filter rules one account may accumulate.
// Unlike send-as aliases (each Create sends an unsolicited email to a third
// party), a rule's only cost is the poller's own per-message evaluation
// time, so this is set well above maxSendAsAliasesPerUser (20) — closer to
// a Gmail-style filter allowance — purely as a hygiene backstop against
// unbounded accumulation, not a tight abuse-resistance limit.
const maxRulesPerUser = 100

type rulePayload struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Enabled     bool             `json:"enabled"`
	Order       int              `json:"order"`
	Scope       rules.RuleScope  `json:"scope"`
	Match       rules.MatchGroup `json:"match"`
	Actions     []rules.Action   `json:"actions"`
	Rev         int64            `json:"rev"`
	CreatedAt   string           `json:"createdAt"`
	UpdatedAt   string           `json:"updatedAt"`
	GUIEditable bool             `json:"guiEditable"`
}

// ruleIsGUIEditable reports whether r's Match tree is flat enough for the
// GUI builder: depth 1, i.e. no Condition.Group anywhere. Rules produced by
// hand-edited Sieve can nest arbitrarily deep and are reported as
// script-only.
func ruleIsGUIEditable(r rules.Rule) bool {
	for _, c := range r.Match.Conditions {
		if c.Group != nil {
			return false
		}
	}
	return true
}

func ruleToPayload(r rules.Rule) rulePayload {
	return rulePayload{
		ID:          r.ID,
		Name:        r.Name,
		Enabled:     r.Enabled,
		Order:       r.Order,
		Scope:       r.Scope,
		Match:       r.Match,
		Actions:     r.Actions,
		Rev:         r.Rev,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
		GUIEditable: ruleIsGUIEditable(r),
	}
}

func ruleFromPayload(p rulePayload) rules.Rule {
	return rules.Rule{
		ID:      p.ID,
		Name:    p.Name,
		Enabled: p.Enabled,
		Order:   p.Order,
		Scope:   p.Scope,
		Match:   p.Match,
		Actions: p.Actions,
	}
}

// handleRules serves the caller's rule list and creates new rules.
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	store, err := s.rulesFor(r)
	if err != nil {
		http.Error(w, "failed to open rules store", http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case http.MethodGet:
		list := store.List()
		out := make([]rulePayload, 0, len(list))
		for _, rl := range list {
			out = append(out, ruleToPayload(rl))
		}
		writeJSON(w, http.StatusOK, map[string]any{"rules": out})
	case http.MethodPost:
		var payload rulePayload
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(payload.Name)
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if len(store.List()) >= maxRulesPerUser {
			http.Error(w, "too many rules for this account", http.StatusBadRequest)
			return
		}
		if err := rules.ValidateMatchShape(payload.Match); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		payload.ID = ""
		payload.Name = name
		created, err := store.Upsert(ruleFromPayload(payload))
		if err != nil {
			http.Error(w, "failed to create rule", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, ruleToPayload(created))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRuleByID updates or deletes a single rule.
func (s *Server) handleRuleByID(w http.ResponseWriter, r *http.Request) {
	store, err := s.rulesFor(r)
	if err != nil {
		http.Error(w, "failed to open rules store", http.StatusInternalServerError)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPut:
		existing, ok := store.Get(id)
		if !ok {
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}
		var payload rulePayload
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(payload.Name)
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if err := rules.ValidateMatchShape(payload.Match); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		payload.ID = existing.ID
		payload.Name = name
		// Order and Scope aren't part of the editable payload for this
		// endpoint (Order is managed by /reorder; Scope isn't settable via
		// the GUI editor) — base on existing so a partial update (e.g. a
		// client that only sends name/match/actions) doesn't silently zero
		// them out via Go's int/struct zero values.
		payload.Order = existing.Order
		payload.Scope = existing.Scope
		updated, err := store.Upsert(ruleFromPayload(payload))
		if err != nil {
			http.Error(w, "failed to update rule", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, ruleToPayload(updated))
	case http.MethodDelete:
		removed, err := store.Delete(id)
		if err != nil {
			http.Error(w, "failed to delete rule", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRulesReorder persists a new Order for each named rule ID, in the
// order given.
func (s *Server) handleRulesReorder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	store, err := s.rulesFor(r)
	if err != nil {
		http.Error(w, "failed to open rules store", http.StatusInternalServerError)
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if len(req.IDs) == 0 {
		http.Error(w, "ids is required", http.StatusBadRequest)
		return
	}
	if err := store.Reorder(req.IDs); err != nil {
		http.Error(w, "failed to reorder rules", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleRuleSieve serves (GET) and accepts (PUT) the Sieve-subset text view
// of one rule. GET compiles Match/Actions to script text; PUT parses script
// text back into Match/Actions, leaving every other field on the rule
// untouched. A parse error is reported as 400 with the parser's message (it
// already includes a line number) so the frontend can show it inline
// without discarding the user's edit.
func (s *Server) handleRuleSieve(w http.ResponseWriter, r *http.Request) {
	store, err := s.rulesFor(r)
	if err != nil {
		http.Error(w, "failed to open rules store", http.StatusInternalServerError)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	existing, ok := store.Get(id)
	if !ok {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		script, err := rules.CompileRule(existing)
		if err != nil {
			http.Error(w, "failed to compile rule", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"script": script})
	case http.MethodPut:
		var req struct {
			Script string `json:"script"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		parsed, err := rules.ParseRuleText(req.Script, existing)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		// The same width bound the two JSON write paths enforce. ParseRuleText
		// caps nesting depth but not leaf count, and a script well inside the
		// 1 MiB body limit above parses into hundreds of thousands of
		// conditions — each of which recompiles its regex on every message,
		// inside an evaluation the poller cannot interrupt and holds a
		// single instance-wide semaphore across. Skipping this check here made
		// the cap the other two paths enforce trivially bypassable.
		if err := rules.ValidateMatchShape(parsed.Match); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		updated, err := store.Upsert(parsed)
		if err != nil {
			http.Error(w, "failed to save rule", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, ruleToPayload(updated))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// rulesRunResult is the wire response of POST /api/rules/run.
type rulesRunResult struct {
	Scanned int `json:"scanned"`
	Matched int `json:"matched"`
	Applied int `json:"applied"`
	Failed  int `json:"failed"`
}

// handleRulesRun is the manual "run rules now" backfill: it lists the
// target folder's messages live (independent of the poller's
// checkpoint/processed-state machinery — a deliberate re-apply regardless
// of AI-processed status), evaluates every enabled rule against each, and
// applies matched actions. Bodies are fetched only when at least one
// enabled rule has a body-field condition.
func (s *Server) handleRulesRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}
	store, err := s.rulesFor(r)
	if err != nil {
		http.Error(w, "failed to open rules store", http.StatusInternalServerError)
		return
	}

	var req struct {
		Mailbox string `json:"mailbox"`
		Limit   int    `json:"limit"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil && err != io.EOF {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
	}
	mailbox := strings.TrimSpace(req.Mailbox)
	if mailbox == "" {
		mailbox = "INBOX"
	}
	limit := req.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	var activeRules []rules.Rule
	needsBody := false
	for _, rl := range store.List() {
		if !rl.Enabled {
			continue
		}
		activeRules = append(activeRules, rl)
		if conditionsUseBody(rl.Match) {
			needsBody = true
		}
	}

	overviews, err := mailClient.ListOverviews(r.Context(), mailbox, limit)
	if err != nil {
		http.Error(w, "failed to list messages", http.StatusBadGateway)
		return
	}

	var bodies map[int]imapadapter.MessageContent
	if needsBody && len(overviews) > 0 {
		uids := make([]int, 0, len(overviews))
		for _, ov := range overviews {
			uids = append(uids, ov.UID)
		}
		bodies, err = mailClient.GetMessageBodies(r.Context(), mailbox, uids)
		if err != nil {
			http.Error(w, "failed to fetch message bodies", http.StatusBadGateway)
			return
		}
	}

	result := rulesRunResult{Scanned: len(overviews)}
	for _, ov := range overviews {
		body := ""
		if bodies != nil {
			body = bodies[ov.UID].Body
		}
		input := rules.EvalInput{
			UID:       ov.UID,
			MessageID: ov.MessageID,
			From:      ov.Sender,
			To:        ov.SentTo,
			CC:        ov.CC,
			BCC:       ov.BCC,
			Subject:   ov.Subject,
			Body:      body,
			Keywords:  ov.Keywords,
			Folder:    mailbox,
		}
		outcome := rules.Evaluate(input, activeRules)
		if len(outcome.Matched) == 0 {
			continue
		}
		result.Matched++
		actionResults := rules.ApplyOutcome(r.Context(), mailClient, mailbox, input, outcome)
		failed := false
		for _, ar := range actionResults {
			if ar.Err != nil {
				failed = true
				break
			}
		}
		if failed {
			result.Failed++
		} else {
			result.Applied++
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// conditionsUseBody reports whether g (or any nested Condition.Group)
// contains a body-field condition, so handleRulesRun can skip the body
// fetch entirely when no active rule needs it.
func conditionsUseBody(g rules.MatchGroup) bool {
	for _, c := range g.Conditions {
		if c.Group != nil {
			if conditionsUseBody(*c.Group) {
				return true
			}
			continue
		}
		if strings.EqualFold(c.Field, "body") {
			return true
		}
	}
	return false
}
