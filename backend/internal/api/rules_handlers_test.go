package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/rules"
)

func TestRulesCreateListUpdateDelete(t *testing.T) {
	srv := newTestServer(t)

	createBody, _ := json.Marshal(map[string]any{
		"name":    "Archive newsletters",
		"enabled": true,
		"match": map[string]any{
			"op": "allof",
			"conditions": []map[string]any{
				{"field": "from", "comparator": "contains", "value": "newsletter"},
			},
		},
		"actions": []map[string]any{{"type": "archive"}},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewReader(createBody))
	authRequest(srv, createReq)
	createRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d, body=%s", createRec.Code, createRec.Body.String())
	}
	var created rulePayload
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected assigned ID")
	}
	if !created.GUIEditable {
		t.Fatal("expected flat rule to be GUI editable")
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	authRequest(srv, listReq)
	listRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body=%s", listRec.Code, listRec.Body.String())
	}
	var listResp struct {
		Rules []rulePayload `json:"rules"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listResp.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(listResp.Rules))
	}

	updateBody, _ := json.Marshal(map[string]any{
		"name":    "Archive all newsletters",
		"enabled": false,
		"match":   listResp.Rules[0].Match,
		"actions": listResp.Rules[0].Actions,
	})
	updateReq := httptest.NewRequest(http.MethodPut, "/api/rules/"+created.ID, bytes.NewReader(updateBody))
	authRequest(srv, updateReq)
	updateRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("update status = %d, body=%s", updateRec.Code, updateRec.Body.String())
	}
	var updated rulePayload
	if err := json.Unmarshal(updateRec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if updated.Name != "Archive all newsletters" || updated.Enabled {
		t.Fatalf("update did not apply, got %+v", updated)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/rules/"+created.ID, nil)
	authRequest(srv, deleteReq)
	deleteRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body=%s", deleteRec.Code, deleteRec.Body.String())
	}
}

func TestRulesSieveRoundTrip(t *testing.T) {
	srv := newTestServer(t)

	createBody, _ := json.Marshal(map[string]any{
		"name": "from acme",
		"match": map[string]any{
			"op":         "allof",
			"conditions": []map[string]any{{"field": "from", "comparator": "contains", "value": "acme"}},
		},
		"actions": []map[string]any{{"type": "move", "value": "Archive/Acme"}},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewReader(createBody))
	authRequest(srv, createReq)
	createRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(createRec, createReq)
	var created rulePayload
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/rules/"+created.ID+"/sieve", nil)
	authRequest(srv, getReq)
	getRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get sieve status = %d, body=%s", getRec.Code, getRec.Body.String())
	}
	var sieveResp struct {
		Script string `json:"script"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &sieveResp); err != nil {
		t.Fatalf("decode sieve response: %v", err)
	}
	if sieveResp.Script == "" {
		t.Fatal("expected non-empty compiled script")
	}

	putBody, _ := json.Marshal(map[string]any{"script": sieveResp.Script})
	putReq := httptest.NewRequest(http.MethodPut, "/api/rules/"+created.ID+"/sieve", bytes.NewReader(putBody))
	authRequest(srv, putReq)
	putRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put sieve status = %d, body=%s", putRec.Code, putRec.Body.String())
	}

	badReq := httptest.NewRequest(http.MethodPut, "/api/rules/"+created.ID+"/sieve", bytes.NewReader([]byte(`{"script":"if bogus(x) { keep; }"}`)))
	authRequest(srv, badReq)
	badRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a bad script, got %d, body=%s", badRec.Code, badRec.Body.String())
	}
}

// deeplyNestedMatchPayload builds a MatchGroup-shaped map with `wraps`
// levels of allof(...) nested around a single leaf condition, mirroring the
// same pathological shape sieve_test.go's "excessive allof nesting is
// rejected" regression test uses (there, 50 levels of Sieve source text;
// here, the equivalent JSON MatchGroup/Condition.Group tree). Used to prove
// rules.ValidateMatchShape is actually wired into the JSON create/update
// paths, not just ParseRuleText's Sieve-script path.
func deeplyNestedMatchPayload(wraps int) map[string]any {
	current := map[string]any{
		"op": "allof",
		"conditions": []map[string]any{
			{"field": "from", "comparator": "contains", "value": "x"},
		},
	}
	for i := 0; i < wraps; i++ {
		current = map[string]any{
			"op": "allof",
			"conditions": []map[string]any{
				{"group": current},
			},
		}
	}
	return current
}

// TestRulesCreate_RejectsDeeplyNestedMatch guards the gap the first
// nesting-depth fix (sieve.go's maxTestNestingDepth check inside
// ParseRuleText) left open: POST /api/rules decodes rulePayload.Match
// straight from JSON and previously handed it to store.Upsert with no shape
// validation at all, so a caller could persist a Match tree deep enough that
// engine.go's evaluator would walk it on every poller tick forever,
// bypassing the Sieve-script path's depth bound entirely. This posts a
// 51-level-deep Match tree (well past maxTestNestingDepth's 32) and expects
// a 400, not a stored rule.
func TestRulesCreate_RejectsDeeplyNestedMatch(t *testing.T) {
	srv := newTestServer(t)

	createBody, _ := json.Marshal(map[string]any{
		"name":    "deeply nested",
		"enabled": true,
		"match":   deeplyNestedMatchPayload(50),
		"actions": []map[string]any{{"type": "archive"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewReader(createBody))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for deeply-nested match, got %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "nesting exceeds maximum depth") {
		t.Fatalf("expected nesting-depth error message, got %q", rec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	authRequest(srv, listReq)
	listRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(listRec, listReq)
	var listResp struct {
		Rules []rulePayload `json:"rules"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listResp.Rules) != 0 {
		t.Fatalf("expected the rejected rule not to be stored, got %d rules", len(listResp.Rules))
	}
}

// TestRulesUpdate_RejectsDeeplyNestedMatch is TestRulesCreate_RejectsDeeplyNestedMatch's
// sibling for PUT /api/rules/{id}, the other JSON CRUD path that bypassed
// ParseRuleText's depth check.
func TestRulesUpdate_RejectsDeeplyNestedMatch(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	store, err := srv.userRulesStore(all[0].ID)
	if err != nil {
		t.Fatalf("userRulesStore: %v", err)
	}
	existing, err := store.Upsert(rulesTestRule("original"))
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	updateBody, _ := json.Marshal(map[string]any{
		"name":    "updated",
		"enabled": true,
		"match":   deeplyNestedMatchPayload(50),
		"actions": []map[string]any{{"type": "archive"}},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/rules/"+existing.ID, bytes.NewReader(updateBody))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for deeply-nested match, got %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "nesting exceeds maximum depth") {
		t.Fatalf("expected nesting-depth error message, got %q", rec.Body.String())
	}

	// The original rule must be untouched by the rejected update.
	stillThere, ok := must2(store.Get(existing.ID))
	if !ok {
		t.Fatal("expected original rule to still exist")
	}
	if stillThere.Name != "original" {
		t.Fatalf("expected rejected update not to apply, got name=%q", stillThere.Name)
	}
}

// wideMatchPayload builds a single flat "anyof" MatchGroup with n sibling
// leaf conditions — the shape ValidateMatchDepth's original depth-only check
// let straight through (depth 1, no nesting at all), used to prove the
// width bound is actually wired into the JSON create/update paths.
func wideMatchPayload(n int) map[string]any {
	conditions := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		conditions = append(conditions, map[string]any{
			"field": "subject", "comparator": "contains", "value": fmt.Sprintf("v%d", i),
		})
	}
	return map[string]any{"op": "anyof", "conditions": conditions}
}

// TestRulesCreate_RejectsTooWideMatch is TestRulesCreate_RejectsDeeplyNestedMatch's
// sibling for tree width: a single flat group with more than
// rules.maxMatchConditions sibling conditions must be rejected, not stored.
func TestRulesCreate_RejectsTooWideMatch(t *testing.T) {
	srv := newTestServer(t)

	createBody, _ := json.Marshal(map[string]any{
		"name":    "too wide",
		"enabled": true,
		"match":   wideMatchPayload(301),
		"actions": []map[string]any{{"type": "archive"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewReader(createBody))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a 301-condition match, got %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "more than 300") {
		t.Fatalf("expected a condition-count error message, got %q", rec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	authRequest(srv, listReq)
	listRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(listRec, listReq)
	var listResp struct {
		Rules []rulePayload `json:"rules"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listResp.Rules) != 0 {
		t.Fatalf("expected the rejected rule not to be stored, got %d rules", len(listResp.Rules))
	}
}

// TestRulesCreate_RejectsOverRuleCap confirms the per-user rule cap: once an
// account has maxRulesPerUser rules, the next create is rejected, but PUT on
// an existing rule still succeeds (updating in place doesn't grow the
// count).
func TestRulesCreate_RejectsOverRuleCap(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	store, err := srv.userRulesStore(all[0].ID)
	if err != nil {
		t.Fatalf("userRulesStore: %v", err)
	}

	var lastID string
	for i := 0; i < maxRulesPerUser; i++ {
		created, err := store.Upsert(rulesTestRule(fmt.Sprintf("rule-%d", i)))
		if err != nil {
			t.Fatalf("seed rule %d: %v", i, err)
		}
		lastID = created.ID
	}

	overCapBody, _ := json.Marshal(map[string]any{
		"name":    "one too many",
		"enabled": true,
		"match":   map[string]any{"op": "allof", "conditions": []map[string]any{{"field": "from", "comparator": "contains", "value": "x"}}},
		"actions": []map[string]any{{"type": "archive"}},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewReader(overCapBody))
	authRequest(srv, createReq)
	createRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for the (maxRulesPerUser+1)th rule, got %d, body=%s", createRec.Code, createRec.Body.String())
	}
	if !strings.Contains(createRec.Body.String(), "too many rules") {
		t.Fatalf("expected a rule-cap error message, got %q", createRec.Body.String())
	}

	// Updating an existing rule must still succeed even at the cap.
	updateBody, _ := json.Marshal(map[string]any{
		"name":    "updated at cap",
		"enabled": true,
		"match":   map[string]any{"op": "allof", "conditions": []map[string]any{{"field": "from", "comparator": "contains", "value": "y"}}},
		"actions": []map[string]any{{"type": "archive"}},
	})
	updateReq := httptest.NewRequest(http.MethodPut, "/api/rules/"+lastID, bytes.NewReader(updateBody))
	authRequest(srv, updateReq)
	updateRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("expected update to succeed even at the rule cap, got %d, body=%s", updateRec.Code, updateRec.Body.String())
	}
}

// TestRulesCreateUpdate_ReasonableNestingStillSucceeds confirms the new
// depth check doesn't collaterally break normal rules: a 3-4 level nested
// Match tree (deeper than the flat GUI builder ever produces, but nowhere
// near maxTestNestingDepth) must still be accepted by both POST and PUT.
func TestRulesCreateUpdate_ReasonableNestingStillSucceeds(t *testing.T) {
	srv := newTestServer(t)

	reasonableMatch := deeplyNestedMatchPayload(3) // 4 levels total (3 wraps + 1 leaf)

	createBody, _ := json.Marshal(map[string]any{
		"name":    "reasonable nesting",
		"enabled": true,
		"match":   reasonableMatch,
		"actions": []map[string]any{{"type": "archive"}},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewReader(createBody))
	authRequest(srv, createReq)
	createRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d, body=%s", createRec.Code, createRec.Body.String())
	}
	var created rulePayload
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	updateBody, _ := json.Marshal(map[string]any{
		"name":    "reasonable nesting updated",
		"enabled": true,
		"match":   reasonableMatch,
		"actions": []map[string]any{{"type": "archive"}},
	})
	updateReq := httptest.NewRequest(http.MethodPut, "/api/rules/"+created.ID, bytes.NewReader(updateBody))
	authRequest(srv, updateReq)
	updateRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("update status = %d, body=%s", updateRec.Code, updateRec.Body.String())
	}
	var updated rulePayload
	if err := json.Unmarshal(updateRec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if updated.Name != "reasonable nesting updated" {
		t.Fatalf("update did not apply, got %+v", updated)
	}
}

func TestRulesReorder(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	store, err := srv.userRulesStore(all[0].ID)
	if err != nil {
		t.Fatalf("userRulesStore: %v", err)
	}
	a, _ := store.Upsert(rulesTestRule("a"))
	b, _ := store.Upsert(rulesTestRule("b"))

	reorderBody, _ := json.Marshal(map[string]any{"ids": []string{b.ID, a.ID}})
	req := httptest.NewRequest(http.MethodPost, "/api/rules/reorder", bytes.NewReader(reorderBody))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reorder status = %d, body=%s", rec.Code, rec.Body.String())
	}

	list, _ := store.List()
	if len(list) != 2 || list[0].Name != "b" || list[1].Name != "a" {
		t.Fatalf("expected [b, a] after reorder, got %+v", list)
	}
}

// TestRulesUpdatePreservesOrder guards against a regression where PUT
// /api/rules/{id} zeroed out a rule's Order whenever the request payload
// omitted it (Go zero-values a missing "order" field to 0, and Store.Upsert
// only defaults Order on create, not update). With a single rule in the
// store the rule's Order is already 0, so that scenario alone wouldn't catch
// the bug: this test seeds two rules with distinct, non-zero-at-index Order
// values and updates the second one with a payload that has no "order" key
// at all, then asserts both rules' Order/relative ordering survive.
func TestRulesUpdatePreservesOrder(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	store, err := srv.userRulesStore(all[0].ID)
	if err != nil {
		t.Fatalf("userRulesStore: %v", err)
	}
	first, err := store.Upsert(rulesTestRule("first"))
	if err != nil {
		t.Fatalf("seed first rule: %v", err)
	}
	second, err := store.Upsert(rulesTestRule("second"))
	if err != nil {
		t.Fatalf("seed second rule: %v", err)
	}
	if first.Order != 0 || second.Order != 1 {
		t.Fatalf("expected seeded orders [0, 1], got first=%d second=%d", first.Order, second.Order)
	}

	// Deliberately omit "order" (and "scope"), as a partial edit form would.
	updateBody, _ := json.Marshal(map[string]any{
		"name":    "second updated",
		"enabled": true,
		"match":   ruleToPayload(second).Match,
		"actions": ruleToPayload(second).Actions,
	})
	updateReq := httptest.NewRequest(http.MethodPut, "/api/rules/"+second.ID, bytes.NewReader(updateBody))
	authRequest(srv, updateReq)
	updateRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("update status = %d, body=%s", updateRec.Code, updateRec.Body.String())
	}
	var updated rulePayload
	if err := json.Unmarshal(updateRec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if updated.Name != "second updated" {
		t.Fatalf("update did not apply name change, got %+v", updated)
	}
	if updated.Order != 1 {
		t.Fatalf("expected updated rule's Order to remain 1, got %d", updated.Order)
	}

	list, _ := store.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(list))
	}
	if list[0].Name != "first" || list[0].Order != 0 {
		t.Fatalf("expected first rule unaffected at Order 0, got %+v", list[0])
	}
	if list[1].Name != "second updated" || list[1].Order != 1 {
		t.Fatalf("expected second rule updated in place at Order 1, got %+v", list[1])
	}
}

func TestRulesRun_AppliesMatchingRuleAndSkipsNonMatching(t *testing.T) {
	srv := newTestServer(t)
	srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
	all, _ := srv.users.List()
	userID := all[0].ID

	store, err := srv.userRulesStore(userID)
	if err != nil {
		t.Fatalf("userRulesStore: %v", err)
	}
	if _, err := store.Upsert(rulesTestRule("archive acme")); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// mailFor/userMailClient only reuses a cached client when the cached
	// updatedAt matches what's on disk — write a real (if inert) IMAP
	// config payload stamped with the same updatedAt used below so the
	// handler's mailFor resolves to the injected fake instead of building a
	// real imapadapter.APIClient.
	if err := writeIMAPConfigPayload(srv.userIMAPConfigPath(userID), srv.imapConfigKeyPath, imapConfigPayload{
		Host: "imap.example.com", Port: 993, Username: "alice@example.com", Password: "pw",
		Mailbox: "INBOX", UpdatedAt: "test",
	}); err != nil {
		t.Fatalf("writeIMAPConfigPayload: %v", err)
	}
	fake := &fakeMailClient{
		overviews: []imapadapter.Overview{
			{MessageID: "1", UID: 1, Sender: "billing@acme.com", Subject: "Invoice"},
			{MessageID: "2", UID: 2, Sender: "someone@example.com", Subject: "Hello"},
		},
	}
	srv.userMu.Lock()
	srv.userMail[userID] = &serverMailEntry{client: fake, updatedAt: "test"}
	srv.userMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/rules/run", bytes.NewReader([]byte(`{"mailbox":"INBOX"}`)))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var result rulesRunResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Scanned != 2 || result.Matched != 1 || result.Applied != 1 || result.Failed != 0 {
		t.Fatalf("result = %+v, want scanned=2 matched=1 applied=1 failed=0", result)
	}
}

// rulesTestRule builds a minimal enabled rule matching From contains "acme"
// with an archive action, for tests that only need a fixture rule to exist.
// Task 7 adds a second test function to this file that also uses this
// helper — keep it exported at file scope, not local to one test.
func rulesTestRule(name string) rules.Rule {
	return rules.Rule{
		Name:    name,
		Enabled: true,
		Match: rules.MatchGroup{
			Op:         "allof",
			Conditions: []rules.Condition{{Field: "from", Comparator: "contains", Value: "acme"}},
		},
		Actions: []rules.Action{{Type: "archive"}},
	}
}

// setupRulesRunTest wires up a test server with a fake IMAP client injected
// so POST /api/rules/run resolves to it instead of building a real
// imapadapter.APIClient. Mirrors the setup in
// TestRulesRun_AppliesMatchingRuleAndSkipsNonMatching.
func setupRulesRunTest(t *testing.T, overviews []imapadapter.Overview, bodies map[int]string) (*Server, *fakeMailClient, string) {
	t.Helper()
	srv := newTestServer(t)
	srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
	all, _ := srv.users.List()
	userID := all[0].ID

	if err := writeIMAPConfigPayload(srv.userIMAPConfigPath(userID), srv.imapConfigKeyPath, imapConfigPayload{
		Host: "imap.example.com", Port: 993, Username: "alice@example.com", Password: "pw",
		Mailbox: "INBOX", UpdatedAt: "test",
	}); err != nil {
		t.Fatalf("writeIMAPConfigPayload: %v", err)
	}
	fake := &fakeMailClient{overviews: overviews, bodies: bodies}
	srv.userMu.Lock()
	srv.userMail[userID] = &serverMailEntry{client: fake, updatedAt: "test"}
	srv.userMu.Unlock()
	return srv, fake, userID
}

// TestRulesRun_FetchesBodyWhenRuleNeedsIt guards against a regression where
// a body-field condition is never actually exercised end-to-end: it seeds a
// rule whose only condition is on Field "body", confirms the handler fetched
// message bodies (fake.bodiesCalls), that the fetched body content genuinely
// reached rules.EvalInput.Body, and that the match/no-match outcome tracked
// the fetched content rather than some other field.
func TestRulesRun_FetchesBodyWhenRuleNeedsIt(t *testing.T) {
	srv, fake, userID := setupRulesRunTest(t,
		[]imapadapter.Overview{
			{MessageID: "1", UID: 1, Sender: "a@example.com", Subject: "s1"},
			{MessageID: "2", UID: 2, Sender: "b@example.com", Subject: "s2"},
		},
		map[int]string{
			1: "contains the secret keyword",
			2: "nothing interesting here",
		},
	)

	store, err := srv.userRulesStore(userID)
	if err != nil {
		t.Fatalf("userRulesStore: %v", err)
	}
	if _, err := store.Upsert(rules.Rule{
		Name:    "body has secret",
		Enabled: true,
		Match: rules.MatchGroup{
			Op:         "allof",
			Conditions: []rules.Condition{{Field: "body", Comparator: "contains", Value: "secret"}},
		},
		Actions: []rules.Action{{Type: "archive"}},
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/rules/run", bytes.NewReader([]byte(`{"mailbox":"INBOX"}`)))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}

	if fake.bodiesCalls != 1 {
		t.Fatalf("expected exactly one body fetch, got %d", fake.bodiesCalls)
	}
	if len(fake.lastBodyUIDs) != 2 {
		t.Fatalf("expected bodies fetched for both UIDs, got %+v", fake.lastBodyUIDs)
	}

	var result rulesRunResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Only UID 1's fetched body contains "secret"; UID 2's does not. If
	// EvalInput.Body weren't genuinely populated from the fetched content,
	// this would either match 0 or match both.
	if result.Scanned != 2 || result.Matched != 1 || result.Applied != 1 || result.Failed != 0 {
		t.Fatalf("result = %+v, want scanned=2 matched=1 applied=1 failed=0", result)
	}
}

// TestRulesRun_DisabledRuleExcludedFromActionsAndBodyFetch seeds one disabled
// rule with a body-field condition alongside one enabled from-field rule. It
// guards two things at once: (1) the handler's own Enabled pre-filter (around
// rules_handlers.go's activeRules loop) must keep the disabled rule's actions
// from ever being applied, and (2) needsBody must be computed only from
// enabled rules, so the disabled rule's body condition must NOT trigger a
// body fetch.
func TestRulesRun_DisabledRuleExcludedFromActionsAndBodyFetch(t *testing.T) {
	srv, fake, userID := setupRulesRunTest(t,
		[]imapadapter.Overview{
			{MessageID: "1", UID: 1, Sender: "billing@acme.com", Subject: "Invoice"},
			{MessageID: "2", UID: 2, Sender: "someone@example.com", Subject: "Hello"},
		},
		nil,
	)

	store, err := srv.userRulesStore(userID)
	if err != nil {
		t.Fatalf("userRulesStore: %v", err)
	}
	// Disabled rule: matches every message on body content and would apply a
	// keyword action (observable via fake.appliedLabels) if it were ever
	// (wrongly) evaluated.
	if _, err := store.Upsert(rules.Rule{
		Name:    "disabled body rule",
		Enabled: false,
		Match: rules.MatchGroup{
			Op:         "allof",
			Conditions: []rules.Condition{{Field: "body", Comparator: "contains", Value: ""}},
		},
		Actions: []rules.Action{{Type: "keyword", Value: "ShouldNotApply"}},
	}); err != nil {
		t.Fatalf("Upsert disabled rule: %v", err)
	}
	// Enabled rule: only matches the acme sender, no body condition.
	if _, err := store.Upsert(rulesTestRule("archive acme")); err != nil {
		t.Fatalf("Upsert enabled rule: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/rules/run", bytes.NewReader([]byte(`{"mailbox":"INBOX"}`)))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}

	if fake.bodiesCalls != 0 {
		t.Fatalf("expected no body fetch (disabled rule's body condition must not count), got %d calls", fake.bodiesCalls)
	}
	if len(fake.appliedLabels) != 0 {
		t.Fatalf("expected no label actions applied, got %+v", fake.appliedLabels)
	}

	var result rulesRunResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Only the acme-sender message matches the enabled rule; if the disabled
	// rule's allof-with-empty-value body condition were evaluated, both
	// messages would match instead.
	if result.Scanned != 2 || result.Matched != 1 || result.Applied != 1 || result.Failed != 0 {
		t.Fatalf("result = %+v, want scanned=2 matched=1 applied=1 failed=0", result)
	}
}

// TestRulesRun_MalformedJSONReturns400 guards against the request body
// decode error at handleRulesRun being silently discarded: malformed JSON
// must be reported as 400, matching every other JSON-decoding call site in
// this file.
func TestRulesRun_MalformedJSONReturns400(t *testing.T) {
	srv, _, _ := setupRulesRunTest(t, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/rules/run", bytes.NewReader([]byte(`{"mailbox": `)))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON, got %d, body=%s", rec.Code, rec.Body.String())
	}
}
