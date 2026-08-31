package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kypost-server/backend/internal/users"
)

func TestReviewPairingRequiresOptInAndConfiguredAccountCredential(t *testing.T) {
	srv := newTestServer(t)
	req := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "/api/notifications/review-pairing",
			strings.NewReader(`{"username":"play-review","password":"review-password-123"}`))
	}

	disabled := httptest.NewRecorder()
	srv.handleReviewPairing(disabled, req())
	if disabled.Code != http.StatusNotFound {
		t.Fatalf("disabled status = %d, want 404", disabled.Code)
	}

	u, err := srv.users.Create(context.Background(), "play-review", "review-password-123", users.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.users.ClearMustChangePassword(u.ID); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REVIEW_PAIRING_USERNAME", "play-*")
	srv.serverBaseURL = "http://review.example"

	wrongAccount := httptest.NewRecorder()
	wrongReq := httptest.NewRequest(http.MethodPost, "/api/notifications/review-pairing",
		strings.NewReader(`{"username":"someone-else","password":"review-password-123"}`))
	srv.handleReviewPairing(wrongAccount, wrongReq)
	if wrongAccount.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-account status = %d, want 401", wrongAccount.Code)
	}

	ok := httptest.NewRecorder()
	srv.handleReviewPairing(ok, req())
	if ok.Code != http.StatusOK {
		t.Fatalf("valid status = %d: %s", ok.Code, ok.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(ok.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body["deepLink"].(string), "kypost://native-pair?") {
		t.Fatalf("deepLink = %q", body["deepLink"])
	}

	if reviewUsernameMatches("*", u.Username) {
		t.Fatal("a bare wildcard must not enable every account")
	}
}
