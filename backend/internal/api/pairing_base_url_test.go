package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Every pairing endpoint follows SERVER_BASE_URL and nothing else.
//
// These URLs are where a device sends the 90-second pairing token and, once
// paired, its device secret. They used to fall back to externalBaseURL, which
// drops to the request's Host header, so a deployment answering on an alternate
// hostname handed out a pairing package aiming the token at that hostname. The
// helper that did it is gone; this is what keeps it gone.
func TestPairingEndpointsIgnoreTheRequestHost(t *testing.T) {
	srv := newTestServer(t)
	srv.pairingSecret = "test-pairing-secret-at-least-32-bytes-long"
	all, _ := srv.users.List()
	owner := all[0]

	pairingResponse := func() map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/notifications/pairing", nil)
		req.Host = "attacker.example"
		req.Header.Set("X-Forwarded-Host", "attacker.example")
		authRequestAs(srv, req, owner.ID)
		srv.withAuth(srv.handleNotificationPairing)(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return out
	}

	// Unset: no endpoint, no token, and a configuration error naming the fix.
	srv.serverBaseURL = ""
	out := pairingResponse()
	for _, field := range []string{"serverBaseUrl", "registerEndpoint", "pullEndpoint"} {
		if got, _ := out[field].(string); got != "" {
			t.Errorf("%s = %q with SERVER_BASE_URL unset, want empty — the Host header must not supply it", field, got)
		}
	}
	if out["configured"] != false {
		t.Errorf("configured = %v with SERVER_BASE_URL unset, want false", out["configured"])
	}
	if _, minted := out["pairingToken"]; minted {
		t.Error("a pairing token was minted with no address to send it to")
	}
	if msg, _ := out["configurationError"].(string); msg == "" {
		t.Error("no configurationError explaining what the operator must set")
	}

	// Set: the configured value wins over the request, verbatim.
	srv.serverBaseURL = "https://mail.example"
	out = pairingResponse()
	if got, _ := out["serverBaseUrl"].(string); got != "https://mail.example" {
		t.Errorf("serverBaseUrl = %q, want the configured value", got)
	}
	if got, _ := out["registerEndpoint"].(string); got != "https://mail.example/api/notifications/native/register" {
		t.Errorf("registerEndpoint = %q, want it built from SERVER_BASE_URL", got)
	}
	if got, _ := out["pullEndpoint"].(string); got != "https://mail.example/api/notifications/native/pull" {
		t.Errorf("pullEndpoint = %q, want it built from SERVER_BASE_URL", got)
	}
	if out["configured"] != true {
		t.Errorf("configured = %v with both halves set, want true", out["configured"])
	}
}
