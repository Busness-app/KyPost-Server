package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/config"
)

// Every classify request carries the sender, the subject and up to 2000 bytes
// of the message body, plus the configured API key in an Authorization header.
// The base URL that names where all of that goes was accepted after a
// non-empty check: no scheme requirement, so a mistyped http:// shipped
// correspondence and the key across the public internet in the clear, and
// nothing reported it because classification kept working.
func TestConfigPutRefusesAPlaintextPublicClassifierURL(t *testing.T) {
	srv := newTestServer(t)
	admin, _ := newTestUsers(t, srv)
	srv.configPath = t.TempDir() + "/config.yaml"

	put := func(baseURL string) *httptest.ResponseRecorder {
		next := config.Default()
		next.Classifier.BaseURL = baseURL
		body, _ := json.Marshal(next)
		req := httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(body))
		authRequestAs(srv, req, admin.ID)
		rec := httptest.NewRecorder()
		srv.withAdmin(srv.handleConfig)(rec, req)
		return rec
	}

	// A real public address over http. IP literals throughout so the check
	// never depends on live DNS.
	if rec := put("http://93.184.216.34/v1"); rec.Code != http.StatusBadRequest {
		t.Fatalf("plaintext public classifier URL: status = %d, want %d (%s)",
			rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if rec := put("https://user:pass@93.184.216.34/v1"); rec.Code != http.StatusBadRequest {
		t.Fatalf("classifier URL with embedded credentials: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if rec := put("93.184.216.34:11434"); rec.Code != http.StatusBadRequest {
		t.Fatalf("schemeless classifier URL: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	// The bundled Ollama on loopback is the normal deployment and must keep
	// working over plain http — the policy is "TLS off-premises", not "TLS
	// everywhere".
	if rec := put("http://127.0.0.1:11434"); rec.Code != http.StatusOK {
		t.Fatalf("loopback classifier URL: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec := put("https://93.184.216.34/v1"); rec.Code != http.StatusOK {
		t.Fatalf("public classifier URL over https: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}
