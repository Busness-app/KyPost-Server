package classifier

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPClientVersionParsesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/version" {
			t.Errorf("unexpected path %q, want /api/version", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"version":"0.32.1"}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "", "", 0)
	got, err := c.Version(context.Background())
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if got != "0.32.1" {
		t.Fatalf("Version = %q, want %q", got, "0.32.1")
	}
}

func TestHTTPClientVersionErrorsOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "", "", 0)
	if _, err := c.Version(context.Background()); err == nil {
		t.Fatal("expected an error for a non-2xx /api/version response")
	}
}

// TestClassifyDoesNotLaunderOffAllowlistOutput pins the invariant that
// Classify's label return value is always a member of allowedLabels: an
// answer the allowlist does not cover comes back as NoAllowedLabelError
// carrying the raw text, never as a label.
func TestClassifyDoesNotLaunderOffAllowlistOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"response": "Totally Made Up Label"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "/api/generate", "", 5*time.Second)
	defer c.Close()

	got, err := c.Classify(context.Background(), []string{"Important", "Questionable"}, "s@example.com", "subj", "body", "")
	var noLabel *NoAllowedLabelError
	if !errors.As(err, &noLabel) {
		t.Fatalf("Classify off-allowlist: err = %v, want NoAllowedLabelError (got label %q)", err, got)
	}
	if got != "" {
		t.Fatalf("Classify off-allowlist returned label %q, want empty", got)
	}
	if !strings.Contains(noLabel.Output, "Totally Made Up Label") {
		t.Fatalf("NoAllowedLabelError.Output = %q, want the raw model text", noLabel.Output)
	}
}

// A lenient match ("This is Important") must still resolve, so tightening the
// contract did not tighten behavior.
func TestClassifyAcceptsLenientAllowlistMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"response": "I think this one is Important."})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "/api/generate", "", 5*time.Second)
	defer c.Close()

	got, err := c.Classify(context.Background(), []string{"Important", "Questionable"}, "", "", "body", "")
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got != "Important" {
		t.Fatalf("Classify = %q, want %q", got, "Important")
	}
}
