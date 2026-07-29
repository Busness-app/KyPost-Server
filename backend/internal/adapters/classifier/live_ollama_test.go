package classifier

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveOllamaClassify exercises the real Classify path — the payload
// classifyOnce sends and the response parsing it does — against a running
// Ollama. Unit tests cannot catch the failure this exists for: with a `format`
// schema set, a reasoning model routes its answer into the "thinking" field and
// leaves "response" empty, so the classifier returns nothing on every call
// while every mock still passes.
//
// Skipped unless OLLAMA_LIVE_TEST is set, since it needs a model loaded:
//
//	OLLAMA_LIVE_TEST=1 OLLAMA_BASE_URL=http://127.0.0.1:11434 \
//	  go test ./internal/adapters/classifier/ -run TestLiveOllama -v
func TestLiveOllamaClassify(t *testing.T) {
	if os.Getenv("OLLAMA_LIVE_TEST") == "" {
		t.Skip("set OLLAMA_LIVE_TEST=1 to run against a live Ollama")
	}
	base := os.Getenv("OLLAMA_BASE_URL")
	if base == "" {
		base = "http://127.0.0.1:11434"
	}

	labels := []string{"Primary", "Promotions", "Social", "Updates"}
	c := NewHTTPClient(base, "", "", LoadTuningText(), 5*time.Minute)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cases := []struct {
		name    string
		sender  string
		subject string
		body    string
		want    string
	}{
		{"promotions", "deals@shop.example", "40% off everything this weekend",
			"Huge sale, use code SAVE40. Unsubscribe at any time.", "Promotions"},
		{"updates", "account@service.example", "Reset your password",
			"We received a request to reset your password. This link expires in 60 minutes.", "Updates"},
		{"social", "notify@linkedin.example", "Marcus Webb wants to connect",
			"Marcus Webb would like to connect with you on LinkedIn. Accept | Ignore", "Social"},
		{"primary", "sarah@work.example", "Can you review the migration doc?",
			"I finished the draft. Section 4 is the part I'm least sure about — tell me if the rollback window is too tight.", "Primary"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.Classify(ctx, labels, tc.sender, tc.subject, tc.body, "")
			if err != nil {
				t.Fatalf("Classify returned error: %v", err)
			}
			if strings.TrimSpace(got) == "" {
				t.Fatal("Classify returned an empty label — check think=false and the thinking-field fallback")
			}
			allowed := false
			for _, l := range labels {
				if got == l {
					allowed = true
				}
			}
			if !allowed {
				t.Fatalf("Classify returned %q, which is not in the allowlist", got)
			}
			t.Logf("%s -> %s", tc.name, got)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
