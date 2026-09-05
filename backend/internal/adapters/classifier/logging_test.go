package classifier

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClassifierLogsFailureContextAtDefaultLevel(t *testing.T) {
	var out bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&out, nil)))
	defer slog.SetDefault(old)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/pull" {
			w.Write([]byte(`{"status":"success"}`))
			return
		}
		w.Write([]byte(`{"response":"you've reached your weekly chat limit"}`))
	}))
	defer srv.Close()
	c := NewHTTPClient(srv.URL, "", "/api/generate", "", 0)
	if _, err := c.Classify(context.Background(), []string{"work"}, "", "", "", ""); err == nil {
		t.Fatal("credits exhaustion accepted")
	}
	for _, want := range []string{"AI credits exhausted", "OLLAMA WARMUP", "CLASSIFY FAILED"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %s: %s", want, out.String())
		}
	}
	c.logError("classify: connection refused\ncontinued")
	if !strings.Contains(out.String(), "connection refused continued") {
		t.Fatal("transport context lost")
	}
}

func TestClassifierErrorResponsesNeverReachLogs(t *testing.T) {
	for _, kind := range []string{"classify-http", "classify-json", "pull-http", "credits", "no-label"} {
		t.Run(kind, func(t *testing.T) {
			var out bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&out, nil)))
			defer slog.SetDefault(old)
			const private = "PRIVATE-SUBJECT-AND-BODY"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/pull" && kind != "pull-http" {
					w.Write([]byte(`{"status":"success"}`))
					return
				}
				switch kind {
				case "classify-http", "pull-http":
					w.WriteHeader(503)
					w.Write([]byte(private))
				case "classify-json":
					w.Write([]byte(`{"error":"` + private + `"}`))
				case "no-label":
					w.Write([]byte(`{"response":"` + private + `"}`))
				case "credits":
					w.Write([]byte(`{"response":"you've reached your weekly chat limit ` + private + `"}`))
				}
			}))
			defer srv.Close()
			c := NewHTTPClient(srv.URL, "", "/api/generate", "", 0)
			_, err := c.Classify(context.Background(), []string{"work"}, "", "", private, "")
			if err == nil {
				t.Fatal("expected failure")
			}
			if strings.Contains(out.String(), private) || strings.Contains(err.Error(), private) {
				t.Fatal("upstream content escaped through diagnostic or returned error")
			}
			if (kind == "classify-http" || kind == "pull-http") && !strings.Contains(out.String(), "status 503") {
				t.Fatal("lost safe HTTP status")
			}
		})
	}
}
