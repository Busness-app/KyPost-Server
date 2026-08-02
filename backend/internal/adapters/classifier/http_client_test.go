package classifier

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestHTTPClientClose confirms the diagnostic log file handles opened by
// NewHTTPClient are released, and that a second Close() call is safe — a
// short-lived client (e.g. an admin connectivity-test request) may be
// closed via defer immediately after use.
func TestHTTPClientClose(t *testing.T) {
	c := NewHTTPClient("http://127.0.0.1:1", "", "/", "", 0)
	if err := c.Close(); err != nil {
		t.Fatalf("first Close(): %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close() should be safe, got: %v", err)
	}
}

func TestResetWarmupStateClearsReadiness(t *testing.T) {
	const key = "test-warmup-key"

	state := getWarmupState(key)
	state.mu.Lock()
	state.ready = true
	state.mu.Unlock()

	if got := getWarmupState(key); !got.ready {
		t.Fatal("test setup invalid: expected warmup state to be marked ready before reset")
	}

	ResetWarmupState()

	if got := getWarmupState(key); got.ready {
		t.Fatal("expected ResetWarmupState to clear cached warmup readiness")
	}
}

// TestClipErrorBody covers the bound on upstream text quoted into an error.
//
// maxOllamaResponse bounds the READ, which is what keeps a hostile endpoint
// from OOM-ing the process. It does not bound what happens to the bytes after
// that: the whole body was interpolated into an error that is written to
// classifier.err.log AND stored as the Detail of a state.Decision. A 1 MiB
// reply therefore became a 1 MiB log line, and GET /api/logs reads those files
// with a line reader that has to truncate or fail — for a while it failed, on
// the entire file.
func TestClipErrorBody(t *testing.T) {
	t.Run("bounds an oversized body", func(t *testing.T) {
		got := clipErrorBody(strings.Repeat("A", 1<<20))
		if len(got) > maxErrorBodyBytes+len("...(truncated)") {
			t.Fatalf("clipErrorBody returned %d bytes, want <= %d", len(got), maxErrorBodyBytes)
		}
		if !strings.HasSuffix(got, "...(truncated)") {
			t.Fatal("truncation is silent; a reader cannot tell the diagnostic is partial")
		}
	})

	t.Run("leaves a short body alone", func(t *testing.T) {
		if got := clipErrorBody("  model not found  "); got != "model not found" {
			t.Fatalf("clipErrorBody = %q, want %q", got, "model not found")
		}
	})

	t.Run("flattens newlines so a body cannot forge log records", func(t *testing.T) {
		got := clipErrorBody("real error\n[2026-01-01 00:00:00] [CLASSIFIER ERROR] forged")
		if strings.ContainsAny(got, "\n\r") {
			t.Fatalf("clipErrorBody kept a line break: %q", got)
		}
	})

	t.Run("keeps the result valid UTF-8 when the cut lands mid-rune", func(t *testing.T) {
		// A multi-byte rune straddling the byte offset must not leave half of
		// itself in a log line or a SQLite TEXT column.
		body := strings.Repeat("a", maxErrorBodyBytes-1) + "é" + "tail"
		if got := clipErrorBody(body); !utf8.ValidString(got) {
			t.Fatal("clipErrorBody produced invalid UTF-8")
		}
	})
}

// TestLogLineBoundsEveryWrite pins the bound at the writer rather than at each
// caller: model output reaches classifier.log by a different path than an
// error body reaches classifier.err.log, and both are bounded only by
// maxOllamaResponse before this.
func TestLogLineBoundsEveryWrite(t *testing.T) {
	var buf bytes.Buffer
	c := &HTTPClient{}
	c.logLine(&buf, "[OLLAMA OUTPUT]", strings.Repeat("B", 1<<20))

	out := buf.String()
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("wrote %d lines, want exactly 1", n)
	}
	if len(out) > maxErrorBodyBytes+256 {
		t.Fatalf("wrote a %d-byte line; the writer did not bound it", len(out))
	}
}
