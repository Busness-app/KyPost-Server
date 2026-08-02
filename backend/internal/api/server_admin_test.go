package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kypost-server/backend/internal/state"
)

// TestTailLinesOversizedLine is the regression guard for the admin log viewer
// against a single oversized line. The classifier quotes upstream error bodies
// and model replies into its logs bounded only by maxOllamaResponse (1 MiB),
// and the previous bufio.Scanner implementation failed the whole file with
// bufio.ErrTooLong the moment one appeared — GET /api/logs returned 500 and
// the admin lost every line in that file, including the ones diagnosing the
// outage that produced the long line.
func TestTailLinesOversizedLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "classifier.err.log")
	content := "first\n" + strings.Repeat("A", 1<<20) + "\nlast\ntail\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := tailLines(p, 200)
	if err != nil {
		t.Fatalf("tailLines errored on an oversized line: %v", err)
	}
	if len(out) != 4 {
		t.Fatalf("got %d lines, want 4: %#v", len(out), firstBytes(out))
	}
	if out[0] != "first" || out[2] != "last" || out[3] != "tail" {
		t.Fatalf("lines after the oversized one were lost: %#v", firstBytes(out))
	}
	if !strings.HasSuffix(out[1], "...(truncated)") || len(out[1]) > maxLogLineBytes+64 {
		t.Fatalf("oversized line not truncated: len=%d", len(out[1]))
	}
}

// TestTailLinesNoTrailingNewline covers a live log being read mid-write: the
// final record has no newline yet, and ReadLine reports it alongside io.EOF.
func TestTailLinesNoTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	if err := os.WriteFile(p, []byte("a\nb\nc"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := tailLines(p, 200)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(out, ",") != "a,b,c" {
		t.Fatalf("got %#v", out)
	}
}

// TestTailLinesLimit pins the "tail" in tailLines — the newest lines, not the
// oldest, which is what recovering from ErrTooLong mid-file would have given.
func TestTailLinesLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	if err := os.WriteFile(p, []byte("a\nb\nc\nd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := tailLines(p, 2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(out, ",") != "c,d" {
		t.Fatalf("got %#v, want the LAST 2 lines", out)
	}
}

// firstBytes keeps a failure message readable when one of the lines is a
// megabyte long.
func firstBytes(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		if len(s) > 40 {
			s = s[:40] + "..."
		}
		out[i] = s
	}
	return out
}

// TestStatusReportsPollFreshness covers the end-to-end path for the health
// page's poll stats: the daemon records a tick into the user's state.db, and
// the API process — a different process in deployment — reads it back out.
//
// It exists because /api/health cannot answer "is mail being polled?": it
// reports IMAP reachability, which a daemon that has stopped ticking entirely
// still satisfies. Everything asserted here was previously a log line.
func TestStatusReportsPollFreshness(t *testing.T) {
	srv := newTestServer(t)
	u, err := users0(t, srv)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	type statusBody struct {
		LastPollTick *struct {
			AtUTC          string `json:"atUtc"`
			Fetched        int    `json:"fetched"`
			Processed      int    `json:"processed"`
			Failed         int    `json:"failed"`
			Deferred       int    `json:"deferred"`
			CheckpointHeld bool   `json:"checkpointHeld"`
		} `json:"lastPollTick"`
		CheckpointHeldSince string `json:"checkpointHeldSinceUtc"`
		FailedLast24h       int    `json:"failedLast24h"`
		StateDiskBytes      int64  `json:"stateDiskBytes"`
		ServerTimeUTC       string `json:"serverTimeUtc"`
	}

	call := func() statusBody {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.RemoteAddr = "127.0.0.1:41000"
		rec := httptest.NewRecorder()
		srv.handleStatus(rec, authedRequestForTest(req, u))
		if rec.Code != http.StatusOK {
			t.Fatalf("status: %d (%s)", rec.Code, rec.Body.String())
		}
		var out statusBody
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode status: %v", err)
		}
		return out
	}

	// Before any tick: absent, not zero. "Never polled" and "polled, fetched
	// nothing" are different answers and the page renders them differently.
	if got := call(); got.LastPollTick != nil {
		t.Fatalf("lastPollTick present before any tick ran: %+v", got.LastPollTick)
	}

	// The daemon's store — a separate handle over the same directory, which is
	// what the two processes actually have.
	store, err := state.New(srv.userStateDir(u.ID))
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	if err := store.RecordPollTick(state.PollTick{
		Fetched: 9, Processed: 7, Failed: 2, Deferred: 2, CheckpointHeld: true,
	}); err != nil {
		t.Fatalf("RecordPollTick: %v", err)
	}

	got := call()
	if got.LastPollTick == nil {
		t.Fatal("lastPollTick absent after the daemon recorded one")
	}
	if got.LastPollTick.Fetched != 9 || got.LastPollTick.Processed != 7 || got.LastPollTick.Failed != 2 {
		t.Fatalf("counts did not survive the round trip: %+v", got.LastPollTick)
	}
	if !got.LastPollTick.CheckpointHeld || got.CheckpointHeldSince == "" {
		t.Fatalf("a held checkpoint must be reported with its since-timestamp: %+v", got)
	}
	if got.StateDiskBytes <= 0 {
		t.Fatalf("stateDiskBytes = %d, want a positive size", got.StateDiskBytes)
	}
	// Ages are computed client-side against this, so it has to be there.
	if got.ServerTimeUTC == "" {
		t.Fatal("serverTimeUtc missing; the client cannot measure poll age without it")
	}

	// Recovery clears the sticky timestamp.
	if err := store.RecordPollTick(state.PollTick{Fetched: 1, Processed: 1}); err != nil {
		t.Fatalf("RecordPollTick (recovered): %v", err)
	}
	if got := call(); got.CheckpointHeldSince != "" {
		t.Fatalf("checkpointHeldSinceUtc = %q, want cleared once the checkpoint advanced", got.CheckpointHeldSince)
	}
}

// TestStatusCountsFailedMessagesNotAttempts pins what the "Failed (24h)" card
// means. A message deferred through a long classifier outage is retried every
// tick, so a count of attempts would report one stuck message as dozens.
func TestStatusCountsFailedMessagesNotAttempts(t *testing.T) {
	srv := newTestServer(t)
	u, err := users0(t, srv)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	store, err := state.New(srv.userStateDir(u.ID))
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}

	now := time.Now().UTC()
	for _, d := range []state.Decision{
		{MessageID: "1", Status: "failed", AtUTC: now.Add(-1 * time.Hour).Format(time.RFC3339)},
		{MessageID: "2", Status: "failed", AtUTC: now.Add(-2 * time.Hour).Format(time.RFC3339)},
		{MessageID: "3", Status: "classified", AtUTC: now.Add(-1 * time.Hour).Format(time.RFC3339)},
		{MessageID: "4", Status: "failed", AtUTC: now.Add(-72 * time.Hour).Format(time.RFC3339)},
	} {
		if err := store.AddDecision(d); err != nil {
			t.Fatalf("AddDecision: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.RemoteAddr = "127.0.0.1:41000"
	rec := httptest.NewRecorder()
	srv.handleStatus(rec, authedRequestForTest(req, u))
	var out struct {
		FailedLast24h int `json:"failedLast24h"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if out.FailedLast24h != 2 {
		t.Fatalf("failedLast24h = %d, want 2 (in-window failures only)", out.FailedLast24h)
	}
}
