package health

import (
	"strings"
	"testing"
	"time"
)

// The API process and the poll daemon are two processes with two health
// services, and only the API's was ever served. Everything the daemon observes
// — whether mail can be fetched at all, whether the classifier answers, whether
// the push relay works — reached nobody, and the API's own untouched copies of
// those fields rendered as "false", which reads as "fine".

func reportJSON(t *testing.T, r DaemonReport) string {
	t.Helper()
	raw, err := r.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return raw
}

func TestMergeDaemonReportSurfacesDaemonSubsystems(t *testing.T) {
	now := time.Now().UTC()
	raw := reportJSON(t, DaemonReport{
		AtUTC:               now.Add(-20 * time.Second).Format(time.RFC3339),
		ClassifierFailing:   true,
		ClassifierFailingAt: "2026-08-02T10:00:00Z",
		NativePushFailing:   true,
		PollingHealthy:      true,
	})

	// The API's own status: healthy, and false for every field only the daemon
	// ever writes. This is exactly the state that used to be served.
	got := MergeDaemonReport(Status{Healthy: true}, raw, now)

	if !got.ClassifierFailing {
		t.Fatal("a failing classifier did not reach the served status")
	}
	if got.ClassifierFailingAt != "2026-08-02T10:00:00Z" {
		t.Fatalf("ClassifierFailingAt = %q", got.ClassifierFailingAt)
	}
	if !got.NativePushFailing {
		t.Fatal("a failing push relay did not reach the served status")
	}
	if got.DaemonStale {
		t.Fatal("a 20-second-old heartbeat was treated as stale")
	}
	// Neither subsystem flips Healthy: restarting the container fixes neither,
	// which is why they are reported separately in the first place.
	if !got.Healthy {
		t.Fatal("a subsystem failure flipped the overall healthy flag")
	}
}

// The API's zeroes must never win over the daemon's observations. They are the
// absence of an observation — nothing in the API process classifies mail — so
// OR-ing or preferring them re-creates the bug.
func TestMergeDaemonReportDoesNotLetTheAPIZeroesMaskTheDaemon(t *testing.T) {
	now := time.Now().UTC()
	raw := reportJSON(t, DaemonReport{
		AtUTC:             now.Format(time.RFC3339),
		ClassifierFailing: true,
		PollingHealthy:    true,
	})

	got := MergeDaemonReport(Status{Healthy: true, ClassifierFailing: false}, raw, now)
	if !got.ClassifierFailing {
		t.Fatal("the API's empty classifier field overwrote the daemon's failure")
	}
}

func TestMergeDaemonReportTreatsAStaleHeartbeatAsUnhealthy(t *testing.T) {
	now := time.Now().UTC()
	raw := reportJSON(t, DaemonReport{
		AtUTC:          now.Add(-DaemonHeartbeatMaxAge - time.Minute).Format(time.RFC3339),
		PollingHealthy: true,
	})

	got := MergeDaemonReport(Status{Healthy: true}, raw, now)

	if !got.DaemonStale {
		t.Fatal("an expired heartbeat was not marked stale")
	}
	if got.Healthy {
		t.Fatal("a dead poll daemon still reported a healthy server")
	}
	if len(got.FailureReason) == 0 {
		t.Fatal("nothing said why the server is unhealthy")
	}
}

// Absent and unparseable are the same answer: no usable news. Neither may read
// as health — "we have never heard from the daemon" is not "the daemon is fine".
func TestMergeDaemonReportTreatsMissingNewsAsUnhealthy(t *testing.T) {
	for _, raw := range []string{"", "   ", "not json", `{"classifierFailing":true}`} {
		got := MergeDaemonReport(Status{Healthy: true}, raw, time.Now().UTC())
		if got.Healthy || !got.DaemonStale {
			t.Fatalf("report %q reported a healthy server: healthy=%v stale=%v", raw, got.Healthy, got.DaemonStale)
		}
	}
}

// A report with no timestamp cannot be aged, and a report that cannot be aged
// cannot be trusted — otherwise a daemon that wrote once and died reads as live
// forever.
func TestDecodeDaemonReportRejectsAnUndateableReport(t *testing.T) {
	if _, ok := DecodeDaemonReport(`{"atUtc":"","classifierFailing":true}`); ok {
		t.Fatal("accepted a report with no timestamp")
	}
	if _, ok := DecodeDaemonReport(`{"atUtc":"not-a-date"}`); !ok {
		t.Fatal("a malformed timestamp should decode and then age out, not vanish")
	}
	r, _ := DecodeDaemonReport(`{"atUtc":"not-a-date"}`)
	if r.Age(time.Now()) <= DaemonHeartbeatMaxAge {
		t.Fatal("an unparseable timestamp aged as fresh")
	}
}

// The daemon's own verdict on whether it can reach ANY mailbox is the one thing
// it reports that does flip Healthy: a server that cannot poll mail is not a
// healthy mail server, however well its HTTP handlers are answering.
func TestMergeDaemonReportFailsWhenNoMailboxIsReachable(t *testing.T) {
	now := time.Now().UTC()
	raw := reportJSON(t, DaemonReport{
		AtUTC:          now.Format(time.RFC3339),
		PollingHealthy: false,
		FailureReason:  []string{"imap unreachable for all users"},
	})

	got := MergeDaemonReport(Status{Healthy: true}, raw, now)
	if got.Healthy {
		t.Fatal("an unreachable mailbox still reported a healthy server")
	}
	if !strings.Contains(strings.Join(got.FailureReason, " "), "imap unreachable") {
		t.Fatalf("the daemon's reason was dropped: %v", got.FailureReason)
	}
}

// Round trip through the shape the daemon actually writes.
func TestNewDaemonReportCarriesWhatTheAPICannotSee(t *testing.T) {
	svc := NewService()
	svc.MarkHealthy()
	svc.RecordClassifierFailure()
	svc.RecordNativePushFailure("relay refused")
	svc.SetAICreditsExhausted("2026-08-02T09:00:00Z")

	raw := reportJSON(t, NewDaemonReport(svc.GetStatus(), time.Now()))
	got := MergeDaemonReport(Status{Healthy: true}, raw, time.Now())

	if !got.ClassifierFailing || !got.NativePushFailing || !got.AICreditsExhausted {
		t.Fatalf("a subsystem was lost in the round trip: %+v", got)
	}
	if got.NativePushLastError != "relay refused" {
		t.Fatalf("NativePushLastError = %q", got.NativePushLastError)
	}
}
