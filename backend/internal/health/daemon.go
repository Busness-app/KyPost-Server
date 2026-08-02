package health

import (
	"encoding/json"
	"strings"
	"time"
)

// Cross-process health.
//
// health.Service is in-memory, and under supervisord this server runs as TWO
// processes: `--mode server` (the API) and `--mode daemon` (the poller). Each
// builds its own Service (app.go), and only the API's is served by /api/health.
// Everything the daemon observes therefore reached nothing: the classifier
// flag, the native-push relay flag and the poller's own liveness are all
// recorded in a Service no HTTP handler can see. The health page rendered
// `classifierFailing: false` because it was reading the API's copy of a field
// only the daemon ever writes — not "classification is fine", but "nobody
// here has ever tried to classify anything".
//
// So the daemon writes a DaemonReport to shared state each heartbeat and the
// API overlays it onto what it serves. The heartbeat is what makes the absence
// of news distinguishable from good news: a report that has stopped arriving is
// a daemon that is wedged or gone, and it reads as unhealthy rather than as
// silence.
//
// In `--mode all` (single binary, both halves in one process) the two share one
// Service, the daemon half still writes reports, and the overlay puts back the
// values that are already there. Same code path, same answer.

// DaemonHeartbeatMaxAge is how stale a report may be before the daemon counts
// as unavailable.
//
// Well above the default 90s scan interval AND above tickTimeout (8 minutes),
// because a heartbeat is not written by the tick: a tick that legitimately runs
// long must not be reported as a dead daemon. The poller writes on its own
// ticker (daemonHeartbeatInterval) precisely so this stays a liveness signal
// rather than a throughput one.
const DaemonHeartbeatMaxAge = 5 * time.Minute

// DaemonReport is the subsystem health one process observed at a point in time.
//
// Deliberately not health.Status: Status carries the API's own HTTP-facing
// judgement (Healthy, UnhealthyFor, FailureReason) which is not the daemon's to
// assert. This is only the part the daemon is the sole observer of.
type DaemonReport struct {
	AtUTC string `json:"atUtc"`

	ClassifierFailing   bool   `json:"classifierFailing"`
	ClassifierFailingAt string `json:"classifierFailingAt,omitempty"`

	NativePushFailing     bool   `json:"nativePushFailing"`
	NativePushLastError   string `json:"nativePushLastError,omitempty"`
	NativePushFailingAt   string `json:"nativePushFailingAt,omitempty"`
	NativePushLastSuccess string `json:"nativePushLastSuccessUtc,omitempty"`

	AICreditsExhausted   bool   `json:"aiCreditsExhausted"`
	AICreditsExhaustedAt string `json:"aiCreditsExhaustedAt,omitempty"`

	// PollingHealthy is the daemon's own verdict on whether it can reach the
	// mailboxes it polls — MarkUnhealthy("imap unreachable for all users") and
	// friends. Carried separately from the API's Healthy so the API can fail
	// its own health check on it without the daemon being able to assert
	// anything about the HTTP server it does not run.
	PollingHealthy bool     `json:"pollingHealthy"`
	FailureReason  []string `json:"failureReason,omitempty"`
}

// NewDaemonReport snapshots the parts of st the daemon is the sole observer of.
func NewDaemonReport(st Status, at time.Time) DaemonReport {
	return DaemonReport{
		AtUTC:                 at.UTC().Format(time.RFC3339),
		ClassifierFailing:     st.ClassifierFailing,
		ClassifierFailingAt:   st.ClassifierFailingAt,
		NativePushFailing:     st.NativePushFailing,
		NativePushLastError:   st.NativePushLastError,
		NativePushFailingAt:   st.NativePushFailingAt,
		NativePushLastSuccess: st.NativePushLastSuccess,
		AICreditsExhausted:    st.AICreditsExhausted,
		AICreditsExhaustedAt:  st.AICreditsExhaustedAt,
		PollingHealthy:        st.Healthy,
		FailureReason:         st.FailureReason,
	}
}

// Encode renders the report for storage.
func (r DaemonReport) Encode() (string, error) {
	b, err := json.Marshal(r)
	return string(b), err
}

// DecodeDaemonReport parses a stored report. ok is false for an empty or
// unparseable record, which both mean the same thing to the caller: no usable
// news from the daemon.
func DecodeDaemonReport(raw string) (DaemonReport, bool) {
	if strings.TrimSpace(raw) == "" {
		return DaemonReport{}, false
	}
	var r DaemonReport
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return DaemonReport{}, false
	}
	if strings.TrimSpace(r.AtUTC) == "" {
		// A report with no timestamp cannot be aged, and a report that cannot
		// be aged cannot be trusted — that is the whole mechanism.
		return DaemonReport{}, false
	}
	return r, true
}

// Age reports how long ago the report was written. A timestamp that will not
// parse yields a duration large enough to count as stale, rather than a zero
// that would read as "just now".
func (r DaemonReport) Age(now time.Time) time.Duration {
	at, err := time.Parse(time.RFC3339, strings.TrimSpace(r.AtUTC))
	if err != nil {
		return DaemonHeartbeatMaxAge + time.Hour
	}
	return now.UTC().Sub(at.UTC())
}

// MergeDaemonReport overlays the daemon's view onto the status the API serves.
//
// raw is whatever was found in shared state, including "" for nothing at all.
// Absent and stale are treated identically and both flip Healthy: the API
// process being fine says nothing about whether mail is being polled, labelled
// or pushed, and reporting "healthy" on that basis is what let a container run
// for days with a dead poller behind a green tick.
//
// It replaces rather than merges the subsystem flags. The API's own copies of
// them are always zero — nothing in the API process classifies mail or sends a
// native push — so "false" there is the absence of an observation, not an
// observation of health, and OR-ing the two would let it mask the daemon's.
func MergeDaemonReport(st Status, raw string, now time.Time) Status {
	report, ok := DecodeDaemonReport(raw)
	if !ok {
		st.DaemonStale = true
		st.Healthy = false
		st.FailureReason = append(st.FailureReason, "daemon has not reported its health")
		return st
	}

	st.DaemonHeartbeatUTC = report.AtUTC
	st.ClassifierFailing = report.ClassifierFailing
	st.ClassifierFailingAt = report.ClassifierFailingAt
	st.NativePushFailing = report.NativePushFailing
	st.NativePushLastError = report.NativePushLastError
	st.NativePushFailingAt = report.NativePushFailingAt
	st.NativePushLastSuccess = report.NativePushLastSuccess
	st.AICreditsExhausted = report.AICreditsExhausted
	st.AICreditsExhaustedAt = report.AICreditsExhaustedAt

	if age := report.Age(now); age > DaemonHeartbeatMaxAge {
		st.DaemonStale = true
		st.Healthy = false
		st.FailureReason = append(st.FailureReason,
			"daemon last reported "+age.Round(time.Second).String()+" ago")
		return st
	}

	// A daemon that cannot reach any mailbox is an unhealthy server even though
	// the API answering this request is fine. This is the signal that used to
	// exist only inside the daemon process.
	if !report.PollingHealthy {
		st.Healthy = false
		st.FailureReason = append(st.FailureReason, report.FailureReason...)
	}
	return st
}
