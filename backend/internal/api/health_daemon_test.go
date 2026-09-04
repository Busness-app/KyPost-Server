package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/health"
)

// /api/health serves the API process's health, and under supervisord the poll
// daemon is a DIFFERENT process with its own health.Service. Everything the
// daemon observes therefore reached nobody: the endpoint reported the API's own
// copies of classifierFailing and nativePushFailing, which are permanently
// false because nothing in the API process classifies mail or sends a push.
//
// These drive the endpoint through the same shared state the daemon writes to.

func getHealth(t *testing.T, srv *Server) (int, health.Status) {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	var st health.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode health: %v (body=%s)", err, rec.Body.String())
	}
	return rec.Code, st
}

func TestHealthEndpointServesTheDaemonsView(t *testing.T) {
	srv := newTestServer(t)
	if srv.globalStore == nil {
		t.Fatal("test server has no shared state store to read the daemon report from")
	}
	srv.health.MarkHealthy()

	report := health.NewDaemonReport(health.Status{
		Healthy:           true,
		ClassifierFailing: true,
	}, time.Now())
	raw, err := report.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := srv.globalStore.SetDaemonHealth(raw); err != nil {
		t.Fatalf("SetDaemonHealth: %v", err)
	}

	code, st := getHealth(t, srv)

	if !st.ClassifierFailing {
		t.Fatal("the endpoint served the API's empty classifier field instead of the daemon's failure")
	}
	// A failing classifier is deliberately not a failing server: restarting
	// fixes nothing, and mail is still delivered.
	if code != http.StatusOK || !st.Healthy {
		t.Fatalf("a classifier failure took the whole server down: code=%d healthy=%v", code, st.Healthy)
	}
	if st.DaemonStale {
		t.Fatal("a heartbeat written just now was treated as stale")
	}
}

func TestHealthEndpointReportsAStoppedDaemon(t *testing.T) {
	srv := newTestServer(t)
	srv.health.MarkHealthy()

	report := health.NewDaemonReport(
		health.Status{Healthy: true},
		time.Now().Add(-health.DaemonHeartbeatMaxAge-time.Minute))
	raw, err := report.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := srv.globalStore.SetDaemonHealth(raw); err != nil {
		t.Fatalf("SetDaemonHealth: %v", err)
	}

	code, st := getHealth(t, srv)

	if !st.DaemonStale {
		t.Fatal("a daemon that stopped reporting was not marked stale")
	}
	if st.Healthy || code != http.StatusServiceUnavailable {
		t.Fatalf("a server whose poller is dead answered healthy: code=%d healthy=%v", code, st.Healthy)
	}
}

// The API process being fine is not the question the endpoint is asked. A
// server that has never heard from its daemon must not answer "healthy" — that
// is the state a fresh container is in, and also the state a container with a
// crash-looping daemon is in.
func TestHealthEndpointDoesNotReportHealthyWithNoDaemonNews(t *testing.T) {
	srv := newTestServer(t)
	srv.health.MarkHealthy()

	code, st := getHealth(t, srv)

	if st.Healthy || code != http.StatusServiceUnavailable {
		t.Fatalf("no daemon report read as healthy: code=%d healthy=%v", code, st.Healthy)
	}
	if !st.DaemonStale {
		t.Fatal("silence from the daemon was not reported as staleness")
	}
}

// A nil globalStore means state.New failed at startup for the directory the
// daemon keeps its checkpoints and per-user state in. Skipping the overlay
// there would answer "healthy" for a server that cannot see its daemon AND
// cannot read its own state — reintroducing the exact failure this endpoint was
// changed to stop telling, in the one case where the deployment is most broken.
func TestHealthEndpointFailsClosedWithNoSharedStore(t *testing.T) {
	srv := newTestServer(t)
	srv.health.MarkHealthy()
	srv.globalStore = nil

	code, st := getHealth(t, srv)

	if st.Healthy || code != http.StatusServiceUnavailable {
		t.Fatalf("an unreadable shared state store read as healthy: code=%d healthy=%v", code, st.Healthy)
	}
	if !st.DaemonStale {
		t.Fatal("a server that cannot read the daemon's report did not say so")
	}
}
