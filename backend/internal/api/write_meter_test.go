package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kypost-server/backend/internal/users"
)

// TestWithMailAuthMetersMutatingRequests pins the bound withAuth applies and
// its sibling wrapper does not.
//
// accountWriteLimiter was deliberately placed at the WRAPPER rather than at the
// endpoints, so that — in the remediation commit's own words — "the next such
// route gets the bound without anyone remembering to ask for it". Three of the
// four wrappers never received it, so ~26 mail routes plus every device and
// CardDAV route accept an unbounded request rate. Those routes carry the
// expensive work in several other findings (rules/run, recipient resolution,
// pickup creation), so the missing meter is what removes their rate bound.
func TestWithMailAuthMetersMutatingRequests(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "metered", "irrelevant-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	token, csrf := mintSessionForTest(srv, u.ID)
	handler := srv.withMailAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	throttled := 0
	for i := 0; i < accountWriteBurst*3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/mail/send", nil)
		req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			throttled++
		}
	}
	if throttled == 0 {
		t.Fatalf("0 of %d mutating requests were throttled on withMailAuth; "+
			"withAuth throttles the same load", accountWriteBurst*3)
	}
}

// TestWithMailAuthDoesNotMeterReads is the control: GETs are untouched on
// withAuth and must stay untouched here, or opening a mailbox would throttle.
func TestWithMailAuthDoesNotMeterReads(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "reader", "irrelevant-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	token, csrf := mintSessionForTest(srv, u.ID)
	handler := srv.withMailAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for i := 0; i < accountWriteBurst*3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/inbox", nil)
		req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("read request %d was throttled", i)
		}
	}
}

// mintSessionForTest registers a live session and returns its cookie value and
// CSRF token, so a wrapper under test resolves the AuthContext itself instead
// of having one injected past its own resolution.
func mintSessionForTest(srv *Server, userID string) (string, string) {
	token := "session-" + userID
	csrf := "csrf-" + userID
	srv.sessMu.Lock()
	srv.sessions[token] = Session{
		UserID:    userID,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CSRFToken: csrf,
	}
	srv.sessMu.Unlock()
	_, _ = srv.users.ClearMustChangePassword(userID)
	return token, csrf
}
