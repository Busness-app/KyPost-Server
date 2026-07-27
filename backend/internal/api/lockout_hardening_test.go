package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kypost-server/backend/internal/users"
)

func loginAttempt(srv *Server, username, password, remoteAddr string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	srv.handleLogin(rec, req)
	return rec
}

// A lockout must apply only to the (username, client IP) pair that earned it:
// otherwise anyone who knows a username can lock the real owner out at will
// from a different machine.
func TestLoginLockoutScopedToClientIP(t *testing.T) {
	srv := newTestServer(t)

	for i := 0; i < loginMaxFailures; i++ {
		if rec := loginAttempt(srv, "victim", "wrong", "203.0.113.10:40000"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want %d", i+1, rec.Code, http.StatusUnauthorized)
		}
	}
	if rec := loginAttempt(srv, "victim", "wrong", "203.0.113.10:40000"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("same IP after threshold: status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if rec := loginAttempt(srv, "victim", "wrong", "198.51.100.7:40000"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("different IP: status = %d, want %d (a lockout earned by one IP must not lock the account for everyone)", rec.Code, http.StatusUnauthorized)
	}
}

func TestFailureLockoutCustomThreshold(t *testing.T) {
	l := newFailureLockout(2, time.Minute)
	_, _ = l.tryAttempt("key")
	if ok, _ := l.allowed("key"); !ok {
		t.Fatal("one failure below a threshold of two must not lock")
	}
	_, _ = l.tryAttempt("key")
	ok, retryAfter := l.allowed("key")
	if ok {
		t.Fatal("expected lockout after reaching the custom threshold")
	}
	if retryAfter <= 0 || retryAfter > time.Minute {
		t.Fatalf("retryAfter = %v, want a positive duration <= 1m", retryAfter)
	}
}

func davRequest(srv *Server, username, password, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, davPrefix+"/", nil)
	req.SetBasicAuth(username, password)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	return rec
}

// The DAV surface authenticates with scrypt-verified Basic Auth on every
// request; without a lockout each guess costs the server a full scrypt run
// (CPU DoS) with no cap, unlike the login endpoint.
func TestDAVAuthLockoutAfterRepeatedFailures(t *testing.T) {
	srv := newTestServer(t)

	for i := 0; i < davMaxFailures; i++ {
		if rec := davRequest(srv, "nobody", "guess", "203.0.113.20:40000"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want %d", i+1, rec.Code, http.StatusUnauthorized)
		}
	}
	if rec := davRequest(srv, "nobody", "guess", "203.0.113.20:40000"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("same IP after threshold: status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if rec := davRequest(srv, "nobody", "guess", "198.51.100.9:40000"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("different IP: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDAVAuthSuccessClearsLockoutHistory(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	u := all[0]
	hash, err := users.HashPassword("dav-app-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := srv.writeDAVPassword(u.ID, davPasswordFile{Hash: hash, CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatalf("writeDAVPassword: %v", err)
	}

	const ip = "203.0.113.30:40000"
	for i := 0; i < davMaxFailures-1; i++ {
		if rec := davRequest(srv, u.Username, "wrong", ip); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want %d", i+1, rec.Code, http.StatusUnauthorized)
		}
	}
	if rec := davRequest(srv, u.Username, "dav-app-password", ip); rec.Code == http.StatusUnauthorized || rec.Code == http.StatusTooManyRequests {
		t.Fatalf("correct password below threshold: status = %d, want an authenticated response", rec.Code)
	}
	// The success must have reset the strike count: a single further failure
	// alone must not trip the lockout.
	if rec := davRequest(srv, u.Username, "wrong", ip); rec.Code != http.StatusUnauthorized {
		t.Fatalf("failure after success: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
