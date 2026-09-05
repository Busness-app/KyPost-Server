package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// plantLegacyPasswordHash writes a scrypt hash straight into users.json, the
// way an install that has not signed in since the Argon2id migration actually
// looks. There is no exported Store method for writing an arbitrary hash, on
// purpose.
func plantLegacyPasswordHash(t *testing.T, srv *Server, userID, password string) {
	t.Helper()
	legacy, err := users.LegacyScryptHashForTest(context.Background(), password)
	if err != nil {
		t.Fatalf("LegacyScryptHashForTest: %v", err)
	}
	usersPath := filepath.Join(srv.configDir, "users.json")
	raw, err := os.ReadFile(usersPath)
	if err != nil {
		t.Fatalf("read users.json: %v", err)
	}
	var file struct {
		Version int              `json:"version"`
		Users   []map[string]any `json:"users"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("unmarshal users.json: %v", err)
	}
	planted := false
	for _, entry := range file.Users {
		if entry["id"] == userID {
			entry["passwordHash"] = legacy
			planted = true
		}
	}
	if !planted {
		t.Fatalf("user %q not found in users.json", userID)
	}
	out, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal users.json: %v", err)
	}
	if err := os.WriteFile(usersPath, out, 0o600); err != nil {
		t.Fatalf("write users.json: %v", err)
	}
	stored, err := srv.users.Get(userID)
	if err != nil {
		t.Fatalf("Get after planting: %v", err)
	}
	if !users.NeedsRehash(stored.PasswordHash) {
		t.Fatal("planted hash does not report as needing a rehash")
	}
}

// timingSamples is how many attempts each case makes. The MINIMUM is kept:
// that is the figure an attacker gets by repeating, and it is the statistic
// least polluted by a scheduler hiccup.
const timingSamples = 3

// fastest runs attempt timingSamples times and returns the shortest.
// Each call gets its own source address so the per-(username, IP) lockout
// (three strikes) never fires and never becomes the thing being measured.
func fastest(t *testing.T, name string, attempt func(remoteAddr string)) time.Duration {
	t.Helper()
	best := time.Duration(1<<63 - 1)
	for i := range timingSamples {
		addr := fmt.Sprintf("203.0.113.%d:40000", 100+i)
		start := time.Now()
		attempt(addr)
		if d := time.Since(start); d < best {
			best = d
		}
	}
	t.Logf("%s: %v", name, best)
	return best
}

// assertTimingSpread fails when the slowest case is more than a small multiple
// of the fastest. A RATIO rather than an absolute band, because the floor is
// measured from this machine's own scrypt cost and an absolute millisecond
// figure would be a statement about the CI runner instead of about the code.
func assertTimingSpread(t *testing.T, timings map[string]time.Duration) {
	t.Helper()
	const maxRatio = 1.5
	var slowest, quickest time.Duration
	var slowestName, quickestName string
	for name, d := range timings {
		if slowest == 0 || d > slowest {
			slowest, slowestName = d, name
		}
		if quickest == 0 || d < quickest {
			quickest, quickestName = d, name
		}
	}
	if ratio := float64(slowest) / float64(quickest); ratio > maxRatio {
		t.Fatalf("credential-check timing spread %.2fx (%s %v vs %s %v), want under %.1fx — "+
			"response timing tells an anonymous caller which accounts exist",
			ratio, slowestName, slowest, quickestName, quickest, maxRatio)
	}
}

// TestLoginTimingDoesNotRevealUnknownUsernames is the account-enumeration
// regression, and it plants a LEGACY hash on purpose.
//
// The old version compared an unknown username against an account the test had
// just created — Argon2id on both sides, so it could not fail on the bug it was
// named for. Once two hash formats coexist, the expensive side is the account
// that has NOT signed in since the migration: a legacy scrypt verify costs
// several times the always-Argon2id equalization dummy, and that gap is
// permanent for exactly the dormant accounts an attacker wants to find.
// settleCredentialTiming pads all three outcomes to one floor; without it this
// test sees the raw ratio between the two KDFs.
func TestLoginTimingDoesNotRevealUnknownUsernames(t *testing.T) {
	srv := newTestServer(t)
	const pw = "correct-horse-battery-staple"
	modern, err := srv.users.Create(context.Background(), "timing-argon2id", pw, users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	legacy, err := srv.users.Create(context.Background(), "timing-legacy", pw, users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	plantLegacyPasswordHash(t, srv, legacy.ID, pw)

	wrongPassword := func(username string) func(string) {
		return func(addr string) {
			if rec := loginAttempt(srv, username, "wrong-password", addr); rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s: status = %d, want 401", username, rec.Code)
			}
		}
	}
	assertTimingSpread(t, map[string]time.Duration{
		"argon2id account":      fastest(t, "argon2id account", wrongPassword(modern.Username)),
		"legacy scrypt account": fastest(t, "legacy scrypt account", wrongPassword(legacy.Username)),
		"unknown username":      fastest(t, "unknown username", wrongPassword("no-such-user-anywhere")),
	})
}

// TestDAVAuthTimingDoesNotRevealUsernames is the same oracle on the CardDAV
// surface, where the comment used to claim the always-Argon2id dummy was what
// kept the skew out of the comparison — it was the mechanism by which the skew
// leaked. A wrong password against an account whose app-password file still
// holds a scrypt hash must not be distinguishable from an unknown username.
func TestDAVAuthTimingDoesNotRevealUsernames(t *testing.T) {
	srv := newTestServer(t)

	modern, err := srv.users.Create(context.Background(), "dav-timing-argon2id", "pw-dav-timing-argon2id-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	modernHash, err := users.HashPassword(context.Background(), "app-password-modern")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := srv.writeDAVPassword(modern.ID, davPasswordFile{Hash: modernHash}); err != nil {
		t.Fatalf("writeDAVPassword: %v", err)
	}

	legacy, err := srv.users.Create(context.Background(), "dav-timing-legacy", "pw-dav-timing-legacy-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	legacyHash, err := users.LegacyScryptHashForTest(context.Background(), "app-password-legacy")
	if err != nil {
		t.Fatalf("LegacyScryptHashForTest: %v", err)
	}
	if err := srv.writeDAVPassword(legacy.ID, davPasswordFile{Hash: legacyHash}); err != nil {
		t.Fatalf("writeDAVPassword: %v", err)
	}

	handler := srv.withDAVBasicAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a wrong app password reached the handler")
	}))
	wrongPassword := func(username string) func(string) {
		return func(addr string) {
			req := httptest.NewRequest("PROPFIND", davPrefix+"/"+username+"/", nil)
			req.SetBasicAuth(username, "not-the-app-password")
			req.RemoteAddr = addr
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s: status = %d, want 401", username, rec.Code)
			}
		}
	}
	assertTimingSpread(t, map[string]time.Duration{
		"argon2id app password": fastest(t, "argon2id app password", wrongPassword(modern.Username)),
		"legacy app password":   fastest(t, "legacy app password", wrongPassword(legacy.Username)),
		"unknown username":      fastest(t, "unknown username", wrongPassword("no-such-user-anywhere")),
		"no app password":       fastest(t, "no app password", wrongPassword("admin")),
	})
}
