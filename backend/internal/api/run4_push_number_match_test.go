package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"kypost-server/backend/internal/mfa"
	"kypost-server/backend/internal/users"
)

// pushMFAUser creates a user with TOTP, a paired approver device, and push 2FA
// on — the state in which a number-match challenge is issued.
func pushMFAUser(t *testing.T, srv *Server, name, password, deviceName string) (userID, deviceID, deviceSecret string) {
	t.Helper()
	u, err := srv.users.Create(context.Background(), name, password, users.RoleUser)
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}
	enrollTOTP(t, srv, u.ID)
	deviceID, deviceSecret = pairApproverDevice(t, srv, u.ID, deviceName)
	enablePush(t, srv, u.ID)
	return u.ID, deviceID, deviceSecret
}

// run-4 M14 at the HTTP layer. The store-level rules are covered in
// internal/mfa; these pin the parts that only exist here: that the browser is
// told the number, and that the respond endpoint refuses an approval without it.

// TestPushNumberMatchAtTheHTTPLayer covers run-4 M14's HTTP surface: the browser
// is told the number, and the respond endpoint refuses an approval that does not
// carry it.
//
// One fixture for all four cases. Each used to build its own server and user,
// which is two scrypt derivations apiece at scryptN=1<<17 -- the first-run admin
// that users.LoadOrMigrate mints inside newTestServer, then the test's own
// users.Create -- roughly 3.5s per test before a single assertion ran. All four
// want the identical starting state (a user with TOTP, a paired approver device,
// push enabled) and none of them mutates it, so paying for it four times bought
// nothing.
//
// The loop resets the per-account state a login *does* touch, so the cases stay
// independent of each other and of their order: the push burst (mfaPushBurst is
// 3, so the fourth case would otherwise find push throttled and quietly stop
// being offered) and any challenge the previous case left behind.
func TestPushNumberMatchAtTheHTTPLayer(t *testing.T) {
	srv := newTestServer(t)
	const username, password = "rowan", "pw-rowan-testpassword"
	userID, deviceID, deviceSecret := pushMFAUser(t, srv, username, password, "dev-rowan")

	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		// The number must reach the browser, and it must be the challenge's real
		// value -- otherwise the human compares against something the server will
		// not accept.
		{"login returns the match digits", func(t *testing.T) {
			rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
				map[string]string{"username": username, "password": password})
			if rec.Code != http.StatusOK {
				t.Fatalf("login: status=%d body=%s", rec.Code, rec.Body.String())
			}

			var resp struct {
				ChallengeID string `json:"challengeId"`
				MatchDigits string `json:"matchDigits"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(resp.MatchDigits) != 2 {
				t.Fatalf("matchDigits = %q, want two digits for the browser to display", resp.MatchDigits)
			}

			ch, ok := srv.mfaChallenges.Get(resp.ChallengeID)
			if !ok {
				t.Fatal("challenge not found")
			}
			if ch.MatchDigits != resp.MatchDigits {
				t.Fatalf("login showed %q but the challenge holds %q", resp.MatchDigits, ch.MatchDigits)
			}
		}},

		// The core of M14: valid device credentials are no longer enough to
		// approve. An omitted number is a wrong number, and a wrong number is
		// terminal for push (see mfa.maxMatchAttempts).
		{"approval without the number locks push", func(t *testing.T) {
			challengeID, _ := loginChallenge(t, srv, username, password)

			rec := respondPushWithDigits(srv, challengeID, deviceID, deviceSecret, true, "")
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
			}
			if got := pollPush(srv, challengeID); got != mfa.PushLocked {
				t.Fatalf("push status = %q, want %q", got, mfa.PushLocked)
			}
		}},

		{"approval with the wrong number locks push and leaves TOTP", func(t *testing.T) {
			challengeID, _ := loginChallenge(t, srv, username, password)
			ch, ok := srv.mfaChallenges.Get(challengeID)
			if !ok {
				t.Fatal("challenge not found")
			}
			wrong := "00"
			if ch.MatchDigits == wrong {
				wrong = "11"
			}

			rec := respondPushWithDigits(srv, challengeID, deviceID, deviceSecret, true, wrong)
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
			}
			if got := pollPush(srv, challengeID); got != mfa.PushLocked {
				t.Fatalf("push status = %q, want %q", got, mfa.PushLocked)
			}

			// Locked, not approved: no session may be minted, and the correct
			// number does not reopen it.
			rec = respondPushWithDigits(srv, challengeID, deviceID, deviceSecret, true, ch.MatchDigits)
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("retry with the right number: status = %d, want %d", rec.Code, http.StatusTooManyRequests)
			}

			// But the challenge survives, so TOTP can still finish the sign-in.
			if _, ok := srv.mfaChallenges.Get(challengeID); !ok {
				t.Fatal("the challenge was destroyed; the TOTP fallback is unreachable")
			}
		}},

		// Denying must never require the number. Someone being MFA-fatigued is
		// looking at a challenge they cannot match and needs the safe answer to work.
		{"deny without the number is allowed", func(t *testing.T) {
			challengeID, _ := loginChallenge(t, srv, username, password)

			rec := respondPushWithDigits(srv, challengeID, deviceID, deviceSecret, false, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			if pollPush(srv, challengeID) != "denied" {
				t.Fatal("deny without a number did not take effect")
			}
		}},
	}

	for _, tc := range cases {
		srv.mfaPushLimiter = newMfaPushLimiter()
		srv.mfaChallenges.DeleteByUser(userID)
		t.Run(tc.name, tc.run)
	}
}

// A TOTP-only user is never sent a push, so there is no number to show and
// nothing should imply otherwise.
func TestLoginOmitsMatchDigitsForTOTPOnlyUser(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "sage", "pw-sage-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}
	enrollTOTP(t, srv, u.ID)

	rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
		map[string]string{"username": "sage", "password": "pw-sage-testpassword"})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := resp["matchDigits"]; present {
		t.Fatalf("a TOTP-only login advertised a match number: %s", rec.Body.String())
	}
}
