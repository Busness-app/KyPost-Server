// The pre-login handshake that tells a browser how to derive its auth secret.
//
// This exists so the password never has to leave the browser: the client
// stretches it with the salt from here, splits the result into an authentication
// half and a key-wrapping half (see frontend/src/lib/authSecret.ts and
// keyVault.ts), and sends only the authentication half. POSTing the plaintext
// password on every sign-in while keyVault.ts derived the PGP vault key from
// that same password made the "the server cannot open your key" claim false by
// construction.
package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"

	"kypost-server/backend/internal/users"
)

// clientLoginIterations is the PBKDF2 work factor this server asks new clients
// to use. It matches keyVault.ts's DEFAULT_ITERATIONS (the OWASP figure for
// PBKDF2-HMAC-SHA256), so one stretch serves both halves.
//
// Advisory: the client reports back what it actually used and the store bounds
// it (users.MinLoginIterations). Raising this affects new credentials only.
const clientLoginIterations = 600_000

// handleLoginParams returns the salt and work factor a client must use to derive
// its auth secret for a given username. Public and unauthenticated: it runs
// before any credential exists.
//
// IT MUST NOT REVEAL WHETHER THE ACCOUNT EXISTS. A real account returns its
// stored salt; a nonexistent account, or a legacy one not yet converted, returns
// a synthetic salt derived from the instance secret and the username. All three
// are 16 random-looking bytes with no distinguishing shape, and the synthetic
// one is stable across requests, so asking twice does not out it either.
//
// The response deliberately carries no "derivation" or "legacy" field: once
// every account has converted, "legacy" would mean "no such user". The client
// always derives and always sends the auth secret, and additionally sends the
// plaintext only while it still has to — see handleLogin.
func (s *Server) handleLoginParams(w http.ResponseWriter, r *http.Request) {
	// Metered per IP, in requests. This endpoint performs no derivation, so charging
	// it a full attempt's reservation against the INSTANCE-WIDE derivation budget
	// priced a ~5us HMAC at 0.2 core-seconds: sixteen free requests emptied that
	// bucket and denied sign-in to every user, from any single address, with no
	// per-IP proxy rule able to restore it.
	if s.loginParamsLimiter != nil {
		if ok, _ := s.loginParamsLimiter.allow(clientIP(r)); !ok {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": "too many sign-in attempts right now, try again shortly",
			})
			return
		}
	}

	username := strings.TrimSpace(r.URL.Query().Get("username"))
	// With no username, answer for the authenticated caller. That is what the
	// re-authentication flows need (disabling TOTP, exporting a legacy key): they
	// already have a session, and making them echo their own username back invites a
	// caller to pass someone else's. Falling through to the synthetic salt for the
	// empty string would hand them a salt that cannot reproduce their credential.
	if username == "" {
		if ac, ok := s.currentUser(r); ok {
			username = ac.Username
		}
	}
	salt, iterations := s.loginParamsFor(username)
	writeJSON(w, http.StatusOK, map[string]any{
		"salt":       salt,
		"iterations": iterations,
	})
}

// loginParamsFor resolves the salt and iteration count for a username, without
// disclosing whether it names a real account.
func (s *Server) loginParamsFor(username string) (salt string, iterations int) {
	if u, err := s.users.GetByUsername(username); err == nil && u.UsesDerivedAuth() && u.LoginSalt != "" {
		it := u.LoginIterations
		// Clamped at BOTH ends. The floor has always been here; the ceiling
		// matters because the client refuses to derive above
		// MaxLoginIterations, so serving a stored value past it hands the
		// browser a parameter it will reject and locks the account out of
		// itself. The store now rejects such a value on write — this covers
		// anything already persisted, and costs nothing.
		if it < users.MinLoginIterations || it > users.MaxLoginIterations {
			it = clientLoginIterations
		}
		return u.LoginSalt, it
	}
	return s.syntheticLoginSalt(username), clientLoginIterations
}

// syntheticLoginSalt derives a stable, per-username salt for any username this
// server cannot (or will not) hand a real one for. Keyed on the instance's
// pairing secret so it is unguessable without server access, and deterministic
// so repeated requests for the same username agree — a salt that changed per
// request would be a louder existence oracle than returning nothing at all.
//
// It is also the salt a legacy account's first derived credential ends up pinned
// to: the client derives with whatever this returns, and the upgrade in
// handleLogin recomputes and stores that same value. The domain string and the
// fold must not change without a migration, since changing either invalidates
// every credential derived against it.
//
// Falls back to a fixed key when no pairing secret is configured: with no
// secret the salt is merely non-secret, and a salt's job is uniqueness, not
// secrecy.
func (s *Server) syntheticLoginSalt(username string) string {
	key := []byte(s.pairingSecret)
	if len(key) == 0 {
		key = []byte("kypost-login-salt-fallback")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("kypost/login-salt/v1|"))
	mac.Write([]byte(users.NormalizeUsername(username)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// verifyAccountCredential checks a re-authentication request against whichever
// credential form the account actually stores. Shared by every endpoint that
// re-verifies the account password before doing something sensitive (disabling
// TOTP, exporting a legacy private key). The account decides which form is
// checked, never the request: the derivation salt is public, so letting a caller
// choose "check this as a password" against a derived-auth account would let
// them authenticate with a value computed from the salt alone.
//
// The (bool, error) split is the caller's cue: an error means the credential
// was NOT checked (the derivation slots were saturated, or the client hung up),
// so the caller must answer 503 and must not spend a lockout strike. Folding it
// into false would report overload as "wrong password" and, on the flows that
// take a strike, lock the account out of its own remediation during a spike.
func verifyAccountCredential(ctx context.Context, u users.User, password, authSecret string) (bool, error) {
	if u.UsesDerivedAuth() {
		return users.VerifyAuthSecret(ctx, u, authSecret)
	}
	return users.VerifyPassword(ctx, u, password)
}
