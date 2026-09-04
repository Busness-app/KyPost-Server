package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// totpCodeForTest independently computes a 6-digit TOTP for a base32 secret at
// time t, mirroring RFC 6238. Used to drive the real handlers and to
// cross-check the production totp package.
func totpCodeForTest(t *testing.T, base32Secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(base32Secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	counter := uint64(at.Unix() / 30)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", bin%1_000_000)
}

// totpStep mirrors internal/totp's unexported `period`. A TOTP code names a
// step, not an instant, so a test that mints one and a server that checks it
// agree only while both read the same step.
const totpStep = 30 * time.Second

// totpStepAt reports the step counter an instant falls in — the same
// t.Unix()/period totp.Validate computes. Tests use it to tell "the code was
// wrong" apart from "the code aged out between minting and checking".
func totpStepAt(at time.Time) int64 { return at.Unix() / int64(totpStep/time.Second) }

// testPasswordFor reconstructs a test account's password from the
// pw-<username>-testpassword convention every test in this package uses.
func testPasswordFor(t *testing.T, srv *Server, userID string) string {
	t.Helper()
	u, err := srv.users.Get(userID)
	if err != nil {
		t.Fatalf("get user %s: %v", userID, err)
	}
	return "pw-" + u.Username + "-testpassword"
}

// enrollTOTP runs setup + confirm for userID and returns the base32 secret and
// the recovery codes.
func enrollTOTP(t *testing.T, srv *Server, userID string) (secret string, recoveryCodes []string) {
	t.Helper()

	setupReq := httptest.NewRequest(http.MethodPost, "/api/mfa/totp/setup", nil)
	authRequestAs(srv, setupReq, userID)
	setupRec := httptest.NewRecorder()
	srv.withAuth(srv.handleMFASetup)(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup: status=%d body=%s", setupRec.Code, setupRec.Body.String())
	}
	var setupResp struct {
		Secret     string `json:"secret"`
		OtpauthURI string `json:"otpauthUri"`
	}
	if err := json.Unmarshal(setupRec.Body.Bytes(), &setupResp); err != nil {
		t.Fatalf("unmarshal setup: %v", err)
	}
	if setupResp.Secret == "" || setupResp.OtpauthURI == "" {
		t.Fatalf("setup response missing fields: %s", setupRec.Body.String())
	}

	// Confirming re-authenticates: enrolling a factor is gated the same way
	// removing one is. Test accounts all use the pw-<username>-testpassword
	// convention, so the helper derives it rather than every caller passing it.
	// Resolved before the loop so no user lookup sits inside the window below.
	password := testPasswordFor(t, srv, userID)

	// The code is deliberately the PREVIOUS step's, and this retries once if the
	// clock rolls into a new step underneath the request.
	//
	// Previous rather than current because handleMFAConfirm records
	// LastUsedTOTPStep (see TestTOTPConfirmCodeCannotReplayAgainstLoginChallenge)
	// and the per-account replay guard refuses any step at or below it.
	// Consuming the current step would make whatever code a test computes
	// immediately afterwards via time.Now() unusable -- a same-instant test
	// artifact, not a real user scenario, since a real user confirming
	// enrolment is not simultaneously mid-login. The NEXT step is not an option
	// for the mirror-image reason: it would consume a step above the one the
	// test is about to use.
	//
	// So exactly one step is usable, and it carries no forward margin.
	// totp.Validate accepts t-1, t and t+1, so a code minted for step S-1 is
	// accepted only while the server's own clock still reads step S. Confirm
	// re-authenticates the password, which puts a full scrypt between minting
	// the code and validating it -- hundreds of milliseconds in CI under -race.
	// Mint in the tail of a step and the server reads S+1, the code is two steps
	// back, and confirm answers "invalid code". It did, intermittently, in CI.
	//
	// Retrying is the correct response rather than a papering-over: the server
	// was right, the code really had expired. That path consumes nothing -- the
	// 401 returns before SetLastUsedTOTPStep, TOTPSecretEnc is untouched and
	// TOTPEnabled stays false -- and the password verified, so loginLockout
	// recorded a success rather than a strike. One retry is provably enough: it
	// starts immediately after a boundary, so it has a full step to run in.
	var confirmRec *httptest.ResponseRecorder
	for range 2 {
		mintedIn := totpStepAt(time.Now())
		confirmRec = doJSONAuth(srv, srv.withAuth(srv.handleMFAConfirm), http.MethodPost,
			"/api/mfa/totp/confirm", map[string]string{
				"code":     totpCodeForTest(t, setupResp.Secret, time.Now().Add(-totpStep)),
				"password": password,
			}, userID)
		// Anything but a step rollover is the real answer, pass or fail.
		if confirmRec.Code == http.StatusOK || totpStepAt(time.Now()) == mintedIn {
			break
		}
	}
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("confirm: status=%d body=%s", confirmRec.Code, confirmRec.Body.String())
	}
	var confirmResp struct {
		Ok            bool     `json:"ok"`
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	if err := json.Unmarshal(confirmRec.Body.Bytes(), &confirmResp); err != nil {
		t.Fatalf("unmarshal confirm: %v", err)
	}
	if !confirmResp.Ok || len(confirmResp.RecoveryCodes) != recoveryCodeCount {
		t.Fatalf("confirm response unexpected: %s", confirmRec.Body.String())
	}
	return setupResp.Secret, confirmResp.RecoveryCodes
}

// doJSONAuth is doJSON plus an injected session for userID, including the
// matching X-CSRF-Token header a real browser client would send (see
// authRequestAs/csrfCheckOK) — without it every mutating request would be
// rejected with 403 regardless of the test's own assertions.
func doJSONAuth(srv *Server, handler http.HandlerFunc, method, path string, payload any, userID string) *httptest.ResponseRecorder {
	token := "session-token-" + userID
	csrfToken := "csrf-token-" + userID
	srv.sessMu.Lock()
	srv.sessions[token] = Session{UserID: userID, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: csrfToken}
	srv.sessMu.Unlock()
	// Model an onboarded session; the must-change gate (withAuth) is exercised
	// by its own dedicated test.
	_, _ = srv.users.ClearMustChangePassword(userID)

	var body *bytes.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	} else {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, body)
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
	req.Header.Set("X-CSRF-Token", csrfToken)
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func TestTOTPEnrollmentAndLoginFlow(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "erin", "pw-erin-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	secret, _ := enrollTOTP(t, srv, u.ID)

	// Password login now returns an MFA challenge, NOT a session cookie.
	loginRec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
		map[string]string{"username": "erin", "password": "pw-erin-testpassword"})
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
	if cookies := loginRec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("expected no session cookie on MFA-required login, got %+v", cookies)
	}
	var login struct {
		MFARequired bool     `json:"mfaRequired"`
		ChallengeID string   `json:"challengeId"`
		Methods     []string `json:"methods"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &login); err != nil {
		t.Fatalf("unmarshal login: %v", err)
	}
	if !login.MFARequired || login.ChallengeID == "" {
		t.Fatalf("expected mfaRequired challenge, got %s", loginRec.Body.String())
	}

	// Second factor mints the real session.
	code := totpCodeForTest(t, secret, time.Now())
	totpRec := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": login.ChallengeID, "code": code})
	if totpRec.Code != http.StatusOK {
		t.Fatalf("mfa/totp: status=%d body=%s", totpRec.Code, totpRec.Body.String())
	}
	cookies := totpRec.Result().Cookies()
	if findCookie(cookies, "kypost_session") == nil {
		t.Fatalf("expected a kypost_session cookie after second factor, got %+v", cookies)
	}

	// Replay: reusing the same challenge is rejected.
	replayRec := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": login.ChallengeID, "code": totpCodeForTest(t, secret, time.Now())})
	if replayRec.Code != http.StatusUnauthorized {
		t.Fatalf("replay: status=%d, want 401", replayRec.Code)
	}
}

// TestTOTPPerAccountReplayGuard proves replay protection is scoped to the
// account, not just a single challenge: a captured valid code cannot be
// replayed against a freshly minted challenge, a genuinely later code still
// works normally, and a wrong code never advances the recorded step (so the
// user can still retry the current step correctly).
func TestTOTPPerAccountReplayGuard(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "ivy", "pw-ivy-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	secret, _ := enrollTOTP(t, srv, u.ID)

	newChallenge := func() string {
		t.Helper()
		loginRec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
			map[string]string{"username": "ivy", "password": "pw-ivy-testpassword"})
		var login struct {
			ChallengeID string `json:"challengeId"`
		}
		if err := json.Unmarshal(loginRec.Body.Bytes(), &login); err != nil {
			t.Fatalf("unmarshal login: %v", err)
		}
		if login.ChallengeID == "" {
			t.Fatalf("expected a challengeId, got %s", loginRec.Body.String())
		}
		return login.ChallengeID
	}

	// (a) A valid TOTP code works once.
	firstCode := totpCodeForTest(t, secret, time.Now())
	ch1 := newChallenge()
	rec1 := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": ch1, "code": firstCode})
	if rec1.Code != http.StatusOK {
		t.Fatalf("(a) first use: status=%d body=%s", rec1.Code, rec1.Body.String())
	}

	// (b) Replaying that SAME code (same step) is rejected even against a
	// brand-new challenge — this is the per-account guard; the per-challenge
	// guard alone would let it through since ch2 never saw this code before.
	ch2 := newChallenge()
	rec2 := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": ch2, "code": firstCode})
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("(b) cross-challenge replay: status=%d, want 401", rec2.Code)
	}
	// The rejection must be indistinguishable from a wrong code: same status,
	// same body. Uses a fresh challenge since ch2 was consumed by rec2 above
	// (a rejected code, replay or otherwise, always burns the challenge it
	// was submitted against).
	wrongRec := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": newChallenge(), "code": "000000"})
	if wrongRec.Code != rec2.Code || wrongRec.Body.String() != rec2.Body.String() {
		t.Fatalf("replay response (%d %q) distinguishable from wrong-code response (%d %q)",
			rec2.Code, rec2.Body.String(), wrongRec.Code, wrongRec.Body.String())
	}

	// (c) A legitimately later code (later time-step) still works normally.
	laterCode := totpCodeForTest(t, secret, time.Now().Add(30*time.Second))
	ch3 := newChallenge()
	rec3 := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": ch3, "code": laterCode})
	if rec3.Code != http.StatusOK {
		t.Fatalf("(c) later code: status=%d body=%s", rec3.Code, rec3.Body.String())
	}

	// (d) A wrong/invalid code does NOT advance the recorded step — proven on
	// a second, independent account so there is no ceiling on how far a
	// following genuine code can legitimately advance (ivy's recorded step
	// above is already pinned near the edge of the ±1 skew window accepted
	// by totp.Validate, since (c) deliberately used a next-step code).
	v, err := srv.users.Create(context.Background(), "jill", "pw-jill-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create jill: %v", err)
	}
	jillSecret, _ := enrollTOTP(t, srv, v.ID)
	newJillChallenge := func() string {
		t.Helper()
		loginRec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
			map[string]string{"username": "jill", "password": "pw-jill-testpassword"})
		var login struct {
			ChallengeID string `json:"challengeId"`
		}
		if err := json.Unmarshal(loginRec.Body.Bytes(), &login); err != nil {
			t.Fatalf("unmarshal login: %v", err)
		}
		return login.ChallengeID
	}

	// enrollTOTP's own confirm call already recorded a step (handleMFAConfirm
	// is wired to the same per-account guard — see
	// TestTOTPConfirmCodeCannotReplayAgainstLoginChallenge), so "fresh" here
	// means "fresh off enrollment", not literally zero.
	before, _ := srv.users.Get(v.ID)
	if before.LastUsedTOTPStep == 0 {
		t.Fatalf("expected enrollment confirm to have recorded LastUsedTOTPStep, got 0")
	}
	badRec := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": newJillChallenge(), "code": "111111"})
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("(d) wrong code: status=%d, want 401", badRec.Code)
	}
	afterWrong, _ := srv.users.Get(v.ID)
	if afterWrong.LastUsedTOTPStep != before.LastUsedTOTPStep {
		t.Fatalf("wrong code advanced LastUsedTOTPStep: want unchanged %d, got %d", before.LastUsedTOTPStep, afterWrong.LastUsedTOTPStep)
	}

	// The user's next attempt at the (still-unused) current step succeeds,
	// proving the wrong attempt above did not poison the account's state.
	realCode := totpCodeForTest(t, jillSecret, time.Now())
	rec5 := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": newJillChallenge(), "code": realCode})
	if rec5.Code != http.StatusOK {
		t.Fatalf("post-wrong-attempt genuine code: status=%d body=%s", rec5.Code, rec5.Body.String())
	}
	afterGenuine, _ := srv.users.Get(v.ID)
	if afterGenuine.LastUsedTOTPStep <= afterWrong.LastUsedTOTPStep {
		t.Fatalf("expected LastUsedTOTPStep to advance past %d, got %d",
			afterWrong.LastUsedTOTPStep, afterGenuine.LastUsedTOTPStep)
	}
}

// TestTOTPReplayCountsTowardLockout proves a replayed (already-used) TOTP
// code counts as a failure against the account-wide MFA lockout, the same as
// a wrong code, rather than clearing it. Before the fix, recordSuccess ran as
// soon as totp.Validate accepted the code -- before the per-account replay
// guard rejected it -- so a captured valid code let an attacker keep
// resetting the lockout counter to zero indefinitely while grinding through
// guesses for the real, still-unknown current code.
func TestTOTPReplayCountsTowardLockout(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "kate", "pw-kate-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	secret, _ := enrollTOTP(t, srv, u.ID)

	newChallenge := func() string {
		t.Helper()
		loginRec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
			map[string]string{"username": "kate", "password": "pw-kate-testpassword"})
		var login struct {
			ChallengeID string `json:"challengeId"`
		}
		if err := json.Unmarshal(loginRec.Body.Bytes(), &login); err != nil {
			t.Fatalf("unmarshal login: %v", err)
		}
		if login.ChallengeID == "" {
			t.Fatalf("expected a challengeId, got %s", loginRec.Body.String())
		}
		return login.ChallengeID
	}

	// Consume the current code once, legitimately.
	firstCode := totpCodeForTest(t, secret, time.Now())
	rec := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": newChallenge(), "code": firstCode})
	if rec.Code != http.StatusOK {
		t.Fatalf("initial use: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Replay that now-used code against mfaMaxFailures fresh challenges. Each
	// one passes totp.Validate (the code is still time-window valid) but must
	// be rejected by the per-account replay guard -- and, per the fix, that
	// rejection must count as a lockout failure exactly like a wrong code
	// would, not a success that clears the lockout.
	for i := 0; i < mfaMaxFailures; i++ {
		replay := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
			map[string]string{"challengeId": newChallenge(), "code": firstCode})
		if replay.Code != http.StatusUnauthorized {
			t.Fatalf("replay attempt %d: status=%d, want 401", i+1, replay.Code)
		}
	}

	// The account must now be locked out by the account-wide MFA throttle:
	// a fresh challenge is rejected before the code is even inspected. If
	// replays had instead been clearing the lockout (the bug), this would
	// still be a plain 401 "invalid code", not 429.
	locked := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": newChallenge(), "code": firstCode})
	if locked.Code != http.StatusTooManyRequests {
		t.Fatalf("expected account lockout after %d replayed attempts, got status=%d body=%s",
			mfaMaxFailures, locked.Code, locked.Body.String())
	}
}

func TestTOTPAttemptLockout(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "frank", "pw-frank-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	secret, _ := enrollTOTP(t, srv, u.ID)

	loginRec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
		map[string]string{"username": "frank", "password": "pw-frank-testpassword"})
	var login struct {
		ChallengeID string `json:"challengeId"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &login)

	// 5 wrong codes are tolerated (401 invalid), the 6th locks out.
	for i := 0; i < 5; i++ {
		rec := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
			map[string]string{"challengeId": login.ChallengeID, "code": "000000"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong attempt %d: status=%d, want 401", i+1, rec.Code)
		}
	}
	rec := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": login.ChallengeID, "code": "000000"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("lockout attempt: status=%d, want 401", rec.Code)
	}
	// Challenge is now gone: even the genuinely correct current code cannot
	// revive it. Using a real valid code here (rather than another wrong one)
	// is what actually proves the lockout is enforced by challenge deletion,
	// not merely that a wrong code keeps failing.
	correctCode := totpCodeForTest(t, secret, time.Now())
	after := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": login.ChallengeID, "code": correctCode})
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("post-lockout with correct code: status=%d, want 401", after.Code)
	}
	// And a second correct-code attempt to be doubly sure it isn't a one-shot fluke.
	after2 := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": login.ChallengeID, "code": correctCode})
	if after2.Code != http.StatusUnauthorized {
		t.Fatalf("post-lockout retry with correct code: status=%d, want 401", after2.Code)
	}
}

func TestRecoveryCodeSingleUse(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "grace", "pw-grace-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, recoveryCodes := enrollTOTP(t, srv, u.ID)
	code := recoveryCodes[0]

	// First challenge: recovery code works and mints a session.
	login1 := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
		map[string]string{"username": "grace", "password": "pw-grace-testpassword"})
	var l1 struct {
		ChallengeID string `json:"challengeId"`
	}
	_ = json.Unmarshal(login1.Body.Bytes(), &l1)
	rec1 := doJSON(srv, srv.handleMFARecoveryCode, http.MethodPost, "/api/auth/mfa/recovery-code",
		map[string]string{"challengeId": l1.ChallengeID, "code": code})
	if rec1.Code != http.StatusOK {
		t.Fatalf("recovery use 1: status=%d body=%s", rec1.Code, rec1.Body.String())
	}

	// Second challenge: the same code is now consumed and rejected.
	login2 := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
		map[string]string{"username": "grace", "password": "pw-grace-testpassword"})
	var l2 struct {
		ChallengeID string `json:"challengeId"`
	}
	_ = json.Unmarshal(login2.Body.Bytes(), &l2)
	rec2 := doJSON(srv, srv.handleMFARecoveryCode, http.MethodPost, "/api/auth/mfa/recovery-code",
		map[string]string{"challengeId": l2.ChallengeID, "code": code})
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("recovery reuse: status=%d, want 401", rec2.Code)
	}
}

func TestMFAStatusAndDisable(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "heidi", "pw-heidi-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	enrollTOTP(t, srv, u.ID)

	statusRec := doJSONAuth(srv, srv.withAuth(srv.handleMFAStatus), http.MethodGet, "/api/mfa/status", nil, u.ID)
	var status struct {
		TOTPEnabled            bool `json:"totpEnabled"`
		RecoveryCodesRemaining int  `json:"recoveryCodesRemaining"`
	}
	_ = json.Unmarshal(statusRec.Body.Bytes(), &status)
	if !status.TOTPEnabled || status.RecoveryCodesRemaining != recoveryCodeCount {
		t.Fatalf("status = %+v", status)
	}

	// Disable requires the correct password.
	bad := doJSONAuth(srv, srv.withAuth(srv.handleMFADisable), http.MethodPost, "/api/mfa/totp/disable",
		map[string]string{"password": "wrong"}, u.ID)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("disable wrong pw: status=%d, want 401", bad.Code)
	}
	good := doJSONAuth(srv, srv.withAuth(srv.handleMFADisable), http.MethodPost, "/api/mfa/totp/disable",
		map[string]string{"password": "pw-heidi-testpassword"}, u.ID)
	if good.Code != http.StatusOK {
		t.Fatalf("disable: status=%d body=%s", good.Code, good.Body.String())
	}
	got, _ := srv.users.Get(u.ID)
	if got.TOTPEnabled {
		t.Fatalf("expected TOTP disabled")
	}
}

// TestTOTPConfirmCodeCannotReplayAgainstLoginChallenge proves handleMFAConfirm
// (the enrollment-confirmation handler) is wired to the same per-account
// replay guard as handleMFATOTP (the login-challenge handler): the exact code
// used to confirm/enable TOTP records LastUsedTOTPStep, so it cannot then be
// replayed against a login MFA challenge within the same 30-90s time-step
// window.
//
// Before this fix, handleMFAConfirm validated the code via totp.Validate but
// never called SetLastUsedTOTPStep, so LastUsedTOTPStep stayed at its
// zero-value after enrollment -- and 0 < any real step always passes
// handleMFATOTP's guard, making the confirmation code replayable once
// against a login challenge in the same window.
func TestTOTPConfirmCodeCannotReplayAgainstLoginChallenge(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "nora", "pw-nora-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	setupReq := httptest.NewRequest(http.MethodPost, "/api/mfa/totp/setup", nil)
	authRequestAs(srv, setupReq, u.ID)
	setupRec := httptest.NewRecorder()
	srv.withAuth(srv.handleMFASetup)(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup: status=%d body=%s", setupRec.Code, setupRec.Body.String())
	}
	var setupResp struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(setupRec.Body.Bytes(), &setupResp); err != nil {
		t.Fatalf("unmarshal setup: %v", err)
	}

	before, _ := srv.users.Get(u.ID)
	if before.LastUsedTOTPStep != 0 {
		t.Fatalf("expected fresh account to have LastUsedTOTPStep=0, got %d", before.LastUsedTOTPStep)
	}

	confirmCode := totpCodeForTest(t, setupResp.Secret, time.Now())
	confirmRec := doJSONAuth(srv, srv.withAuth(srv.handleMFAConfirm), http.MethodPost,
		"/api/mfa/totp/confirm", map[string]string{
			"code":     confirmCode,
			"password": testPasswordFor(t, srv, u.ID),
		}, u.ID)
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("confirm: status=%d body=%s", confirmRec.Code, confirmRec.Body.String())
	}

	// The confirmation code must have advanced LastUsedTOTPStep -- this is
	// the actual fix; everything below just observes its consequence via the
	// public login/mfa flow.
	after, _ := srv.users.Get(u.ID)
	if after.LastUsedTOTPStep == 0 {
		t.Fatalf("expected LastUsedTOTPStep to be recorded by handleMFAConfirm, got 0")
	}

	loginRec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
		map[string]string{"username": "nora", "password": "pw-nora-testpassword"})
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
	var login struct {
		ChallengeID string `json:"challengeId"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &login); err != nil {
		t.Fatalf("unmarshal login: %v", err)
	}
	if login.ChallengeID == "" {
		t.Fatalf("expected a challengeId, got %s", loginRec.Body.String())
	}

	// The attack this closes: the same code just used to confirm enrollment,
	// replayed against a login MFA challenge in the same time-step window.
	replayRec := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": login.ChallengeID, "code": confirmCode})
	if replayRec.Code != http.StatusUnauthorized {
		t.Fatalf("replaying confirm code against login challenge: status=%d, want 401 (body=%s)",
			replayRec.Code, replayRec.Body.String())
	}

	// A genuinely later code still works normally -- proves the guard
	// rejects only the specific replayed step, not TOTP login wholesale. A
	// fresh challenge is required since the rejected replay above already
	// consumed login.ChallengeID (handleMFATOTP deletes the challenge on any
	// rejected code, replay or otherwise).
	login2Rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
		map[string]string{"username": "nora", "password": "pw-nora-testpassword"})
	var login2 struct {
		ChallengeID string `json:"challengeId"`
	}
	if err := json.Unmarshal(login2Rec.Body.Bytes(), &login2); err != nil {
		t.Fatalf("unmarshal second login: %v", err)
	}
	laterCode := totpCodeForTest(t, setupResp.Secret, time.Now().Add(30*time.Second))
	laterRec := doJSON(srv, srv.handleMFATOTP, http.MethodPost, "/api/auth/mfa/totp",
		map[string]string{"challengeId": login2.ChallengeID, "code": laterCode})
	if laterRec.Code != http.StatusOK {
		t.Fatalf("later code after replay rejection: status=%d body=%s", laterRec.Code, laterRec.Body.String())
	}
}
