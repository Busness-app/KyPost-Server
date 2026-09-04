package api

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/state"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// --- login lockout keying ---------------------------------------------------

// The lockout key must be the same fold GetByUsername resolves the account
// with. It used to be the raw submitted string, so "victim", "Victim" and
// " victim " were one account to the lookup and three independent strike
// budgets to the lockout — and whitespace padding made that key space
// unbounded, which turned three-strikes into unlimited online guessing from a
// single IP.
func TestLoginLockoutSurvivesUsernameCaseAndWhitespace(t *testing.T) {
	srv := newTestServer(t)
	if _, err := srv.users.Create(context.Background(), "victim", "victim-real-password", users.RoleUser); err != nil {
		t.Fatalf("Create: %v", err)
	}

	attempt := func(username string) int {
		body, _ := json.Marshal(map[string]string{"username": username, "password": "wrong-guess"})
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.RemoteAddr = "203.0.113.9:5555"
		rec := httptest.NewRecorder()
		srv.handleLogin(rec, req)
		return rec.Code
	}

	for i := 0; i < loginMaxFailures; i++ {
		if got := attempt("victim"); got != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, got)
		}
	}
	if got := attempt("victim"); got != http.StatusTooManyRequests {
		t.Fatalf("baseline: got %d, want 429", got)
	}

	for _, variant := range []string{"Victim", "VICTIM", "vIctim", " victim", "victim ", "  victim  "} {
		if got := attempt(variant); got != http.StatusTooManyRequests {
			t.Fatalf("variant %q got %d, want 429 — the lockout is bypassable by respelling the username", variant, got)
		}
	}
}

// A different account must still be unaffected: the fix folds the key, it does
// not widen it.
func TestLoginLockoutStillScopedPerAccount(t *testing.T) {
	srv := newTestServer(t)
	for _, name := range []string{"alice", "bob"} {
		if _, err := srv.users.Create(context.Background(), name, name+"-real-password-long", users.RoleUser); err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
	}
	attempt := func(username string) int {
		body, _ := json.Marshal(map[string]string{"username": username, "password": "wrong-guess"})
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.RemoteAddr = "203.0.113.9:5555"
		rec := httptest.NewRecorder()
		srv.handleLogin(rec, req)
		return rec.Code
	}
	for i := 0; i < loginMaxFailures+1; i++ {
		attempt("alice")
	}
	if got := attempt("bob"); got == http.StatusTooManyRequests {
		t.Fatal("bob was locked out by alice's failures")
	}
}

// --- IMAP connection lifetime -----------------------------------------------

// closingMailClient is a fakeMailClient that also counts Close calls, so the
// cache-eviction paths can be observed doing the hangup.
type closingMailClient struct {
	fakeMailClient
	closed int
}

func (c *closingMailClient) Close() error {
	c.closed++
	return nil
}

// An evicted mail client holds a live authenticated IMAP session that nothing
// else reclaims, so dropping it without a Close leaks one connection per
// eviction — and providers cap concurrent sessions per account.
func TestInvalidateUserMailClosesTheEvictedClient(t *testing.T) {
	srv := newTestServer(t)
	client := &closingMailClient{}
	srv.userMail["user-1"] = &serverMailEntry{client: client, updatedAt: "t0"}

	srv.invalidateUserMail("user-1")

	if client.closed != 1 {
		t.Fatalf("Close called %d times, want 1 — the evicted client's IMAP session is leaked", client.closed)
	}
	if _, still := srv.userMail["user-1"]; still {
		t.Fatal("entry survived invalidation")
	}
}

// closeMailClient must tolerate a client that has nothing to close: the six
// test fakes implementing imapadapter.Client are exactly that, which is why
// this is an io.Closer assertion rather than an interface method.
func TestCloseMailClientIgnoresNonClosers(t *testing.T) {
	closeMailClient(&fakeMailClient{})
}

// --- device auth strike accounting ------------------------------------------

// A correct device secret against a deactivated account is not a guess, so it
// must not spend a lockout strike. It used to: the branch returned without
// settling the strike tryAttempt had already reserved, so a deactivated
// account's phone burned its whole budget on its normal retry cadence and then
// got 429 ("back off") where it needed 401 ("re-pair").
func TestDeactivatedAccountDeviceAuthRefundsTheStrike(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "device-owner", "device-owner-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	store, err := srv.userStore(u.ID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	secret := "device-secret-value"
	hash, err := users.HashPassword(context.Background(), secret)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := store.UpsertNativeDevice(state.NativeDevice{DeviceID: "dev-1", UserID: u.ID, SecretHash: hash}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}
	srv.userMu.Lock()
	srv.deviceIndex["dev-1"] = u.ID
	srv.userMu.Unlock()

	if _, err := srv.users.Deactivate(u.ID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
		req.Header.Set(headerDeviceID, "dev-1")
		req.Header.Set(headerDeviceSecret, secret)
		req.RemoteAddr = "203.0.113.5:4444"
		return req
	}

	// Well past the strike budget: every one of these presents a VALID secret.
	for i := 0; i < deviceMaxFailures+5; i++ {
		_, _, ok, retryAfter := srv.deviceAuthFromRequest(newReq())
		if ok {
			t.Fatal("a deactivated account authenticated")
		}
		if retryAfter > 0 {
			t.Fatalf("attempt %d was rate-limited (retryAfter=%v); a correct secret must not spend a strike", i+1, retryAfter)
		}
	}

	// And the entry must not have accumulated at all.
	srv.deviceLockout.mu.Lock()
	entry, exists := srv.deviceLockout.entries[srv.deviceLockoutKey("dev-1", newReq())]
	srv.deviceLockout.mu.Unlock()
	if exists && entry.failures > 0 {
		t.Fatalf("strike count is %d, want 0", entry.failures)
	}
}

// A WRONG secret must still cost a strike — the refund above is scoped to the
// deactivation branch, not to device auth generally.
func TestWrongDeviceSecretStillSpendsAStrike(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "device-owner2", "device-owner-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	store, err := srv.userStore(u.ID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	hash, err := users.HashPassword(context.Background(), "the-real-secret")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := store.UpsertNativeDevice(state.NativeDevice{DeviceID: "dev-2", UserID: u.ID, SecretHash: hash}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}
	srv.userMu.Lock()
	srv.deviceIndex["dev-2"] = u.ID
	srv.userMu.Unlock()

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
		req.Header.Set(headerDeviceID, "dev-2")
		req.Header.Set(headerDeviceSecret, "wrong")
		req.RemoteAddr = "203.0.113.6:4444"
		return req
	}
	locked := false
	for i := 0; i < deviceMaxFailures+1; i++ {
		if _, _, _, retryAfter := srv.deviceAuthFromRequest(newReq()); retryAfter > 0 {
			locked = true
			break
		}
	}
	if !locked {
		t.Fatal("repeated wrong secrets never locked out; the strike accounting is now too permissive")
	}
}

// --- username validity ------------------------------------------------------

// The CardDAV surface builds principal/home-set URLs out of the username and
// then guards access by comparing the first path segment back against it, so a
// username has to be one path segment.
func TestUsernameMustBeASinglePathSegment(t *testing.T) {
	srv := newTestServer(t)
	for _, bad := range []string{"alice/bob", "..", ".", "a b", "alice:bob", "with\\slash", "", ".hidden", "-flag", "../etc"} {
		if _, err := srv.users.Create(context.Background(), bad, "a-perfectly-fine-password", users.RoleUser); err == nil {
			t.Fatalf("Create(%q) was accepted; CardDAV builds URLs out of this", bad)
		}
	}
	// Distinct names: "alice" and "Alice" deliberately collide (see
	// users.NormalizeUsername), so reusing one here would fail for the wrong
	// reason.
	for _, good := range []string{"alice", "Bob", "carol.dee", "erin_fay", "gil-hall", "user123", "9lives"} {
		if _, err := srv.users.Create(context.Background(), good, "a-perfectly-fine-password", users.RoleUser); err != nil {
			t.Fatalf("Create(%q) was rejected: %v", good, err)
		}
	}
}

func TestUsersCreateHandlerRejectsInvalidUsername(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(map[string]string{
		"username": "alice/bob",
		"password": "a-perfectly-fine-password",
		"role":     "user",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleUsersCreate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

// --- contact photo types ----------------------------------------------------

// encodeSample returns a tiny valid image in the named format. testPNG (see
// run4_photo_quota_test.go) covers png.
func encodeSample(t *testing.T, format string) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 10, G: 20, B: 30, A: 255})
	var buf bytes.Buffer
	var err error
	switch format {
	case "gif":
		err = gif.Encode(&buf, img, nil)
	case "jpeg":
		err = jpeg.Encode(&buf, img, nil)
	default:
		t.Fatalf("no encoder for %q", format)
	}
	if err != nil {
		t.Fatalf("encode %s: %v", format, err)
	}
	return buf.Bytes()
}

// Every advertised content type must have a decoder registered, or the upload
// path advertises support and then rejects the file 100% of the time.
func TestEveryAdvertisedPhotoTypeIsActuallyDecodable(t *testing.T) {
	srv := newTestServer(t)
	samples := map[string][]byte{
		"image/png":  testPNG(t, 1),
		"image/gif":  encodeSample(t, "gif"),
		"image/jpeg": encodeSample(t, "jpeg"),
	}
	for contentType := range contentTypeExt {
		body, ok := samples[contentType]
		if !ok {
			t.Fatalf("contentTypeExt advertises %q but this test has no sample for it — "+
				"either add one and prove it decodes, or the entry has no decoder behind it", contentType)
		}
		if _, err := srv.storeContactPhoto("photo-user", body); err != nil {
			t.Fatalf("storeContactPhoto rejected an advertised %s: %v", contentType, err)
		}
	}
	if _, advertised := contentTypeExt["image/webp"]; advertised {
		t.Fatal("image/webp is advertised again but Go's stdlib still has no webp decoder")
	}
}

// --- MFA challenge sweeping -------------------------------------------------

// A challenge nobody ever comes back for is never accessed, so "swept lazily on
// access" never swept it. Every abandoned second-factor login was pinned for
// the process lifetime.
func TestExpiredMFAChallengesAreSweptWithoutBeingAccessed(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "mfa-user", "mfa-user-password-x", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for i := 0; i < 25; i++ {
		if _, err := srv.mfaChallenges.Create(u.ID); err != nil {
			t.Fatalf("Create challenge: %v", err)
		}
	}
	if got := srv.mfaChallenges.Len(); got != 25 {
		t.Fatalf("held %d challenges, want 25", got)
	}

	// Nothing touches the challenges by id; only the sweeper runs.
	if removed := srv.mfaChallenges.SweepExpired(time.Now().Add(10 * time.Minute)); removed != 25 {
		t.Fatalf("swept %d, want 25", removed)
	}
	if got := srv.mfaChallenges.Len(); got != 0 {
		t.Fatalf("%d challenges survived the sweep", got)
	}
}

func TestMFAChallengeSweeperLeavesLiveChallengesAlone(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "mfa-user2", "mfa-user-password-x", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ch, err := srv.mfaChallenges.Create(u.ID)
	if err != nil {
		t.Fatalf("Create challenge: %v", err)
	}
	if removed := srv.mfaChallenges.SweepExpired(time.Now()); removed != 0 {
		t.Fatalf("swept %d live challenges", removed)
	}
	if _, ok := srv.mfaChallenges.Get(ch.ID); !ok {
		t.Fatal("a live challenge was swept")
	}
}

// --- /api/auth/me is a read -------------------------------------------------

// handleMe is polled on every auth refresh; it used to mint and persist a
// subscriber ID, making a GET a file-locked write that can fail on a full or
// read-only volume.
func TestHandleMeDoesNotWriteState(t *testing.T) {
	srv, u := newTestServerWithUser(t)
	token := "me-session"
	srv.sessMu.Lock()
	srv.sessions[token] = Session{UserID: u.ID, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), CSRFToken: "c"}
	srv.sessMu.Unlock()

	// Open the store first so this measures handleMe rather than the
	// constructor.
	store, err := srv.userStore(u.ID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	if store.SubscriberID() != "" {
		t.Fatal("a fresh account already has a subscriber ID")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
	rec := httptest.NewRecorder()
	srv.handleMe(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}

	// Assert the OBSERVABLE effect rather than the bytes of a storage file:
	// handleMe is a GET the frontend polls on every auth refresh, and it must
	// not mint durable state. Minting is what GetOrCreateSubscriberID does,
	// so a still-empty subscriber ID is the property under test — and unlike a
	// file comparison it does not have to be rewritten when storage changes.
	if got := store.SubscriberID(); got != "" {
		t.Fatalf("handleMe minted a subscriber ID (%q); it must be read-only", got)
	}
	if store.SubscriberID() != "" {
		t.Fatal("handleMe minted a subscriber ID; that belongs to the pairing endpoint")
	}
}

// The mint still has to happen where a subscriber ID is actually about to be
// used, or moving handleMe to a read would just break pairing.
func TestPairingStillMintsTheSubscriberID(t *testing.T) {
	srv, u := newTestServerWithUser(t)
	store, err := srv.userStore(u.ID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	id, err := store.GetOrCreateSubscriberID()
	if err != nil {
		t.Fatalf("GetOrCreateSubscriberID: %v", err)
	}
	if id == "" {
		t.Fatal("no subscriber ID minted")
	}
	if got := store.SubscriberID(); got != id {
		t.Fatalf("SubscriberID() = %q, want %q — the read does not see the mint", got, id)
	}
}

// --- CardDAV credential cache honors deactivation ---------------------------

// The cache is consulted before the account lookup, so a request that read
// Active==true just before a deactivation could populate it just after
// revokeAllUserCredentials cleared it — leaving a deactivated account with full
// CardDAV read/write for up to davCredentialTTL.
func TestDAVCachedCredentialRejectedAfterDeactivation(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "dav-user", "dav-user-password-long", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Simulate the race's outcome directly: a live cache entry for an account
	// that has since been deactivated.
	srv.davCredentials.put(srv.davCredentials.currentGeneration(), u.Username, "app-password", AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role})
	if _, err := srv.users.Deactivate(u.ID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}

	reached := false
	handler := srv.withDAVBasicAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	req := httptest.NewRequest("PROPFIND", davPrefix+"/dav-user/", nil)
	req.SetBasicAuth(u.Username, "app-password")
	req.RemoteAddr = "203.0.113.7:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if reached {
		t.Fatal("a deactivated account reached the CardDAV handler through the credential cache")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
}

// A live account must still get the cache's benefit: the re-check is a field
// read, not a second scrypt verification.
func TestDAVCachedCredentialStillWorksForActiveAccount(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "dav-user2", "dav-user-password-long", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	srv.davCredentials.put(srv.davCredentials.currentGeneration(), u.Username, "app-password", AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role})

	var gotCtx context.Context
	handler := srv.withDAVBasicAuth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { gotCtx = r.Context() }))
	req := httptest.NewRequest("PROPFIND", davPrefix+"/dav-user2/", nil)
	req.SetBasicAuth(u.Username, "app-password")
	req.RemoteAddr = "203.0.113.8:1234"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if gotCtx == nil {
		t.Fatal("an active account was refused on a cache hit")
	}
	ac, ok := authContextFromContext(gotCtx)
	if !ok || ac.UserID != u.ID {
		t.Fatalf("auth context = %+v, want UserID %s", ac, u.ID)
	}
}

// The cache key must fold the username the same way GetByUsername does, so one
// account does not pay scrypt once per spelling.
func TestDAVCredentialCacheKeyFoldsUsername(t *testing.T) {
	if davCredentialCacheKey("Alice", "pw") != davCredentialCacheKey(" alice ", "pw") {
		t.Fatal("cache key is spelling-sensitive; one account gets several entries")
	}
	if davCredentialCacheKey("alice", "pw") == davCredentialCacheKey("bob", "pw") {
		t.Fatal("cache key collides across accounts")
	}
}
