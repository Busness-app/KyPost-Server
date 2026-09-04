package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/state"
)

// Registration was unbounded. Delivery walks every registered destination
// serially, each with its own multi-second network timeout, inside the
// goroutine poller.tick's wg.Wait() awaits — so the row count is a multiplier
// on how long the whole instance's polling is held up, and an ordinary
// authenticated account could raise it without limit while never doing
// anything it was not allowed to do.

// Endpoints are IP literals, not hostnames: ValidateUnifiedPushEndpointURL
// resolves a name before accepting it, and a test that depends on live DNS
// fails for a reason that has nothing to do with what it is checking. The
// address is a real public one because the guard (correctly) refuses private
// and reserved space, TEST-NET included.
func subscribeRequest(t *testing.T, srv *Server, userID, endpoint string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"endpoint": endpoint,
		"keys":     map[string]string{"p256dh": "BParkedPublicKeyValue", "auth": "c2VjcmV0MTIzNDU2Nzg"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/subscriptions", bytes.NewReader(body))
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	return rec
}

func TestWebPushSubscriptionsAreCapped(t *testing.T) {
	srv, u := newTestServerWithUser(t)

	for i := 0; i < state.MaxNotificationSubscriptions; i++ {
		rec := subscribeRequest(t, srv, u.ID, fmt.Sprintf("https://93.184.216.34/%d", i))
		if rec.Code != http.StatusOK {
			t.Fatalf("subscription %d below the cap: status = %d, want 200 (%s)", i, rec.Code, rec.Body.String())
		}
	}

	rec := subscribeRequest(t, srv, u.ID, "https://93.184.216.34/one-too-many")
	if rec.Code != http.StatusConflict {
		t.Fatalf("subscription past the cap: status = %d, want %d", rec.Code, http.StatusConflict)
	}

	// The cap must not stop a browser at the cap from rotating its keys — that
	// would turn a bound on quantity into a bound on staying subscribed.
	if rec := subscribeRequest(t, srv, u.ID, "https://93.184.216.34/0"); rec.Code != http.StatusOK {
		t.Fatalf("refreshing an existing subscription at the cap: status = %d, want 200", rec.Code)
	}
}

// The 1 MiB body limit bounds one REQUEST. It never bounded what got STORED:
// every field below was persisted at whatever length the caller chose, up to
// that limit, and then read back on every delivery attempt.
func TestWebPushSubscriptionFieldsAreBounded(t *testing.T) {
	srv, u := newTestServerWithUser(t)

	huge := "https://93.184.216.34/" + strings.Repeat("a", maxPushEndpointLen)
	if rec := subscribeRequest(t, srv, u.ID, huge); rec.Code != http.StatusBadRequest {
		t.Fatalf("over-length endpoint: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	body, _ := json.Marshal(map[string]any{
		"endpoint": "https://93.184.216.34/ok",
		"keys": map[string]string{
			"p256dh": "BParkedPublicKeyValue",
			"auth":   strings.Repeat("k", maxPushKeyLen+1),
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/subscriptions", bytes.NewReader(body))
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("over-length key: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// POST /api/notifications/test is the one endpoint that lets an authenticated
// caller trigger the serial fanout on demand, as often as they like, against
// destinations they chose. Unmetered, it was the trigger the cap alone does
// not cover.
func TestNotificationTestEndpointIsMetered(t *testing.T) {
	srv, u := newTestServerWithUser(t)

	fire := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/notifications/test", bytes.NewReader([]byte(`{}`)))
		authRequestAs(srv, req, u.ID)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		return rec.Code
	}

	if code := fire(); code == http.StatusTooManyRequests {
		t.Fatal("the first test notification was refused; the meter must not fire on a first request")
	}
	if code := fire(); code != http.StatusTooManyRequests {
		t.Fatalf("second test notification: status = %d, want %d", code, http.StatusTooManyRequests)
	}
}

// A malformed body must not spend the meter.
//
// The cooldown was consumed before the body was decoded, and the decode error
// was discarded — so a truncated or malformed request fell through to the zero
// value, sent the default notification anyway, and left the caller refused
// until the cooldown expired. Whether the notification is "harmless" is beside
// the point: the request the user meant to make is the one that gets rejected,
// and they cannot retry it.
func TestMalformedNotificationTestDoesNotSpendTheCooldown(t *testing.T) {
	srv, u := newTestServerWithUser(t)

	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/notifications/test", bytes.NewReader([]byte(body)))
		authRequestAs(srv, req, u.ID)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		return rec.Code
	}

	if code := post(`{"title": "truncated`); code != http.StatusBadRequest {
		t.Fatalf("malformed body: status = %d, want %d", code, http.StatusBadRequest)
	}

	// The real request must still go through: the malformed one above cost the
	// caller nothing.
	if code := post(`{"title":"real","body":"real"}`); code == http.StatusTooManyRequests {
		t.Fatal("a malformed request spent the cooldown; the caller cannot retry correctly")
	}
}
