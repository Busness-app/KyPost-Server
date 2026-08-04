package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kypost-server/backend/internal/users"
)

// clientProtectedSlotUser is deliberately distinct from clientProtectedUser
// in pgp_client_e2e_test.go: same shape, but this suite needs a
// deterministic, easy-to-assert-on wrapped payload rather than that helper's
// realistic KDF-shaped one, and a different username to avoid colliding with
// its account.
func clientProtectedSlotUser(t *testing.T, srv *Server) string {
	t.Helper()
	u, err := srv.users.Create(context.Background(), "slotapi", "pw-slotapi-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := srv.users.SetPGPIdentityClientProtected(u.ID, "FPR", "KID",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
		`{"v":2,"pw":true}`, "generated", "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	return u.ID
}

func bootstrapSlots(t *testing.T, srv *Server, userID string) []string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/bootstrap", nil)
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePGPBootstrap)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		EnvelopeSlots     []string `json:"envelopeSlots"`
		WrappedPrivateKey string   `json:"wrappedPrivateKey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The legacy field must keep meaning exactly what it meant, or every
	// already-shipped client breaks on upgrade.
	if out.WrappedPrivateKey != `{"v":2,"pw":true}` {
		t.Fatalf("wrappedPrivateKey changed meaning: %q", out.WrappedPrivateKey)
	}
	return out.EnvelopeSlots
}

func TestBootstrapReportsPasswordSlotOnly(t *testing.T) {
	srv := newTestServer(t)
	id := clientProtectedSlotUser(t, srv)
	got := bootstrapSlots(t, srv, id)
	if len(got) != 1 || got[0] != users.EnvelopeSlotPassword {
		t.Fatalf("slots = %v, want [password]", got)
	}
}

func TestBootstrapReportsRecoverySlot(t *testing.T) {
	srv := newTestServer(t)
	id := clientProtectedSlotUser(t, srv)
	if _, err := srv.users.SetPGPWrappedEnvelope(id, users.EnvelopeSlotRecovery, `{"v":2,"rec":1}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	got := bootstrapSlots(t, srv, id)
	if len(got) != 2 || got[1] != users.EnvelopeSlotRecovery {
		t.Fatalf("slots = %v, want [password recovery]", got)
	}
}

// Slot names are metadata; the sealed bytes of a non-password slot are not
// part of the bootstrap payload. Serving them here would put a second
// brute-forceable envelope in every cold-start response for no reason.
func TestBootstrapDoesNotServeNonPasswordEnvelopeBodies(t *testing.T) {
	srv := newTestServer(t)
	id := clientProtectedSlotUser(t, srv)
	if _, err := srv.users.SetPGPWrappedEnvelope(id, users.EnvelopeSlotRecovery, `{"v":2,"SECRETBODY":1}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/bootstrap", nil)
	authRequestAs(srv, req, id)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePGPBootstrap)(rec, req)
	if body := rec.Body.String(); strings.Contains(body, "SECRETBODY") {
		t.Fatalf("bootstrap leaked a non-password envelope body: %s", body)
	}
}

// bootstrapEnvelopeSlotsRaw returns the exact bytes bootstrap wrote for the
// "envelopeSlots" key, undecoded. []string and a nil slice both decode to a
// zero-length Go slice, so a test built on bootstrapSlots's []string return
// cannot tell "[]" from "null" apart — this exists so a test can.
func bootstrapEnvelopeSlotsRaw(t *testing.T, srv *Server, userID string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/bootstrap", nil)
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePGPBootstrap)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw, present := out["envelopeSlots"]
	if !present {
		t.Fatalf("envelopeSlots absent from response: %s", rec.Body.String())
	}
	return string(raw)
}

// A client that ranges over envelopeSlots (for (const s of resp.envelopeSlots))
// breaks on null and works on []. This must hold for server-custody accounts
// too, not just the client-protected accounts the tests above cover.
func TestBootstrapEnvelopeSlotsIsEmptyArrayNotNullForServerCustody(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "legacy-server-slots", "legacy-server-slots-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := srv.users.SetPGPIdentity(u.ID, "FPR", "KID", "pub", "sealed", "generated", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}
	if raw := bootstrapEnvelopeSlotsRaw(t, srv, u.ID); raw != "[]" {
		t.Fatalf("envelopeSlots = %s, want []", raw)
	}
}

// Same rule for an account with no PGP identity at all (handlePGPBootstrap's
// default branch).
func TestBootstrapEnvelopeSlotsIsEmptyArrayNotNullForNoIdentity(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "no-pgp-slots", "no-pgp-slots-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if raw := bootstrapEnvelopeSlotsRaw(t, srv, u.ID); raw != "[]" {
		t.Fatalf("envelopeSlots = %s, want []", raw)
	}
}
