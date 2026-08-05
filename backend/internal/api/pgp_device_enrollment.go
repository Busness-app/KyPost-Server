package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"kypost-server/backend/internal/users"
)

// Device-authenticated halves of the enrollment ceremony. Both resolve the
// caller through deviceAuthFromRequest, which returns the VERIFIED device
// record, so neither ever reads an identity out of the request.
//
// These are deliberately not withAuth and not withMailAuth. withMailAuth would
// admit a session, which has no device to scope to; withAuth would exclude the
// device entirely. See
// docs/superpowers/specs/2026-08-04-device-enrollment-design.md.

// maxEnrollmentPublicKeyBytes bounds the published key. An uncompressed P-256
// point is 65 bytes raw and a few hundred base64-wrapped in any sane encoding;
// this leaves generous headroom while keeping an unbounded string out of the
// device table.
const maxEnrollmentPublicKeyBytes = 4 << 10

// handlePGPPublishEnrollmentKey records the calling device's enrollment public
// key.
//
// A public key is not a capability — it lets a browser seal TO this device and
// confers nothing by itself — which is why a device may publish its own under
// its pairing credential while only a session may mint the sealing.
func (s *Server) handlePGPPublishEnrollmentKey(w http.ResponseWriter, r *http.Request) {
	// userID is the owner deviceAuthFromRequest resolved the credential
	// through; device.UserID is only a stamp on the row and is empty for
	// devices paired before it existed.
	userID, device, ok, retryAfter := s.deviceAuthFromRequest(r)
	if !ok {
		writeDeviceAuthFailure(w, retryAfter)
		return
	}
	var req struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxEnrollmentPublicKeyBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	publicKey := strings.TrimSpace(req.PublicKey)
	if publicKey == "" {
		http.Error(w, "publicKey is required", http.StatusBadRequest)
		return
	}
	store, err := s.userStore(userID)
	if err != nil {
		http.Error(w, "state unavailable", http.StatusInternalServerError)
		return
	}
	// device.DeviceID comes from the verified credential, never from the body.
	if _, err := store.SetNativeDeviceEnrollmentKey(device.DeviceID, publicKey,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		http.Error(w, "could not store the enrollment key", http.StatusInternalServerError)
		return
	}
	s.logger.Info("pgp enrollment key published", "user_id", userID, "device_id", device.DeviceID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handlePGPDeviceEnvelope serves the ONE envelope sealed for the calling device.
//
// It takes no slot parameter, by design. The general GET on
// /api/pgp/identity/envelope/{slot} stays session-only because a device asking
// for another device's sealing — or for the password slot — is exactly what
// that rule withholds. Here the slot name is built from the verified device
// record, so there is no input to abuse.
//
// Serving this one envelope to this one device is safe: it is sealed to a key
// whose private half is non-extractable from that device's secure element, so
// no other caller gains anything by obtaining it.
func (s *Server) handlePGPDeviceEnvelope(w http.ResponseWriter, r *http.Request) {
	userID, device, ok, retryAfter := s.deviceAuthFromRequest(r)
	if !ok {
		writeDeviceAuthFailure(w, retryAfter)
		return
	}
	u, err := s.users.Get(userID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	slot := users.EnvelopeSlotDevicePrefix + device.DeviceID
	// WrappedEnvelopes() already omits expired entries, so a transport copy
	// whose TTL has passed correctly reads as absent rather than being served.
	for _, e := range u.WrappedEnvelopes() {
		if e.Slot == slot {
			writeJSON(w, http.StatusOK, map[string]any{"slot": e.Slot, "envelope": e.Envelope})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "no envelope sealed for this device"})
}
