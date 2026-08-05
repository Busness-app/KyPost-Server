package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
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
