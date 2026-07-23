package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"kypost-server/backend/internal/pgpmail"
)

// keyserverBaseURL is a var (not const) so tests can point it at a local
// httptest.Server instead of the real keys.openpgp.org.
var keyserverBaseURL = "https://keys.openpgp.org"

// errKeyserverKeyNotFound is returned by keyserverLookup when the keyserver
// itself reports (via HTTP 404) that it has no key for the address, so
// callers can distinguish "no key" from other lookup failures.
var errKeyserverKeyNotFound = errors.New("no key found for this address")

// keyserverLookup queries keys.openpgp.org for email and returns a validated
// armored key. Shared by handlePGPKeyserverLookup and the send-time ladder.
func keyserverLookup(ctx context.Context, email string) (string, string, error) {
	lookupURL := keyserverBaseURL + "/vks/v1/by-email/" + url.PathEscape(email)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, lookupURL, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := newSSRFSafeHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return "", "", errKeyserverKeyNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("keyserver status %d", resp.StatusCode)
	}
	armored, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", err
	}
	fp, err := validateDiscoveredKey(string(armored), email)
	if err != nil {
		return "", "", err
	}
	return string(armored), fp, nil
}

// handlePGPKeyserverLookup queries keys.openpgp.org's Verifying Keyserver
// (VKS) for the given email's published public key. Explicit, user-
// triggered only — never called automatically at send time, so a user
// always sees and confirms the key (fingerprint) before it's attached to a
// contact.
func (s *Server) handlePGPKeyserverLookup(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}

	armored, fingerprint, err := keyserverLookup(r.Context(), email)
	if err != nil {
		if errors.Is(err, errKeyserverKeyNotFound) {
			http.Error(w, "no key found for this address", http.StatusNotFound)
			return
		}
		http.Error(w, "keyserver lookup failed", http.StatusBadGateway)
		return
	}

	key, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		http.Error(w, "keyserver returned an unparseable key", http.StatusBadGateway)
		return
	}

	now := time.Now().Unix()
	writeJSON(w, http.StatusOK, map[string]any{
		"email":       email,
		"fingerprint": fingerprint,
		"keyId":       key.GetHexKeyID(),
		"publicKey":   armored,
		"revoked":     key.IsRevoked(now),
		"expired":     key.IsExpired(now),
	})
}

// handlePGPRecipientsCheck reports, for each address in the request, whether
// the caller's contacts already have a PGP key on file — used by compose to
// warn before sending with encryption enabled.
func (s *Server) handlePGPRecipientsCheck(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	contactsStore, err := s.userContactsStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}

	type addressStatus struct {
		Address string `json:"address"`
		HasKey  bool   `json:"hasKey"`
		Revoked bool   `json:"revoked"`
		Expired bool   `json:"expired"`
	}
	statuses := make([]addressStatus, 0, len(req.Addresses))
	for _, addr := range req.Addresses {
		status := addressStatus{Address: addr}
		if key, ok := findContactPGPKey(contactsStore, addr); ok {
			if ks, err := pgpmail.CheckKeyStatus(key); err == nil {
				status.Revoked = ks.Revoked
				status.Expired = ks.Expired
				status.HasKey = ks.Usable()
			}
		}
		statuses = append(statuses, status)
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": statuses})
}
