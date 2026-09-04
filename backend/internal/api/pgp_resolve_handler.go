package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Busness-app/kypost-server/backend/internal/pgpdiscovery"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// handlePGPRecipientsResolve returns the armored public key for each
// recipient, running the same discovery ladder the server-side send path
// uses (pinned contact key → WKD → keyserver, honoring the user's discovery
// settings and suppressions — see keyResolver).
//
// POST /api/pgp/recipients/resolve  {"addresses": ["a@b.c", ...]}
//
// This exists for client-protected accounts, where the browser does the
// encryption and therefore needs the recipients' actual keys rather than the
// yes/no answer /api/pgp/recipients/check gives. Reimplementing the ladder in
// TypeScript would mean a second, weaker copy of the TOFU pinning and
// key-changed rules; running it here keeps one implementation.
//
// Public keys are not secret, and the caller is the account owner who is
// about to encrypt to these people anyway. What is deliberately NOT here is
// any fallback: an address with no usable key comes back unusable, and the
// browser must refuse to send rather than quietly downgrading. The
// server-side path's pickup-link fallback is unavailable by design — it
// works by storing the plaintext on this server, which is the thing
// client-side protection exists to prevent.
func (s *Server) handlePGPRecipientsResolve(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	if u.PGPProtection() != users.PGPProtectionClient {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "this account's PGP key is not client-protected; the server encrypts on its own",
		})
		return
	}

	var req struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	// The sibling bound to /api/pgp/recipients/check and to the send path: this
	// loop carries the same per-address contacts-file re-read, plus outbound WKD
	// and keyserver lookups on top of it.
	if len(req.Addresses) > maxRecipientsPerSend {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error": fmt.Sprintf("too many addresses (maximum %d)", maxRecipientsPerSend),
		})
		return
	}
	if len(req.Addresses) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"results": []any{}})
		return
	}
	addresses, err := parseDeliveryRecipients(req.Addresses)
	if err != nil {
		http.Error(w, "invalid recipient address", http.StatusBadRequest)
		return
	}

	contactsStore, err := s.userContactsStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}
	settings, err := pgpdiscovery.Load(s.userStateDir(ac.UserID))
	if err != nil {
		http.Error(w, "failed to load pgp discovery settings", http.StatusInternalServerError)
		return
	}
	suppressed, err := pgpdiscovery.SuppressedSet(s.userStateDir(ac.UserID))
	if err != nil {
		http.Error(w, "failed to load pgp discovery suppressions", http.StatusInternalServerError)
		return
	}
	resolver := &keyResolver{store: contactsStore, settings: settings, discover: true, suppressed: suppressed}

	type result struct {
		Address     string `json:"address"`
		PublicKey   string `json:"publicKey,omitempty"`
		Fingerprint string `json:"fingerprint,omitempty"`
		Tier        string `json:"tier"`
		Usable      bool   `json:"usable"`
	}
	seen := map[string]bool{}
	results := make([]result, 0, len(addresses))
	for _, addr := range addresses {
		clean := strings.TrimSpace(addr)
		if clean == "" || seen[strings.ToLower(clean)] {
			continue
		}
		seen[strings.ToLower(clean)] = true
		rk := resolver.resolve(r.Context(), clean)
		results = append(results, result{
			Address:     clean,
			PublicKey:   rk.Armored,
			Fingerprint: rk.Fingerprint,
			Tier:        string(rk.Tier),
			Usable:      rk.Usable,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}
