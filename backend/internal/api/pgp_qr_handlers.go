package api

import (
	"net/http"
	"strings"
	"time"

	"kypost-server/backend/internal/contacts"
)

// handlePGPQRToken mints a short-TTL token (session auth) that a scanning
// device can exchange for the caller's public key via handlePGPQRKey — used
// for in-person QR-based contact key exchange.
func (s *Server) handlePGPQRToken(w http.ResponseWriter, r *http.Request) {
	if s.pairingSecret == "" {
		http.Error(w, "pairing is not configured", http.StatusServiceUnavailable)
		return
	}

	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil || u.PGPFingerprint == "" {
		http.Error(w, "no pgp identity configured", http.StatusBadRequest)
		return
	}
	token, expiresAt, err := s.createPairingToken(ac.UserID, pairingPurposePGPQRKey, 2*time.Minute)
	if err != nil {
		http.Error(w, "failed to create qr token", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":     token,
		"expiresAt": expiresAt.Format(time.RFC3339),
		"url":       s.pickupBaseURL() + "/api/pgp/qr/key?t=" + token,
	})
}

// handlePGPQRKey is public and token-gated (no session): it returns the
// token owner's armored public key + display name, for a scanning device to
// offer as a new/updated contact PGP key.
func (s *Server) handlePGPQRKey(w http.ResponseWriter, r *http.Request) {
	if s.pairingSecret == "" {
		http.Error(w, "pairing is not configured", http.StatusServiceUnavailable)
		return
	}

	token := strings.TrimSpace(r.URL.Query().Get("t"))
	if token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}
	claims, err := s.decodeAndVerifyPairingToken(token, pairingPurposePGPQRKey, time.Now())
	if err != nil {
		http.Error(w, "invalid or expired token", http.StatusForbidden)
		return
	}
	userID := claims.Sub
	// Single use. A two-minute window is not a substitute for it: the token
	// travels in a URL and in a QR code on a screen, so anyone who photographs
	// or shoulder-surfs it inside that window could otherwise replay it. Marked
	// before the response is built, so a slow render cannot let a second
	// request in behind the first.
	// Keyed on the signed nonce rather than the token STRING: RawURLEncoding
	// accepts non-canonical trailing bits, so one minted token has several
	// distinct encodings that all verify, and a string-keyed guard books each
	// as a separate token. handleNotificationNativeRegister already keys on
	// claims.Nonce for this reason.
	if !s.consumeQRToken(claims.Nonce) {
		http.Error(w, "this qr code has already been used; generate a new one", http.StatusForbidden)
		return
	}
	u, err := s.users.Get(userID)
	if err != nil || u.PGPFingerprint == "" {
		http.Error(w, "no pgp identity configured", http.StatusNotFound)
		return
	}
	resp := map[string]any{
		"name":        u.Username,
		"fingerprint": u.PGPFingerprint,
		"publicKey":   u.PGPPublicKey,
	}
	if store, err := s.userContactsStore(userID); err == nil {
		if self, ok := store.GetSelf(); ok {
			resp["contactCard"] = contactCardFromContact(self)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// pgpQRContactCard is the subset of the owner's self-contact included in the
// QR key-exchange response.
//
// Deliberately narrow. This endpoint's job is to hand a scanning device a
// PUBLIC KEY and enough identity to file it under, and it is reachable by
// anyone holding the token — which travels in a URL, in a QR code, on a screen
// in a room. It used to return the whole self-contact: phone numbers, postal
// addresses, birthday, free-text notes, relations, custom fields. None of that
// is needed to accept a key, and a postal address handed out by an
// unauthenticated URL is a different kind of disclosure from a public key.
//
// What remains is name, organisation and email addresses: who the key belongs
// to, and the addresses it is for — which is what makes the key usable at all,
// since a key is looked up by address. Anything else the two parties want to
// exchange has an ordinary contact-sharing path that authenticates.
//
// photoRef was already excluded, and stays excluded, for a related reason:
// photos are served from an authenticated route the scanner has no session for.
type pgpQRContactCard struct {
	FormattedName      string                  `json:"fn,omitempty"`
	GivenName          string                  `json:"givenName,omitempty"`
	FamilyName         string                  `json:"familyName,omitempty"`
	MiddleName         string                  `json:"middleName,omitempty"`
	Prefix             string                  `json:"prefix,omitempty"`
	Suffix             string                  `json:"suffix,omitempty"`
	Nickname           string                  `json:"nickname,omitempty"`
	Org                string                  `json:"org,omitempty"`
	Title              string                  `json:"title,omitempty"`
	Department         string                  `json:"department,omitempty"`
	Emails             []contacts.ContactValue `json:"emails,omitempty"`
	PhoneticGivenName  string                  `json:"phoneticGivenName,omitempty"`
	PhoneticFamilyName string                  `json:"phoneticFamilyName,omitempty"`
	Pronouns           string                  `json:"pronouns,omitempty"`
}

func contactCardFromContact(c contacts.Contact) pgpQRContactCard {
	return pgpQRContactCard{
		FormattedName:      c.FormattedName,
		GivenName:          c.GivenName,
		FamilyName:         c.FamilyName,
		MiddleName:         c.MiddleName,
		Prefix:             c.Prefix,
		Suffix:             c.Suffix,
		Nickname:           c.Nickname,
		Org:                c.Org,
		Title:              c.Title,
		Department:         c.Department,
		Emails:             c.Emails,
		PhoneticGivenName:  c.PhoneticGivenName,
		PhoneticFamilyName: c.PhoneticFamilyName,
		Pronouns:           c.Pronouns,
	}
}
