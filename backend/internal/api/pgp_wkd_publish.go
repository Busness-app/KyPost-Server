package api

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/users"
	"kypost-server/backend/internal/wkdpublish"
)

// wkdRecordNameFormat/wkdRecordValueFormat describe, before a claim exists,
// the shape of the DNS TXT record a caller will need to add once they claim
// a domain (used only in the GET list response as a hint for the UI).
const (
	wkdRecordNameFormat  = "_kypost-wkd.<domain>"
	wkdRecordValueFormat = "kypost-wkd-verify=<token>"
)

// wkdClaimResponse is the POST /api/pgp/wkd/domains response: the created
// claim (fields promoted to the top level via embedding) plus the literal
// DNS TXT record the caller must add to prove ownership.
type wkdClaimResponse struct {
	wkdpublish.Claim
	RecordName  string `json:"recordName"`
	RecordValue string `json:"recordValue"`
}

// domainOfEmail returns the lowercased domain part of an email address, or
// "" if email has no usable "@". Mirrors the inline split fetchWKDKey uses
// (internal/api/pgp_wkd.go) since there's no shared domainOf helper in this
// package.
func domainOfEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(email[at+1:]))
}

// publishableDomains returns the lowercased set of domains the caller may
// claim for WKD publishing: the domain of their IMAP account address (the
// same address handleMailSend treats as the account's own From address)
// plus the domains of any of their verified send-as aliases.
func (s *Server) publishableDomains(r *http.Request) (map[string]bool, error) {
	ac, ok := authFromContext(r)
	if !ok {
		return nil, errMailUnauthorized
	}
	out := map[string]bool{}
	payload, exists, err := mailmsg.ReadIMAPConfigPayload(s.userIMAPConfigPath(ac.UserID), s.imapConfigKeyPath)
	if err != nil {
		return nil, err
	}
	if exists {
		if d := domainOfEmail(payload.Username); d != "" {
			out[d] = true
		}
	}
	sendAs, err := s.sendAsFor(r)
	if err != nil {
		return nil, err
	}
	for _, alias := range sendAs.ListVerified() {
		if d := domainOfEmail(alias.Email); d != "" {
			out[d] = true
		}
	}
	return out, nil
}

// handleWKDDomains serves GET (list the caller's claims) and POST (claim a
// new domain) on /api/pgp/wkd/domains.
func (s *Server) handleWKDDomains(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	store, err := s.userWKDPublishStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open wkd store", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		claims := store.List()
		writeJSON(w, http.StatusOK, map[string]any{
			"domains":           claims,
			"recordNameFormat":  wkdRecordNameFormat,
			"recordValueFormat": wkdRecordValueFormat,
		})

	case http.MethodPost:
		var req struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		domain := strings.ToLower(strings.TrimSpace(req.Domain))
		if domain == "" {
			http.Error(w, "domain is required", http.StatusBadRequest)
			return
		}
		allowed, err := s.publishableDomains(r)
		if err != nil {
			http.Error(w, "failed to resolve send addresses", http.StatusInternalServerError)
			return
		}
		if !allowed[domain] {
			http.Error(w, "domain does not match any of your send addresses", http.StatusBadRequest)
			return
		}
		claim, err := store.Create(domain)
		if err != nil {
			http.Error(w, "failed to create claim", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, wkdClaimResponse{
			Claim:       claim,
			RecordName:  wkdpublish.TXTRecordName(domain),
			RecordValue: "kypost-wkd-verify=" + claim.Token,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleWKDDomainVerify re-checks the DNS TXT record for {domain} against
// the stored claim's token and persists the result. A DNS lookup error is
// reported as {verified:false} (200), not a 500 — transient DNS failures
// are an expected, non-exceptional outcome here.
func (s *Server) handleWKDDomainVerify(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}
	store, err := s.userWKDPublishStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open wkd store", http.StatusInternalServerError)
		return
	}

	var claim wkdpublish.Claim
	found := false
	for _, c := range store.List() {
		if c.Domain == domain {
			claim = c
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "no claim for domain", http.StatusNotFound)
		return
	}

	verified, _ := wkdpublish.CheckTXT(domain, claim.Token)
	if err := store.SetVerified(domain, verified, time.Now()); err != nil {
		http.Error(w, "failed to update claim", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verified": verified})
}

// handleWKDDomainDelete removes the caller's claim for {domain}.
func (s *Server) handleWKDDomainDelete(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}
	store, err := s.userWKDPublishStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open wkd store", http.StatusInternalServerError)
		return
	}
	if _, err := store.Delete(domain); err != nil {
		http.Error(w, "failed to delete claim", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleWKD is the single public (unauthenticated) catch-all for both Web Key
// Directory serving methods, registered at GET /.well-known/openpgpkey/. A
// single handler dispatching on the trimmed path is required rather than
// separate mux patterns, because a literal "hu"/"policy" segment pattern and
// a "{domain}" wildcard pattern at the same position conflict under Go 1.22's
// ServeMux (both would match "/.well-known/openpgpkey/hu/xyz").
//
// Shapes handled:
//   - .../openpgpkey/policy                 → 200, empty body (direct method)
//   - .../openpgpkey/{domain}/policy         → 200, empty body (advanced method)
//   - .../openpgpkey/hu/{hu}                 → binary key or 404 (direct; domain from r.Host)
//   - .../openpgpkey/{domain}/hu/{hu}        → binary key or 404 (advanced; domain from path)
func (s *Server) handleWKD(w http.ResponseWriter, r *http.Request) {
	const prefix = "/.well-known/openpgpkey/"
	rest := strings.TrimPrefix(r.URL.Path, prefix)

	var domain, hu string
	switch {
	case rest == "policy":
		writeWKDPolicy(w)
		return
	case strings.HasPrefix(rest, "hu/"):
		domain = hostDomain(r.Host)
		hu = strings.TrimPrefix(rest, "hu/")
	case strings.HasSuffix(rest, "/policy"):
		writeWKDPolicy(w)
		return
	default:
		// <domain>/hu/<hu>
		parts := strings.SplitN(rest, "/hu/", 2)
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		domain, hu = strings.ToLower(parts[0]), parts[1]
	}
	if domain == "" || hu == "" {
		http.NotFound(w, r)
		return
	}

	binary, ok := s.lookupPublishedKey(domain, hu)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "max-age=3600")
	_, _ = w.Write(binary)
}

// writeWKDPolicy answers the WKD "policy" file: a 200 with an empty body,
// meaning "no submission-address / no special policy restrictions".
func writeWKDPolicy(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
}

// hostDomain strips an optional port from an HTTP Host header and, for the
// direct method (where WKD clients request "openpgpkey.<domain>"), the
// leading "openpgpkey." label if present.
func hostDomain(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	return strings.TrimPrefix(host, "openpgpkey.")
}

// lookupPublishedKey scans users for an Active user with a non-empty PGP key
// who holds a verified WKD claim on domain and has a publishable address at
// that domain whose hashed local-part matches hu. On a match it returns the
// BINARY (unarmored) form of that user's public key, as WKD requires.
func (s *Server) lookupPublishedKey(domain, hu string) ([]byte, bool) {
	users, err := s.users.List()
	if err != nil {
		return nil, false
	}
	for _, u := range users {
		if !u.Active || u.PGPPublicKey == "" {
			continue
		}
		store, err := s.userWKDPublishStore(u.ID)
		if err != nil || !store.VerifiedDomains()[domain] {
			continue
		}
		for _, addr := range s.publishableAddressesAt(u, domain) {
			at := strings.LastIndex(addr, "@")
			if at <= 0 {
				continue
			}
			if wkdHashLocalPart(addr[:at]) != hu {
				continue
			}
			key, err := crypto.NewKeyFromArmored(u.PGPPublicKey)
			if err != nil {
				return nil, false
			}
			binary, err := key.GetPublicKey()
			if err != nil {
				return nil, false
			}
			return binary, true
		}
	}
	return nil, false
}

// publishableAddressesAt returns the lowercased addresses belonging to user
// u whose domain equals domain: the IMAP account address (the same address
// handleMailSend and publishableDomains treat as the account's own From
// address) plus any of the user's verified send-as aliases at that domain.
// Read errors (no config yet, corrupt store, etc.) simply yield no addresses
// rather than an error, since this is a best-effort lookup over all users.
func (s *Server) publishableAddressesAt(u users.User, domain string) []string {
	var out []string

	payload, exists, err := mailmsg.ReadIMAPConfigPayload(s.userIMAPConfigPath(u.ID), s.imapConfigKeyPath)
	if err == nil && exists {
		addr := strings.ToLower(strings.TrimSpace(payload.Username))
		if domainOfEmail(addr) == domain {
			out = append(out, addr)
		}
	}

	if store, err := s.userSendAsStore(u.ID); err == nil {
		for _, alias := range store.ListVerified() {
			addr := strings.ToLower(strings.TrimSpace(alias.Email))
			if domainOfEmail(addr) == domain {
				out = append(out, addr)
			}
		}
	}

	return out
}
