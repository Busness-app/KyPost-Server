package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"kypost-server/backend/internal/mailmsg"
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
