package api

import (
	"fmt"
	"html"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/inbucket/html2text"

	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/pgpmail"
)

// pickupLinkTTL is how long a pickup link stays valid if never viewed —
// "expire after N days or first view, whichever comes first."
const pickupLinkTTL = 7 * 24 * time.Hour

// handlePickup serves the one-time, unauthenticated pickup page for a
// message sent to a recipient with no known PGP key. It is registered
// directly on the mux without withAuth: the recipient has no account, only
// the signed token in the link.
func (s *Server) handlePickup(w http.ResponseWriter, r *http.Request) {
	if !s.pairingSecretConfigured() {
		http.Error(w, "pickup links are not configured", http.StatusServiceUnavailable)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	token := strings.TrimSpace(r.URL.Query().Get("t"))
	if id == "" || token == "" {
		http.Error(w, "invalid pickup link", http.StatusBadRequest)
		return
	}
	if err := s.validatePairingToken(id, token, pairingPurposePickupLink, time.Now()); err != nil {
		http.Error(w, "this link is invalid or has expired", http.StatusForbidden)
		return
	}

	// A client-sealed record cannot be rendered here: the server has no key
	// for it. Serve the shell page and let the browser decrypt with the key
	// from the URL fragment. Kind() does not consume the record, so this
	// choice does not burn the link.
	clientSealed, kindErr := s.pickupStore.Kind(id)
	if kindErr == nil && clientSealed {
		s.servePickupDecryptPage(w, id, token)
		return
	}

	subject, body, mode, err := s.pickupStore.View(id)
	if err != nil {
		http.Error(w, "this message has already been viewed or has expired", http.StatusGone)
		return
	}
	body = s.pickupDisplayBody(body, mode)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>%s</title></head>`+
		`<body style="font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px">`+
		`<h1>%s</h1><pre style="white-space:pre-wrap;font-family:inherit">%s</pre>`+
		`<p style="color:#666">This message has now been marked as viewed and cannot be retrieved again.</p>`+
		`</body></html>`,
		html.EscapeString(subject), html.EscapeString(subject), html.EscapeString(body))
}

// pickupDisplayBody turns a stored body into what the pickup page shows.
//
// An HTML body is flattened to readable text rather than rendered as markup.
// The same rule as pickup-decrypt.js, for the same reason: this page has no
// sanitizer and shares an origin with the app, so the sender's markup must
// never become live HTML here. Escaping it without flattening — what this
// used to do to every body — is the other wrong answer, and the one the
// recipient noticed: it showed them the tags instead of the message.
//
// A plain body is returned untouched, so a message that merely talks about
// markup keeps it. The caller escapes either result before it reaches the
// page.
func (s *Server) pickupDisplayBody(body, mode string) string {
	if !strings.EqualFold(strings.TrimSpace(mode), "html") {
		return body
	}
	text, err := html2text.FromString(body)
	if err != nil {
		// The link is already burned by View, so there is no retry to offer:
		// show the raw body escaped, which is at worst what the recipient
		// would have seen before, rather than nothing at all.
		s.logger.Error("failed to flatten pickup HTML body to text", "error", err.Error())
		return body
	}
	return text
}

// sendPickupNotification creates a pickup record for one recipient with no
// known PGP key and sends them a short, unencrypted email with a link to
// retrieve the real message once. Consumed by Task 6's send-path
// integration for every recipient in the "without key" set of an encrypted
// send.
func (s *Server) sendPickupNotification(userID, from, recipient, subject, plainBody, mode, smtpHost string, smtpPort int, addr, smtpUsername, smtpPassword string) error {
	if !s.pairingSecretConfigured() {
		return fmt.Errorf("PAIRING_SECRET is not set; refusing to send a pickup link signed with a known-empty key")
	}
	id, err := s.pickupStore.Create(userID, recipient, subject, plainBody, mode, pickupLinkTTL)
	if err != nil {
		return fmt.Errorf("create pickup record: %w", err)
	}
	token, _, err := s.createPairingToken(id, pairingPurposePickupLink, pickupLinkTTL)
	if err != nil {
		return fmt.Errorf("create pickup token: %w", err)
	}

	link := fmt.Sprintf("%s/pickup/%s?t=%s", s.pickupBaseURL(), id, token)
	notice := mailmsg.Message{
		From: from,
		To:   []string{recipient},
		// Placeholder rather than the real subject: the notification travels
		// in cleartext to a keyless recipient, so leaking the subject here
		// would defeat subject protection. The real subject is shown on the
		// authenticated pickup page (PickupStore.View).
		Subject: pgpmail.OuterPlaceholderSubject,
		Body: "You've received a message that was sent encrypted. " +
			"Since we don't have a PGP key on file for your address, " +
			"you can read it once, securely, at the link below:\n\n" + link +
			"\n\nThis link expires in 7 days or as soon as it's opened, whichever comes first.",
		Mode: "plain",
	}.Build()

	recipients := []string{recipient}
	if smtpPort == 465 {
		return mailmsg.SMTPSendWithImplicitTLS(smtpHost, smtpPort, smtpUsername, smtpPassword, from, recipients, notice, 45*time.Second)
	}
	auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)
	return mailmsg.SMTPSendWithTimeout(addr, auth, from, recipients, notice, 45*time.Second)
}

// pickupBaseURL is the externally-reachable base URL used to build pickup
// links, preferring the explicit SERVER_BASE_URL override — pickup
// notification emails are sent outside any HTTP request context, so
// externalBaseURL's X-Forwarded-* header trick isn't available here. It is
// also used to build the QR key-exchange URL (handlePGPQRToken).
//
// When SERVER_BASE_URL is unset, this falls back to a localhost URL so the
// feature still nominally works in local/dev setups, but that fallback is
// silently wrong for anyone else: pickup links emailed to recipients and QR
// codes scanned by other devices will point at the operator's own machine.
// Log a warning once so the degraded state is observable instead of silent.
// pairingSecretConfigured reports whether PAIRING_SECRET is set, logging a
// one-time warning when it's not: without it, pickup links and QR
// key-exchange tokens would otherwise be HMAC-signed with a known-empty key,
// which provides no security even though the endpoints appear to work.
func (s *Server) pairingSecretConfigured() bool {
	if s.pairingSecret != "" {
		return true
	}
	s.pairingSecretWarn.Do(func() {
		s.logger.Error("PAIRING_SECRET is not set; pickup links and PGP QR key-exchange are disabled (they would otherwise be signed with a known-empty key)")
	})
	return false
}

func (s *Server) pickupBaseURL() string {
	if s.serverBaseURL != "" {
		return s.serverBaseURL
	}
	s.baseURLFallbackWarn.Do(func() {
		s.logger.Error("SERVER_BASE_URL is not set; pickup links and PGP QR key-exchange URLs will fall back to http://localhost:5866 and will not work for remote recipients or scanners")
	})
	return "http://localhost:5866"
}
