package api

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/inbucket/html2text"

	"kypost-server/backend/internal/cryptutil"
	"kypost-server/backend/internal/logging"
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
	// Kind reads without consuming, so a record that is gone can be reported as
	// gone here rather than sending the recipient to a button that will only
	// tell them the same thing one click later. This discloses nothing: the
	// token is scoped to this one ID, so anyone who can reach this line already
	// knows the ID.
	if errors.Is(kindErr, pgpmail.ErrPickupNotFound) || errors.Is(kindErr, pgpmail.ErrPickupExpired) {
		http.Error(w, "this message has already been viewed or has expired", http.StatusGone)
		return
	}

	// A server-sealed record is NOT read or consumed here, and must not be.
	// Rendering on a plain GET means anything that follows a link in an email
	// reads the whole message and leaves the human a permanent 410 — and the
	// URL-detonation scanners that do exactly that (Safe Links, Proofpoint,
	// Mimecast) sit in the recipient's own mail path, so that is the common
	// case. Go's ServeMux routes HEAD here too, so a scanner could destroy a
	// message without even being shown it.
	//
	// Consumption belongs in POST .../open, behind a deliberate click — the
	// same shape handlePickupBlob already uses for the client-sealed path.
	//
	s.serveServerSealedLandingPage(w, id, token)
}

// handlePickupOpen consumes a server-sealed pickup record and renders it.
//
// POST /pickup/{id}/open?t=<token>
//
// POST rather than GET on purpose: this is the call that burns the message, and
// it must not be reachable by a crawler, a prefetch, a link-preview fetch, or a
// HEAD probe. There is no CSRF concern to trade against — the endpoint is
// unauthenticated and carries no ambient authority, so the token in the URL is
// the entire capability, and an attacker who has it does not need the victim's
// browser.
func (s *Server) handlePickupOpen(w http.ResponseWriter, r *http.Request) {
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

	subject, body, mode, err := s.pickupStore.View(id)
	if err != nil {
		http.Error(w, "this message has already been viewed or has expired", http.StatusGone)
		return
	}
	body = s.pickupDisplayBody(body, mode)

	var buf bytes.Buffer
	if err := serverSealedMessageTemplate.Execute(&buf, struct{ Subject, Body string }{subject, body}); err != nil {
		// The link is already burned by View, so there is nothing to retry and
		// no second chance to render. Say so rather than showing a blank page.
		s.logger.Error("failed to render pickup message page", "error", err.Error())
		http.Error(w, "the message could not be displayed, and this link has now been used", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

// serverSealedMessagePage renders the decrypted message.
//
// html/template, not fmt.Fprintf with html.EscapeString — the rule the landing
// page below already followed, applied to the page that actually carries
// sender-controlled content. The two renderers sat fifteen lines apart with
// different escaping strategies, and serverSealedLandingTemplate's own comment
// called the other one wrong: "a hand-rolled fmt.Sprintf here would put an
// attacker-adjacent value into a format string".
//
// html.EscapeString happened to be sufficient for these two sinks (element text
// in <title> and <pre>), so this is not a fix for a live hole. It removes the
// standing invitation to add a third interpolation — into an attribute, a URL,
// or a style — where manual escaping stops being sufficient and nothing would
// have flagged it.
const serverSealedMessagePage = `<!doctype html><html><head><meta charset="utf-8">` +
	`<title>{{.Subject}}</title><meta name="robots" content="noindex,nofollow"></head>` +
	`<body style="font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px">` +
	`<h1>{{.Subject}}</h1>` +
	`<pre style="white-space:pre-wrap;font-family:inherit">{{.Body}}</pre>` +
	`<p style="color:#666">This message has now been marked as viewed and cannot be retrieved again.</p>` +
	`</body></html>`

var serverSealedMessageTemplate = template.Must(template.New("pickupMessage").Parse(serverSealedMessagePage))

// serverSealedLandingPage is the shell shown before the message is read. It
// contains no message content — not even the subject — so fetching it
// discloses nothing, and it consumes nothing, so fetching it costs nothing.
//
// A plain form rather than script: the app-wide CSP forbids inline script, and
// this needs to work for a recipient who has no account here and may well be
// reading in a stripped-down client. A form POST is also precisely the thing
// automated link-followers do not do.
const serverSealedLandingPage = `<!doctype html><html><head><meta charset="utf-8">` +
	`<title>You have a message</title><meta name="robots" content="noindex,nofollow"></head>` +
	`<body style="font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px">` +
	`<h1>You have a message</h1>` +
	`<p>Someone sent you a message that can be read <strong>once</strong>. ` +
	`Opening it marks it as read, and it cannot be retrieved again afterwards.</p>` +
	`<form method="post" action="/pickup/{{.PickupID}}/open?t={{.PickupToken}}">` +
	`<button type="submit" style="font-size:1rem;padding:10px 18px;cursor:pointer">Read the message</button>` +
	`</form>` +
	`<p style="color:#666">If you did not expect this, you can close this page — ` +
	`the message stays unread and expires on its own.</p>` +
	`</body></html>`

// serverSealedLandingTemplate is parsed once at startup, using html/template
// for the same reason its client-sealed counterpart does: the escaping is
// context-aware, and a hand-rolled fmt.Sprintf here would put an
// attacker-adjacent value into a format string.
var serverSealedLandingTemplate = template.Must(template.New("pickupLanding").Parse(serverSealedLandingPage))

func (s *Server) serveServerSealedLandingPage(w http.ResponseWriter, id, token string) {
	var buf bytes.Buffer
	if err := serverSealedLandingTemplate.Execute(&buf, struct{ PickupID, PickupToken string }{id, token}); err != nil {
		s.logger.Error("failed to render pickup landing page", "error", err.Error())
		http.Error(w, "failed to render pickup page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

// pickupDisplayBody turns a stored body into what the pickup page shows.
//
// An HTML body is flattened to readable text rather than rendered as markup.
// Same rule as pickup-decrypt.js: this page has no sanitizer and shares an
// origin with the app, so the sender's markup must never become live HTML.
// Escaping without flattening is the other wrong answer — it shows the
// recipient the tags instead of the message.
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
	// From here on, every failure return has to take the record with it.
	//
	// The record exists before the link does and long before the link is
	// delivered, so any failure below leaves a live seven-day record for a link
	// that reached nobody — unopenable, unresendable, and holding one of the
	// sender's maxOutstandingPickupsPerUser slots the whole time. An SMTP outage
	// plus an ordinary amount of retrying used to spend the entire cap on those,
	// after which real pickup sends were refused for a week.
	discard := func(wrapped error) error {
		if derr := s.pickupStore.Discard(userID, id); derr != nil {
			// Worth knowing about — it means a slot is leaking — but the send
			// failure is what the caller needs reported.
			s.logger.Error("failed to discard undelivered pickup record", "id", id, "error", derr.Error())
		}
		return wrapped
	}

	token, _, err := s.createPairingToken(id, pairingPurposePickupLink, pickupLinkTTL)
	if err != nil {
		return discard(fmt.Errorf("create pickup token: %w", err))
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
	var sendErr error
	if smtpPort == 465 {
		sendErr = mailmsg.SMTPSendWithImplicitTLS(smtpHost, smtpPort, smtpUsername, smtpPassword, from, recipients, notice, 45*time.Second)
	} else {
		auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)
		sendErr = mailmsg.SMTPSendWithTimeout(addr, auth, from, recipients, notice, 45*time.Second)
	}
	if sendErr != nil {
		// Not every failure means the link went nowhere. If the server accepted
		// the message and only the session teardown failed, the recipient has
		// the link in their inbox — deleting the record would hand them a 410
		// for a message they were told about, with no way to ask for it again.
		// A leaked quota slot is recoverable; that is not. Keep the record and
		// let the sweeper collect it if the link really is never used.
		if errors.Is(sendErr, mailmsg.ErrSMTPAcceptedThenFailed) {
			s.logger.Error("pickup link accepted by the smtp server but the session failed; keeping the record",
				"recipient", recipient, "error", sendErr.Error())
			return sendErr
		}
		return discard(sendErr)
	}
	return nil
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

// minPairingSecretLength is the shortest operator-supplied PAIRING_SECRET this
// server will sign with.
//
// 32 BYTES of the value as supplied — len() on the raw string, which for the
// ASCII that `openssl rand -base64 32` produces is also 32 characters.
//
// Bytes rather than runes because bytes are what reaches hmac.New: the value is
// used as the key verbatim, so its length in bytes is the length of the key.
// Counting runes would reject a secret for containing multi-byte characters
// while accepting a shorter ASCII one carrying less key material.
//
// It is deliberately NOT a check on 32 bytes of DECODED entropy. That would
// mean mandating an encoding, and it would break every existing deployment that
// set a long passphrase, for no real gain — a 32-byte passphrase is already far
// past the point where guessing an HMAC key is the cheapest attack available.
// What this is here to reject is "hunter2".
//
// The server's own generated secret is 32 random bytes base64'd (44 bytes of
// ASCII), so the default path clears this bar by construction.
const minPairingSecretLength = 32

// resolvePairingSecret returns the HMAC secret used to sign pickup links, PGP
// QR key-exchange tokens and device pairing tokens.
//
// The environment variable wins when set. Otherwise the secret is GENERATED and
// persisted at keyPath, exactly as every other key in this system already is
// (IMAP_CONFIG_KEY_FILE, TOTP_SECRET_KEY_FILE, PGP_PRIVATE_KEY_FILE,
// PICKUP_STORE_KEY_FILE all go through cryptutil.LoadOrCreateKey).
//
// Generated rather than operator-invented. An unset value fails closed (503,
// logged), and so, now, does a weak one: an operator-supplied secret shorter
// than minPairingSecretLength is REFUSED rather than used. "PAIRING_SECRET=
// hunter2" used to be accepted silently and produced forgeable HMACs for
// pickup links, device pairing tokens and PGP QR key exchange — one guessable
// string standing behind three separate capabilities.
//
// Refused, not fallen back from. Quietly generating a file secret instead would
// hand a multi-replica deployment a different secret per replica, so links
// signed by one would fail to verify on another — an intermittent, load-
// balancer-dependent failure, which is a worse thing to debug than a feature
// that is off and says so.
//
// The environment override stays because a multi-replica deployment needs every
// replica to agree on one secret, which a per-container generated file cannot
// provide. An operator-supplied value of adequate length is used verbatim and
// writes no file.
//
// A generation failure — read-only secrets volume, bad permissions — returns
// "", which every consumer already reads as "not configured" and answers 503
// to. Failing closed is the pre-existing behaviour and is the right one: a
// weak-but-present secret would be worse than a disabled feature.
func resolvePairingSecret(keyPath string, logger *logging.Logger) string {
	if fromEnv := strings.TrimSpace(os.Getenv("PAIRING_SECRET")); fromEnv != "" {
		if len(fromEnv) < minPairingSecretLength {
			if logger != nil {
				logger.Error("PAIRING_SECRET is too short to sign anything with; pickup links, device pairing and PGP QR key-exchange stay disabled",
					"length", strconv.Itoa(len(fromEnv)),
					"minimum", strconv.Itoa(minPairingSecretLength),
					"remedy", "set PAIRING_SECRET to at least "+strconv.Itoa(minPairingSecretLength)+
						" random characters (openssl rand -base64 32), or unset it and let the server generate one")
			}
			return ""
		}
		return fromEnv
	}

	key, err := cryptutil.LoadOrCreateKey(keyPath)
	if err != nil {
		if logger != nil {
			logger.Error("could not generate or read the pairing secret; pickup links and PGP QR key-exchange stay disabled")
		}
		return ""
	}
	// Base64 rather than the raw bytes: the field is a string that reaches
	// hmac.New either way, and keeping it printable means it looks like an
	// operator-supplied value everywhere it might surface. Same 256 bits.
	return base64.StdEncoding.EncodeToString(key)
}
