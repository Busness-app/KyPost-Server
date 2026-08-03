package mailmsg

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"time"

	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/cryptutil"
)

// IMAPConfigPayload is a user's stored IMAP/SMTP mail credentials, encrypted
// at rest on disk. Moved here (from package api) so the SMTP-send helpers
// below — used by both the API's outbound-send handlers and the mail
// poller's own notification path — can share one definition without an
// api->processor->api import cycle.
type IMAPConfigPayload struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Mailbox   string `json:"mailbox"`
	SMTPHost  string `json:"smtpHost,omitempty"`
	SMTPPort  int    `json:"smtpPort,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

// PreparedSMTPMessage is a message that has passed NormalizeSMTPMessage.
// Callers receiving complete MIME from an end-to-end client must prepare it
// before it can enter an SMTP delivery call.
type PreparedSMTPMessage struct {
	data []byte
}

// PrepareSMTPMessage validates and normalizes a complete MIME message before
// it crosses the SMTP transport boundary.
func PrepareSMTPMessage(msg []byte) (PreparedSMTPMessage, error) {
	normalized, err := NormalizeSMTPMessage(msg)
	if err != nil {
		return PreparedSMTPMessage{}, err
	}
	return PreparedSMTPMessage{data: normalized}, nil
}

// NormalizeIMAPPayload applies default values and trimming to an IMAP config
// payload.
func NormalizeIMAPPayload(p IMAPConfigPayload) IMAPConfigPayload {
	p.Host = strings.TrimSpace(p.Host)
	p.Username = strings.TrimSpace(p.Username)
	p.Password = strings.TrimSpace(p.Password)
	p.Mailbox = strings.TrimSpace(p.Mailbox)
	p.SMTPHost = strings.TrimSpace(p.SMTPHost)
	if p.Port <= 0 {
		p.Port = 993
	}
	if p.Mailbox == "" {
		p.Mailbox = "INBOX"
	}
	if p.SMTPHost != "" && p.SMTPPort <= 0 {
		p.SMTPPort = 587
	}
	return p
}

func deriveSMTPHost(imapHost string) string {
	host := strings.TrimSpace(imapHost)
	if host == "" {
		return ""
	}
	lower := strings.ToLower(host)
	if strings.HasPrefix(lower, "imap.") {
		return "smtp." + host[len("imap."):]
	}
	if strings.Contains(lower, ".imap.") {
		return strings.Replace(host, ".imap.", ".smtp.", 1)
	}
	return host
}

// ResolveSMTPTarget derives the SMTP host/port/address to use for a user's
// outbound mail from their stored IMAP config, applying the same fallback
// chain every outbound-send call site needs: the payload's own SMTPHost/
// SMTPPort, then SMTP_HOST/SMTP_PORT env vars, then a heuristic derived from
// the IMAP host, then a hardcoded default port of 587. Returns an error
// (rather than picking a call-site-specific HTTP status) when no host can be
// determined at all — callers translate that into whatever response is
// appropriate for their context.
func ResolveSMTPTarget(payload IMAPConfigPayload) (smtpHost string, smtpPort int, addr string, err error) {
	smtpHost = strings.TrimSpace(payload.SMTPHost)
	if smtpHost == "" {
		smtpHost = strings.TrimSpace(config.EnvOrDefault("SMTP_HOST", ""))
	}
	if smtpHost == "" {
		smtpHost = deriveSMTPHost(payload.Host)
	}
	if smtpHost == "" {
		return "", 0, "", fmt.Errorf("smtp host is not configured")
	}
	smtpPort = payload.SMTPPort
	if smtpPort <= 0 {
		smtpPort = config.EnvInt("SMTP_PORT", 587)
	}
	if smtpPort <= 0 {
		smtpPort = 587
	}
	return smtpHost, smtpPort, fmt.Sprintf("%s:%d", smtpHost, smtpPort), nil
}

// SMTPSendWithTimeout delivers msg over a STARTTLS (or, for a server that
// does not advertise it, plain) SMTP connection with a hard timeout on the
// whole conversation.
//
// It does NOT wrap smtp.SendMail in a goroutine with a select on
// time.After. That pattern times out the *caller* while the goroutine stays
// blocked in SendMail forever, holding its TCP connection, its TLS session,
// and its copy of msg — which can be MaxInboundMessageBytes (25 MiB). One
// unresponsive upstream then leaks a goroutine and 25 MiB per send attempt,
// and the poller and the user both retry. Setting a deadline on the
// connection instead makes every subsequent operation time-bounded, which
// is what "hard timeout" has to mean.
//
// STARTTLS is used whenever the server advertises it. If it does not,
// smtp.Auth's own refusal to send credentials over an unencrypted link
// (net/smtp returns "unencrypted connection") fails the send closed rather
// than leaking the password.
// AllowInsecureSMTP opts an operator out of the mandatory-STARTTLS rule below,
// for a genuinely plaintext relay on a trusted LAN. Off by default, and there
// is deliberately no per-request way to set it: a downgrade has to be a
// deployment decision, not something a caller or a remote server can trigger.
var AllowInsecureSMTP = strings.EqualFold(strings.TrimSpace(os.Getenv("ALLOW_INSECURE_SMTP")), "true")

// requireSTARTTLS decides whether a submission session that did not negotiate
// TLS may proceed to DATA.
//
// Opportunistic STARTTLS is not enough for submission. The capability check is
// advertised by the server, so an on-path attacker strips STARTTLS from the
// EHLO response and the session silently continues in cleartext. Stripping
// AUTH as well means client.Auth is never called, which is what would
// otherwise trigger net/smtp's own refusal to send credentials over an
// unencrypted link — so the one safety net that existed does not fire either,
// and the full message goes to the attacker while the user is shown a
// successful send. Thunderbird defaults new accounts to "STARTTLS, required"
// for the same reason.
func requireSTARTTLS(negotiatedTLS, allowInsecure bool) error {
	if negotiatedTLS || allowInsecure {
		return nil
	}
	return errors.New("smtp submission refused: server did not offer STARTTLS and ALLOW_INSECURE_SMTP is not set")
}

func SMTPSendWithTimeout(addr string, auth smtp.Auth, from string, recipients []string, msg []byte, timeout time.Duration) error {
	if err := validateSMTPEnvelope(from, recipients); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid smtp address %q: %w", addr, err)
	}

	conn, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	// One deadline for the entire conversation: dial, greeting, STARTTLS,
	// auth, and the DATA body all have to finish inside it.
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()

	negotiatedTLS := false
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
		negotiatedTLS = true
	}
	if err := requireSTARTTLS(negotiatedTLS, AllowInsecureSMTP); err != nil {
		return err
	}
	if auth != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(auth); err != nil {
				return err
			}
		}
	}
	return writeSMTPMessage(client, from, recipients, msg)
}

// ErrSMTPAcceptedThenFailed marks a send that the receiving server ACCEPTED
// before the session failed. Wrapped into the returned error so callers can
// tell it apart from a message that never got in.
//
// It exists for callers that undo work when a send fails. The pickup path
// deletes its stored record on failure, so that a link nobody received does not
// hold one of the sender's quota slots for seven days — but deleting on this
// error would throw away a message whose "you have mail" link is already in the
// recipient's inbox, leaving them a 410 and no way to ask for it again. Losing
// a quota slot is an annoyance; losing the message is not.
//
// The window is small and specific: net/smtp's data writer returning nil from
// Close() means the server answered 250 to the body, and QUIT is sent after
// that. Anything that breaks in between is a delivered message reported as a
// failure.
var ErrSMTPAcceptedThenFailed = errors.New("smtp: message was accepted but the session did not close cleanly")

// writeSMTPMessage runs the MAIL/RCPT/DATA/QUIT half of a send, shared by
// the STARTTLS and implicit-TLS paths.
func writeSMTPMessage(client *smtp.Client, from string, recipients []string, msg []byte) error {
	normalized, err := NormalizeSMTPMessage(msg)
	if err != nil {
		return err
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(normalized); err != nil {
		_ = writer.Close()
		return err
	}
	// Close() returning nil is the acceptance: the server has answered 250 to
	// the message body. Everything after this point is teardown, and a failure
	// in teardown does not un-deliver the message.
	if err := writer.Close(); err != nil {
		return err
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("%w: %w", ErrSMTPAcceptedThenFailed, err)
	}
	return nil
}

// NormalizeSMTPMessage makes caller-provided message bytes safe for the SMTP
// DATA stream. MIME bodies may legitimately contain line breaks, so removing
// CR/LF would corrupt mail; instead, all line endings are made RFC 5322 CRLF.
// NUL bytes and overlong physical lines are rejected because they are not
// valid message data and can make different SMTP/MIME parsers disagree about
// where content ends. The returned slice is a copy when normalization is
// needed and otherwise aliases msg.
func NormalizeSMTPMessage(msg []byte) ([]byte, error) {
	if bytes.IndexByte(msg, 0) >= 0 {
		return nil, errors.New("smtp message contains NUL byte")
	}

	var normalized []byte
	for i := 0; i < len(msg); i++ {
		if msg[i] == '\r' && (i+1 >= len(msg) || msg[i+1] != '\n') {
			if normalized == nil {
				normalized = make([]byte, 0, len(msg)+1)
				normalized = append(normalized, msg[:i]...)
			}
			normalized = append(normalized, '\r', '\n')
			continue
		}
		if msg[i] == '\n' && (i == 0 || msg[i-1] != '\r') {
			if normalized == nil {
				normalized = make([]byte, 0, len(msg)+1)
				normalized = append(normalized, msg[:i]...)
			}
			normalized = append(normalized, '\r', '\n')
			continue
		}
		if normalized != nil {
			normalized = append(normalized, msg[i])
		}
	}
	if normalized == nil {
		normalized = msg
	}

	lineStart := 0
	for i, b := range normalized {
		if b == '\n' {
			if i-lineStart > 998 {
				return nil, errors.New("smtp message contains a line longer than 998 bytes")
			}
			lineStart = i + 1
		}
	}
	if len(normalized)-lineStart > 998 {
		return nil, errors.New("smtp message contains a line longer than 998 bytes")
	}
	return normalized, nil
}

// SMTPSendWithImplicitTLS delivers msg over an implicit-TLS (port 465 style)
// SMTP connection, since net/smtp only supports STARTTLS natively.
func SMTPSendWithImplicitTLS(host string, port int, username, password, from string, recipients []string, msg []byte, timeout time.Duration) error {
	if err := validateSMTPEnvelope(from, recipients); err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()

	if ok, _ := client.Extension("AUTH"); ok {
		auth := smtp.PlainAuth("", username, password, host)
		if err := client.Auth(auth); err != nil {
			return err
		}
	}

	return writeSMTPMessage(client, from, recipients, msg)
}

// SMTPDeliver sends msg over SMTP to recipients, choosing implicit TLS (port
// 465) or STARTTLS/plain auth otherwise.
func SMTPDeliver(smtpHost string, smtpPort int, addr, smtpUsername, smtpPassword, from string, recipients []string, msg []byte) error {
	if err := validateSMTPEnvelope(from, recipients); err != nil {
		return err
	}
	if smtpPort == 465 {
		return SMTPSendWithImplicitTLS(smtpHost, smtpPort, smtpUsername, smtpPassword, from, recipients, msg, 45*time.Second)
	}
	auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)
	return SMTPSendWithTimeout(addr, auth, from, recipients, msg, 45*time.Second)
}

// SMTPDeliverPrepared relays a complete MIME message after its caller has
// explicitly passed it through PrepareSMTPMessage.
func SMTPDeliverPrepared(smtpHost string, smtpPort int, addr, smtpUsername, smtpPassword, from string, recipients []string, msg PreparedSMTPMessage) error {
	if err := validateSMTPEnvelope(from, recipients); err != nil {
		return err
	}
	if smtpPort == 465 {
		return SMTPSendWithImplicitTLS(smtpHost, smtpPort, smtpUsername, smtpPassword, from, recipients, msg.data, 45*time.Second)
	}
	auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)
	return SMTPSendWithTimeout(addr, auth, from, recipients, msg.data, 45*time.Second)
}

// validateSMTPEnvelope keeps request/config-derived values out of the SMTP
// command stream. net/smtp formats these strings into MAIL FROM and RCPT TO
// commands; accepting a display name, CR/LF, or an invalid address here would
// let different SMTP servers parse a caller-controlled envelope differently.
func validateSMTPEnvelope(from string, recipients []string) error {
	if err := validateSMTPAddress("sender", from); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err := validateSMTPAddress("recipient", recipient); err != nil {
			return err
		}
	}
	return nil
}

func validateSMTPAddress(kind, value string) error {
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("invalid smtp %s address", kind)
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value {
		return fmt.Errorf("invalid smtp %s address", kind)
	}
	return nil
}

// ErrIMAPConfigNotEncrypted is returned by ReadIMAPConfigPayload when the
// stored config is not a valid encryption envelope. The message names the
// remedy because an operator hitting this needs to know it is fixable.
var ErrIMAPConfigNotEncrypted = errors.New(
	"IMAP config is not encrypted (written before encryption-at-rest, or corrupt); " +
		"re-save your IMAP/SMTP settings to rewrite it encrypted")

// ReadIMAPConfigPayload reads and decrypts the IMAP/SMTP config payload
// stored at path, decrypting it with the master key at keyPath. exists is
// false (with a nil error) when no config file has been saved yet.
func ReadIMAPConfigPayload(path, keyPath string) (IMAPConfigPayload, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return IMAPConfigPayload{}, false, nil
		}
		return IMAPConfigPayload{}, false, err
	}

	plain, err := cryptutil.OpenBytes(b, keyPath)
	if errors.Is(err, cryptutil.ErrNotEncrypted) {
		return IMAPConfigPayload{}, false, fmt.Errorf("%s: %w", path, ErrIMAPConfigNotEncrypted)
	}
	if err != nil {
		return IMAPConfigPayload{}, false, err
	}

	var payload IMAPConfigPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return IMAPConfigPayload{}, false, err
	}
	return NormalizeIMAPPayload(payload), true, nil
}
