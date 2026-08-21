// Per-user IMAP/SMTP credential storage (encrypted at rest) and the
// connectivity test.
package api

import (
	"encoding/json"
	"errors"
	"io"
	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/cryptutil"
	"kypost-server/backend/internal/fsutil"
	"kypost-server/backend/internal/mailmsg"
	"net/http"

	"os"
	"path/filepath"
	"strings"
	"time"

	goimap "github.com/BrianLeishman/go-imap"
)

func (s *Server) handleIMAPConfig(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	imapConfigPath := s.userIMAPConfigPath(ac.UserID)
	switch r.Method {
	case http.MethodGet:
		payload, exists, err := mailmsg.ReadIMAPConfigPayload(imapConfigPath, s.imapConfigKeyPath)
		if err != nil {
			http.Error(w, "failed to read imap configuration", http.StatusInternalServerError)
			return
		}
		if !exists {
			writeJSON(w, http.StatusOK, map[string]any{"configured": false, "path": imapConfigPath, "keyPath": s.imapConfigKeyPath})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"configured":      true,
			"path":            imapConfigPath,
			"keyPath":         s.imapConfigKeyPath,
			"host":            payload.Host,
			"port":            payload.Port,
			"username":        payload.Username,
			"mailbox":         payload.Mailbox,
			"smtpHost":        payload.SMTPHost,
			"smtpPort":        payload.SMTPPort,
			"updatedAt":       payload.UpdatedAt,
			"encryptedAtRest": true,
		})
	case http.MethodPost:
		var payload imapConfigPayload
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		payload = mailmsg.NormalizeIMAPPayload(payload)
		if payload.Host == "" || payload.Username == "" || payload.Password == "" {
			http.Error(w, "host, username, and password are required", http.StatusBadRequest)
			return
		}
		// NormalizeIMAPPayload only trims and defaults. The mailbox is
		// interpolated into a SELECT by go-imap, which escapes only the double
		// quote, so an unvalidated value persisted here is re-executed on every
		// connect by both the API and the unattended daemon.
		if err := imapadapter.ValidateMailboxName(payload.Mailbox); err != nil {
			http.Error(w, "invalid mailbox name", http.StatusBadRequest)
			return
		}
		payload.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

		if err := os.MkdirAll(filepath.Dir(imapConfigPath), 0o700); err != nil {
			http.Error(w, "failed to create imap configuration directory", http.StatusInternalServerError)
			return
		}
		if err := writeIMAPConfigPayload(imapConfigPath, s.imapConfigKeyPath, payload); err != nil {
			http.Error(w, "failed to save imap configuration", http.StatusInternalServerError)
			return
		}
		s.invalidateUserMail(ac.UserID)

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":              true,
			"configured":      true,
			"path":            imapConfigPath,
			"keyPath":         s.imapConfigKeyPath,
			"host":            payload.Host,
			"port":            payload.Port,
			"username":        payload.Username,
			"mailbox":         payload.Mailbox,
			"smtpHost":        payload.SMTPHost,
			"smtpPort":        payload.SMTPPort,
			"updatedAt":       payload.UpdatedAt,
			"encryptedAtRest": true,
		})
	case http.MethodDelete:
		if err := os.Remove(imapConfigPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			http.Error(w, "failed to remove imap configuration", http.StatusInternalServerError)
			return
		}
		s.invalidateUserMail(ac.UserID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "configured": false})
	}
}

func (s *Server) handleIMAPTest(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	// A malformed body is refused rather than silently read as "no fields
	// supplied", which is a different request: the all-or-nothing rule below
	// treats an empty payload as "test the stored configuration". An empty body
	// (io.EOF) really is that request and stays valid.
	var req imapConfigPayload
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid imap test payload", http.StatusBadRequest)
		return
	}

	// All-or-nothing, deliberately. The fallback used to be applied per field,
	// so a caller who supplied only a host — leaving username and password
	// blank — got the *stored* credentials filled in around their chosen
	// destination, and the server then performed an IMAP LOGIN with the
	// victim's real mail password against a server the caller controlled.
	// GET /api/imap/config never returns that password precisely because it is
	// the account's most durable secret (it is the SMTP password too, and it
	// survives every KyPost-side revocation), and this was the one path that
	// handed it out. A caller-chosen destination must never be paired with a
	// server-held secret.
	suppliedHost := strings.TrimSpace(req.Host) != ""
	suppliedUser := strings.TrimSpace(req.Username) != ""
	suppliedPass := strings.TrimSpace(req.Password) != ""
	switch {
	case !suppliedHost && !suppliedUser && !suppliedPass:
		stored, exists, err := mailmsg.ReadIMAPConfigPayload(s.userIMAPConfigPath(ac.UserID), s.imapConfigKeyPath)
		if err != nil {
			http.Error(w, "failed to load imap configuration", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "host, username, and password are required (or store IMAP config first)", http.StatusBadRequest)
			return
		}
		mailbox := strings.TrimSpace(req.Mailbox)
		req = stored
		if mailbox != "" {
			req.Mailbox = mailbox
		}
	case !suppliedHost || !suppliedUser || !suppliedPass:
		http.Error(w, "supply host, username, and password together, or none of them", http.StatusBadRequest)
		return
	}

	req = mailmsg.NormalizeIMAPPayload(req)

	// The comment above forbids pairing a caller-chosen DESTINATION with a
	// server-held secret. The same rule applies to the caller-chosen COMMAND:
	// on the all-blank branch every credential below is the stored one, so an
	// unvalidated mailbox here is arbitrary IMAP executed under a password the
	// caller does not know and the API never hands out.
	if err := imapadapter.ValidateMailboxName(req.Mailbox); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid mailbox name"})
		return
	}

	client, err := goimap.New(req.Username, req.Password, req.Host, req.Port)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer client.Close()

	if err := client.SelectFolder(req.Mailbox); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host": req.Host, "port": req.Port, "mailbox": req.Mailbox})
}

func writeIMAPConfigPayload(path, keyPath string, payload imapConfigPayload) error {
	plain, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return writeEncryptedPayload(path, keyPath, plain)
}

func writeEncryptedPayload(path, keyPath string, payload []byte) error {
	key, err := cryptutil.LoadOrCreateKey(keyPath)
	if err != nil {
		return err
	}

	env, err := cryptutil.Seal(payload, key)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}

	return fsutil.AtomicWriteFile(path, b, 0o600)
}

// decryptEncryptedPayload reverses writeEncryptedPayload. It is a thin
// alias for cryptutil.OpenBytes, kept so the several call sites in this
// package read symmetrically with their write side; see OpenBytes for why
// there is no plaintext fallback.
func decryptEncryptedPayload(raw []byte, keyPath string) ([]byte, error) {
	return cryptutil.OpenBytes(raw, keyPath)
}
