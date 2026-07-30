// Attachment listing and download.
package api

import (
	"errors"
	"kypost-server/backend/internal/mailmsg"
	"mime"
	"net/http"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"strconv"
	"strings"
)

// attachmentRequestParams reads the shared mailbox/messageId query params of
// the two attachment endpoints. messageId is an IMAP UID, the same id shape
// /api/inbox and /api/inbox/actions use.
func attachmentRequestParams(r *http.Request) (mailbox string, uid int, err error) {
	mailbox = strings.TrimSpace(r.URL.Query().Get("mailbox"))
	uid, err = strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("messageId")))
	if err != nil || uid <= 0 {
		return "", 0, errors.New("valid messageId is required")
	}
	return mailbox, uid, nil
}

// handleMailAttachmentList returns attachment metadata for one message.
// GET /api/mail/attachments?sub=&hash=&mailbox=&messageId=
func (s *Server) handleMailAttachmentList(w http.ResponseWriter, r *http.Request) {
	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}
	s.serveAttachmentList(w, r, mailClient)
}

func (s *Server) serveAttachmentList(w http.ResponseWriter, r *http.Request, mailClient imapadapter.Client) {
	mailbox, uid, err := attachmentRequestParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	infos, err := mailClient.ListAttachments(r.Context(), mailbox, uid)
	if err != nil {
		s.logger.Error("attachment list failed", "mailbox", mailbox, "uid", strconv.Itoa(uid), "error", err.Error())
		http.Error(w, "failed to list attachments", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "attachments": infos})
}

// handleMailAttachmentDownload streams one attachment's bytes.
// GET /api/mail/attachment?sub=&hash=&mailbox=&messageId=&index=
func (s *Server) handleMailAttachmentDownload(w http.ResponseWriter, r *http.Request) {
	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}
	s.serveAttachmentDownload(w, r, mailClient)
}

func (s *Server) serveAttachmentDownload(w http.ResponseWriter, r *http.Request, mailClient imapadapter.Client) {
	mailbox, uid, err := attachmentRequestParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	index, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("index")))
	if err != nil || index < 0 {
		http.Error(w, "valid index is required", http.StatusBadRequest)
		return
	}
	info, content, err := mailClient.GetAttachment(r.Context(), mailbox, uid, index)
	if errors.Is(err, imapadapter.ErrAttachmentNotFound) {
		http.Error(w, "attachment not found", http.StatusNotFound)
		return
	}
	if err != nil {
		s.logger.Error("attachment fetch failed", "mailbox", mailbox, "uid", strconv.Itoa(uid), "error", err.Error())
		http.Error(w, "failed to fetch attachment", http.StatusBadGateway)
		return
	}

	// The media type is sender-controlled, and Content-Disposition: attachment
	// governs NAVIGATION only — browsers honour a JavaScript type on a
	// subresource fetch, so <script src=...> against this endpoint executed on
	// our own origin. nosniff does not help: it blocks types that are NOT
	// script, and the sender simply picks one that is. That turns
	// script-src 'self' into "and anything anyone mails you", which is exactly
	// the backstop the CSP exists to provide.
	contentType := normalizeAttachmentContentType(info.MimeType)
	name := mailmsg.SanitizeHeaderValue(info.Name)
	if name == "" {
		name = "attachment"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType(
		"attachment", map[string]string{"filename": name},
	))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	// Not cacheable: the URL is a small integer pair, so a cached response is a
	// per-URL gadget that outlives the message.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

// safeAttachmentContentTypes are the media types served as-is. Everything else
// downloads as an opaque octet-stream, which is what Content-Disposition:
// attachment already implies.
var safeAttachmentContentTypes = map[string]bool{
	"image/jpeg":      true,
	"image/png":       true,
	"image/gif":       true,
	"image/webp":      true,
	"image/bmp":       true,
	"image/tiff":      true,
	"application/pdf": true,
	"text/plain":      true,
	"text/csv":        true,
}

// normalizeAttachmentContentType maps a sender-supplied MIME type onto the
// allowlist. Note image/svg+xml is deliberately absent: it is script-bearing.
func normalizeAttachmentContentType(raw string) string {
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(raw))
	if err != nil {
		return "application/octet-stream"
	}
	if safeAttachmentContentTypes[strings.ToLower(mediaType)] {
		return strings.ToLower(mediaType)
	}
	return "application/octet-stream"
}
