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

// isArmoredPGPMessage delegates to the IMAP adapter's check rather than
// spelling the prefix out again. This file used to carry its own copy with a
// comment claiming the two were "kept the same" — they were not: the adapter's
// test is anchored at byte 0 (gopenpgp's regexp is ^-anchored) while this one
// trimmed leading whitespace first, so a part could be ciphertext here and not
// there. Two spellings of "is this ciphertext" is how the listing and the
// download came to disagree; there is now one.
//
// It is also byte-wise. The previous form converted the whole attachment to a
// string to look at its first 27 bytes, which for a 25 MiB part is a 25 MiB
// copy on every list and every download.
func isArmoredPGPMessage(content []byte) bool {
	return imapadapter.IsArmoredPGPMessage(content)
}

// looksLikeEncryptedEnvelope reports whether a message's outer parts have the
// shape of PGP/MIME: every part is one an envelope could contain.
//
// This deliberately does NOT count parts. It used to require exactly one, which
// never matched a real encrypted message: enmime files the ciphertext under
// both Attachments and Inlines (it carries an inline disposition AND a
// filename), goimap concatenates the two, so the same part arrives here twice.
// The listing therefore only looked inside encrypted mail in tests, where the
// fake supplied a single part. Pinned by TestLooksLikeEncryptedEnvelope.
//
// Requiring EVERY part to be envelope-typed is what keeps an ordinary message
// carrying an encrypted file out: document.pgp next to report.xlsx has a part
// no envelope could contain, so it is left alone and its attachments are served
// as themselves. This matches imap.pgpEnvelopePayload, which makes the same
// judgement on content for the inbox listing — change one, change both, or a
// message shows a padlock in the list and refuses to open its attachments.
//
// A cheap prefilter on metadata already in hand. Without it, confirming a
// message is encrypted would mean fetching its first part on every attachment
// listing — doubling the IMAP work for the ordinary unencrypted message, which
// is nearly all of them. A false positive here costs one fetch and is then
// rejected on content by isArmoredPGPMessage; a false negative just leaves
// today's behavior.
func looksLikeEncryptedEnvelope(infos []imapadapter.AttachmentInfo) bool {
	if len(infos) == 0 {
		return false
	}
	for _, info := range infos {
		if !imapadapter.IsPGPEnvelopePartType(info.MimeType) {
			return false
		}
	}
	return true
}

// messageIsEncryptedEnvelope asks the same question serveAttachmentList asks,
// so the download path cannot decide a message is encrypted when the listing
// decided it was not. A listing failure answers false: serving the bytes the
// reader asked for is the safe direction when the message's shape is unknown.
func (s *Server) messageIsEncryptedEnvelope(r *http.Request, mailClient imapadapter.Client, mailbox string, uid int) bool {
	infos, err := mailClient.ListAttachments(r.Context(), mailbox, uid)
	if err != nil {
		s.logger.Error("attachment envelope check failed", "mailbox", mailbox, "uid", strconv.Itoa(uid), "error", err.Error())
		return false
	}
	return looksLikeEncryptedEnvelope(infos)
}

// pgpInnerAttachments decrypts an armored payload and returns the attachments
// inside it. Reports false when this server cannot open it — no auth context,
// no key, a client-protected account (whose ciphertext is the browser's to
// unwrap), or a decrypt failure. Every one of those falls back to serving the
// outer parts, which is what happened before.
func (s *Server) pgpInnerAttachments(r *http.Request, armored []byte) ([]mailmsg.Attachment, bool) {
	ac, ok := authFromContext(r)
	if !ok {
		return nil, false
	}
	result := s.decryptPGPPayload(ac.UserID, string(armored))
	if result.KeepPayload || result.DecryptError != "" {
		return nil, false
	}
	return result.Attachments, true
}

// attachmentInfos renders decrypted attachments in the wire shape
// ListAttachments produces, so both paths answer identically.
func attachmentInfos(attachments []mailmsg.Attachment) []imapadapter.AttachmentInfo {
	infos := make([]imapadapter.AttachmentInfo, 0, len(attachments))
	for i, a := range attachments {
		infos = append(infos, imapadapter.AttachmentInfo{
			Index:    i,
			Name:     a.Name,
			MimeType: a.MimeType,
			Size:     len(a.Content),
		})
	}
	return infos
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
	// An encrypted message's outer parts are all ciphertext (the same armored
	// part, usually listed twice — see looksLikeEncryptedEnvelope); the files
	// the reader asked for are inside it.
	if looksLikeEncryptedEnvelope(infos) {
		if _, content, ferr := mailClient.GetAttachment(r.Context(), mailbox, uid, 0); ferr == nil && isArmoredPGPMessage(content) {
			if inner, ok := s.pgpInnerAttachments(r, content); ok {
				infos = attachmentInfos(inner)
			}
		}
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

	// The index the reader clicked addresses whatever serveAttachmentList
	// showed them. For an encrypted message that is the DECRYPTED list, so the
	// index has to be resolved inside the ciphertext: index 0 would otherwise
	// land on the armored payload itself and anything past the outer parts
	// would miss entirely. Both mean the same thing here.
	//
	// Probing part 0 only in those two cases keeps the ordinary unencrypted
	// download at the single fetch it has always been.
	probe := content
	if errors.Is(err, imapadapter.ErrAttachmentNotFound) {
		_, probe, _ = mailClient.GetAttachment(r.Context(), mailbox, uid, 0)
	}
	// Armored content is not on its own permission to decrypt and re-index.
	// An ordinary message can carry an encrypted FILE — archive.pgp among a
	// report and a spreadsheet — and that file is what the reader asked for,
	// listed at this very index. Treating it as an envelope would hand back
	// some unrelated attachment from inside it, or a 404, for a file the list
	// says exists. The message must be an envelope by the same test the
	// listing used, or the bytes are served as themselves.
	if isArmoredPGPMessage(probe) && s.messageIsEncryptedEnvelope(r, mailClient, mailbox, uid) {
		if inner, ok := s.pgpInnerAttachments(r, probe); ok {
			if index >= len(inner) {
				http.Error(w, "attachment not found", http.StatusNotFound)
				return
			}
			a := inner[index]
			info = imapadapter.AttachmentInfo{Index: index, Name: a.Name, MimeType: a.MimeType, Size: len(a.Content)}
			content, err = a.Content, nil
		}
	}

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
