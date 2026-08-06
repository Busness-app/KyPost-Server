// Mailbox reading: the inbox DTOs, keyword/tab bucketing, the cache-backed
// delta path (serveInbox), folder management, message actions, and search.
//
// This is the one part of the HTTP surface with real domain logic rather than
// request plumbing, which is why it earns its own file.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/mailcache"
)

type inboxEmail struct {
	MessageID string `json:"messageId"`
	Sender    string `json:"sender"`
	SentTo    string `json:"sentTo,omitempty"`
	CC        string `json:"cc,omitempty"`
	BCC       string `json:"bcc,omitempty"`
	Subject   string `json:"subject"`
	Body      string `json:"body,omitempty"`
	// BodyMode is "html" or "plain": which MIME part Body was taken from.
	// Absent means the server does not know (a cache entry written before this
	// field existed, or a body only the client can decrypt), and the client
	// falls back to a conservative sniff. See imapadapter.clientBody.
	BodyMode string `json:"bodyMode,omitempty"`
	Label    string `json:"label,omitempty"`
	// Keywords is every raw IMAP keyword flag on the message (unlike Label,
	// which is just the first one matching an allowlisted tab). Stamped in
	// bucket() alongside Label so every code path that builds an inboxEmail
	// gets it for free.
	Keywords []string `json:"keywords,omitempty"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	AtUTC    string   `json:"atUtc"`
	// HasAttachments is a warm-path hint for the inbox paperclip badge; see
	// mailcache.Entry.HasAttachments. Absent when false.
	HasAttachments bool `json:"hasAttachments,omitempty"`
	// PGPEncrypted/PGPSigned/PGPVerified/PGPSignerFingerprint/
	// PGPDecryptError mirror imapadapter.MessageContent's PGP fields once
	// decryptPGPMessageContent/decryptPGPUnreadMessage has run.
	PGPEncrypted         bool   `json:"pgpEncrypted,omitempty"`
	PGPSigned            bool   `json:"pgpSigned,omitempty"`
	PGPVerified          bool   `json:"pgpVerified,omitempty"`
	PGPSignerFingerprint string `json:"pgpSignerFingerprint,omitempty"`
	PGPDecryptError      string `json:"pgpDecryptError,omitempty"`
	// ChangeType is only ever set on a delta (since=) response: "new" (Body
	// populated, client should insert) or "updated" (flags/label changed,
	// Body intentionally empty — the client already has it cached). Absent
	// entirely on classic responses, so old clients see no shape change.
	ChangeType string `json:"changeType,omitempty"`
}

type inboxFolder struct {
	Path      string `json:"path"`
	Deletable bool   `json:"deletable"`
}

func mailboxLeaf(path string) string {
	clean := strings.TrimSpace(path)
	if clean == "" {
		return ""
	}
	if idx := strings.LastIndexAny(clean, "/."); idx >= 0 && idx+1 < len(clean) {
		return strings.TrimSpace(clean[idx+1:])
	}
	return clean
}

func mailboxParentPath(path string) string {
	clean := strings.TrimSpace(path)
	idx := strings.LastIndexAny(clean, "/.")
	if idx <= 0 {
		return ""
	}
	return clean[:idx]
}

func isBuiltinMailbox(path string) bool {
	leaf := strings.ToLower(mailboxLeaf(path))
	switch leaf {
	case "inbox", "archive", "drafts", "draft", "sent", "sent items", "spam", "junk", "trash", "deleted items":
		return true
	default:
		return false
	}
}

func toInboxFolders(paths []string) []inboxFolder {
	folders := make([]inboxFolder, 0, len(paths))
	for _, folder := range paths {
		clean := strings.TrimSpace(folder)
		if clean == "" {
			continue
		}
		folders = append(folders, inboxFolder{
			Path:      clean,
			Deletable: mailboxParentPath(clean) != "" && !isBuiltinMailbox(clean),
		})
	}
	return folders
}

func firstMatchingKeyword(keywords []string, allowed []string) string {
	if len(keywords) == 0 || len(allowed) == 0 {
		return ""
	}
	seen := map[string]string{}
	for _, keyword := range keywords {
		clean := strings.TrimSpace(keyword)
		if clean == "" {
			continue
		}
		seen[strings.ToLower(clean)] = clean
	}
	for _, allowedKeyword := range allowed {
		key := strings.ToLower(strings.TrimSpace(allowedKeyword))
		if key == "" {
			continue
		}
		if matched, ok := seen[key]; ok {
			return matched
		}
	}
	return ""
}

// collectAllowedKeywords flattens one ACCOUNT's label set into the keyword
// list the inbox tabs are built from. Per-user since labels became per-user:
// building the tabs from the house list would show every account the same
// tabs regardless of the labels its own mail is actually tagged with.
func collectAllowedKeywords(labels config.UserLabelSettings) []string {
	out := []string{}
	seen := map[string]bool{}
	appendKeyword := func(value string) {
		clean := strings.TrimSpace(value)
		if clean == "" {
			return
		}
		key := strings.ToLower(clean)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, clean)
	}

	for _, label := range labels.Allowlist {
		appendKeyword(label)
	}
	for _, mappedKeywords := range labels.KeywordMappings {
		for _, keyword := range mappedKeywords {
			appendKeyword(keyword)
		}
	}
	return out
}

// inboxCacheMailboxKey normalizes the mailbox query param into a stable
// mailcache window key: empty (account default) is aliased to "INBOX" so
// omitting the param and passing it explicitly share one window — both
// already resolve to the same selected IMAP folder. The raw (possibly
// empty) mailbox string is still passed to mailClient calls unchanged; this
// normalization is cache-key-only.
func inboxCacheMailboxKey(mailbox string) string {
	trimmed := strings.TrimSpace(mailbox)
	if trimmed == "" || strings.EqualFold(trimmed, "INBOX") {
		return "INBOX"
	}
	return trimmed
}

func mailCacheEntryFromOverview(ov imapadapter.Overview) mailcache.Overview {
	return mailcache.Overview{
		UID:      ov.UID,
		Subject:  ov.Subject,
		Sender:   ov.Sender,
		SentTo:   ov.SentTo,
		CC:       ov.CC,
		BCC:      ov.BCC,
		Keywords: ov.Keywords,
		Status:   ov.Status,
		AtUTC:    ov.AtUTC,
	}
}

func mailCacheEntryFromUnreadMessage(msg imapadapter.UnreadMessage, status string) mailcache.Entry {
	uid, _ := strconv.Atoi(strings.TrimSpace(msg.MessageID))
	return mailcache.Entry{
		UID:                  uid,
		MessageID:            msg.MessageID,
		Subject:              msg.Subject,
		Sender:               msg.Sender,
		SentTo:               msg.SentTo,
		CC:                   msg.CC,
		BCC:                  msg.BCC,
		Keywords:             msg.Keywords,
		Status:               status,
		AtUTC:                msg.AtUTC,
		Body:                 msg.Body,
		BodyMode:             msg.BodyMode,
		HasAttachments:       msg.HasAttachments,
		PGPEncrypted:         msg.PGPEncrypted,
		PGPSigned:            msg.PGPSigned,
		PGPVerified:          msg.PGPVerified,
		PGPSignerFingerprint: msg.PGPSignerFingerprint,
		PGPProtectedSubject:  msg.PGPProtectedSubject,
	}
}

// inboxSubject returns the subject to display for a message: the real subject
// recovered from an encrypted message's protected headers when present,
// otherwise the plaintext envelope/overview subject (which for an encrypted
// message is pgpmail.OuterPlaceholderSubject).
func inboxSubject(envelopeSubject, protectedSubject string) string {
	if protectedSubject != "" {
		return protectedSubject
	}
	return envelopeSubject
}

// inboxUncategorizedTab is the fallback tab for messages matching none of
// the configured label keywords.
const inboxUncategorizedTab = "Uncategorized"

// buildInboxTabScaffold seeds the tabs/byTab response shape from the
// account's configured label keywords, before any messages are bucketed in
// — shared by handleInbox's no-mail-client empty scaffold and serveInbox's
// populated response, so both start from identical tab ordering.
func buildInboxTabScaffold(allowedKeywords []string) ([]string, map[string][]inboxEmail) {
	tabs := make([]string, 0, len(allowedKeywords)+1)
	byTab := map[string][]inboxEmail{}
	seenTab := map[string]bool{}

	for _, keyword := range allowedKeywords {
		name := strings.TrimSpace(keyword)
		if name == "" {
			continue
		}
		if seenTab[strings.ToLower(name)] {
			continue
		}
		seenTab[strings.ToLower(name)] = true
		tabs = append(tabs, name)
		byTab[name] = []inboxEmail{}
	}

	byTab[inboxUncategorizedTab] = []inboxEmail{}
	return tabs, byTab
}

// maxInboxLimit bounds one inbox page. The SPA asks for 500; the old ceiling of
// 5000 was reachable only by hand and bought nothing but buffered message bodies.
const maxInboxLimit = 500

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	// Clamped to what the client actually asks for. The cold path fetches every
	// message body in ONE FETCH with no size pre-filter — unlike ListUnreadInbox
	// and GetMessageBodies, which both partition oversized UIDs out first — and
	// go-imap buffers the whole response, retaining a copy in a package global.
	// A hand-written limit=5000 was therefore a memory multiplier bounded only
	// by the mailbox.
	limit := 500
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= maxInboxLimit {
			limit = v
		}
	}
	mailbox := strings.TrimSpace(r.URL.Query().Get("mailbox"))
	useDelta := strings.TrimSpace(r.URL.Query().Get("since")) != ""
	since := parseNonNegativeInt64Query(r, "since")

	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()

	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	mailClient, err := s.mailFor(r)
	if err != nil {
		// No mailbox configured yet — show the empty tab scaffold rather
		// than an error so the page still renders.
		tabs, byTab := buildInboxTabScaffold(collectAllowedKeywords(s.userLabels(ac.UserID)))
		tabs = append(tabs, inboxUncategorizedTab)
		writeJSON(w, http.StatusOK, map[string]any{"tabs": tabs, "byTab": byTab})
		return
	}

	cache, err := s.mailCacheFor(r)
	if err != nil {
		http.Error(w, "failed to open mail cache", http.StatusInternalServerError)
		return
	}

	s.serveInbox(w, r.Context(), ac.UserID, mailClient, cache, cfg, mailbox, limit, since, useDelta)
}

// serveInbox contains handleInbox's core logic once a mail client and cache
// store are resolved — split out from handleInbox (which only does
// param/auth/store resolution) so it can be exercised directly in tests
// against a fake imapadapter.Client, without a real IMAP connection.
func (s *Server) serveInbox(w http.ResponseWriter, ctx context.Context, userID string, mailClient imapadapter.Client, cache *mailcache.Store, cfg config.Config, mailbox string, limit int, since int64, useDelta bool) {
	allowedKeywords := collectAllowedKeywords(s.userLabels(userID))
	tabs, byTab := buildInboxTabScaffold(allowedKeywords)

	// bucket appends entry into the tab its keywords match (or
	// Uncategorized), stamping Label and registering any newly-seen tab —
	// shared by every path below (cache-warmed classic, live-fallback
	// classic, and delta) so bucketing stays identical regardless of where
	// the data came from.
	bucket := func(keywords []string, entry inboxEmail) {
		tab := firstMatchingKeyword(keywords, allowedKeywords)
		if tab == "" {
			tab = inboxUncategorizedTab
		}
		if _, ok := byTab[tab]; !ok {
			byTab[tab] = []inboxEmail{}
			if tab != inboxUncategorizedTab {
				tabs = append(tabs, tab)
			}
		}
		entry.Label = tab
		entry.Keywords = keywords
		byTab[tab] = append(byTab[tab], entry)
	}

	cacheKey := inboxCacheMailboxKey(mailbox)

	// Discard any cached signature verdict whose address-book basis has moved.
	//
	// A verdict is derived from the contacts store, so it is only valid while
	// that store's key bindings are unchanged. Comparing generations here covers
	// EVERY contact writer — including mobile sync, CardDAV, vCard import,
	// dedupe, the discovery-suppression button and the daemon's Autocrypt
	// harvest, none of which could call the handler-level invalidation helper,
	// and three of which run in a different process entirely.
	var contactKeyGen int64
	if contactsStore, err := s.userContactsStore(userID); err == nil {
		contactKeyGen = contactsStore.PGPKeyGeneration()
		if err := cache.SyncContactKeyGeneration(contactKeyGen); err != nil {
			s.logger.Error("could not reconcile cached PGP verdicts with the address book",
				"user_id", userID, "error", err.Error())
		}
	}
	// stampKeyGen records the address-book generation a verdict was computed
	// under, so a later change to any contact's key or addresses invalidates it
	// via SyncContactKeyGeneration above.
	stampKeyGen := func(entries []mailcache.Entry) []mailcache.Entry {
		for i := range entries {
			entries[i].ContactKeyGen = contactKeyGen
		}
		return entries
	}

	if !useDelta {
		// Cache-first: if the background poller (or an earlier request)
		// has already warmed a full window of `limit` messages with
		// bodies, serve it with zero IMAP calls.
		if entries, warmed := cache.Snapshot(cacheKey, limit); warmed {
			for _, e := range entries {
				bucket(e.Keywords, inboxEmail{
					MessageID:            e.MessageID,
					Sender:               e.Sender,
					SentTo:               e.SentTo,
					CC:                   e.CC,
					BCC:                  e.BCC,
					Subject:              inboxSubject(e.Subject, e.PGPProtectedSubject),
					Body:                 e.Body,
					BodyMode:             e.BodyMode,
					Status:               e.Status,
					AtUTC:                e.AtUTC,
					HasAttachments:       e.HasAttachments,
					PGPEncrypted:         e.PGPEncrypted,
					PGPSigned:            e.PGPSigned,
					PGPVerified:          e.PGPVerified,
					PGPSignerFingerprint: e.PGPSignerFingerprint,
				})
			}
			tabs = append(tabs, inboxUncategorizedTab)
			writeJSON(w, http.StatusOK, map[string]any{"tabs": tabs, "byTab": byTab})
			return
		}

		// Cold or partial cache (new user, non-INBOX folder the poller
		// never touches, or fewer entries than requested) — fall back to a
		// live fetch exactly as before, then self-warm the cache so the
		// next load for this user+mailbox+limit can be served from it.
		unread, err := mailClient.ListUnreadMessages(ctx, mailbox, limit)
		if err != nil {
			http.Error(w, "failed to fetch inbox", http.StatusBadGateway)
			return
		}

		for i, msg := range unread {
			if msg.PGPEncryptedPayload != "" {
				unread[i] = s.decryptPGPUnreadMessage(userID, msg)
			} else if msg.PGPSignaturePayload != "" {
				unread[i] = s.verifySignedOnlyUnreadMessage(userID, msg)
			}
		}

		warmEntries := make([]mailcache.Entry, 0, len(unread))
		for _, msg := range unread {
			status := strings.TrimSpace(msg.Status)
			if status == "" {
				status = "unread"
			}
			bucket(msg.Keywords, inboxEmail{
				MessageID:            msg.MessageID,
				Sender:               msg.Sender,
				SentTo:               msg.SentTo,
				CC:                   msg.CC,
				BCC:                  msg.BCC,
				Subject:              inboxSubject(msg.Subject, msg.PGPProtectedSubject),
				Body:                 msg.Body,
				BodyMode:             msg.BodyMode,
				Status:               status,
				AtUTC:                msg.AtUTC,
				HasAttachments:       msg.HasAttachments,
				PGPEncrypted:         msg.PGPEncrypted,
				PGPSigned:            msg.PGPSigned,
				PGPVerified:          msg.PGPVerified,
				PGPSignerFingerprint: msg.PGPSignerFingerprint,
				PGPDecryptError:      msg.PGPDecryptError,
			})
			warmEntries = append(warmEntries, mailCacheEntryFromUnreadMessage(msg, status))
		}
		if len(warmEntries) > 0 {
			if err := cache.Upsert(cacheKey, stampKeyGen(warmEntries)); err != nil {
				s.logger.Error("failed to warm mail cache", "error", err.Error())
			}
		}

		tabs = append(tabs, inboxUncategorizedTab)
		writeJSON(w, http.StatusOK, map[string]any{"tabs": tabs, "byTab": byTab})
		return
	}

	// Delta path: cheap overview fetch (no bodies), diff against the cache,
	// and only pay for a body fetch on genuinely new messages the cache
	// (and the daemon's opportunistic warming) hasn't already seen.
	overviews, err := mailClient.ListOverviews(ctx, mailbox, limit)
	if err != nil {
		http.Error(w, "failed to fetch inbox", http.StatusBadGateway)
		return
	}
	live := make([]mailcache.Overview, 0, len(overviews))
	for _, ov := range overviews {
		live = append(live, mailCacheEntryFromOverview(ov))
	}

	result, err := cache.Sync(cacheKey, limit, live, since)
	if err != nil {
		http.Error(w, "failed to sync mail cache", http.StatusInternalServerError)
		return
	}

	needBodies := make([]int, 0, len(result.New))
	for _, e := range result.New {
		if e.Body == "" {
			needBodies = append(needBodies, e.UID)
		}
	}
	contents := map[int]imapadapter.MessageContent{}
	if len(needBodies) > 0 {
		contents, err = mailClient.GetMessageBodies(ctx, mailbox, needBodies)
		if err != nil {
			http.Error(w, "failed to fetch inbox", http.StatusBadGateway)
			return
		}
		// The signature verdict is bound to the claimed sender, so the body fetched
		// by UID has to be paired back up with the From address the same UID's
		// metadata carries — see signerKeysForSender.
		senderByUID := make(map[int]string, len(result.New))
		for _, e := range result.New {
			senderByUID[e.UID] = e.Sender
		}
		for uid, c := range contents {
			if c.PGPEncryptedPayload != "" {
				contents[uid] = s.decryptPGPMessageContent(userID, senderByUID[uid], c)
			} else if c.PGPSignaturePayload != "" {
				contents[uid] = s.verifySignedOnlyMessageContent(userID, senderByUID[uid], c)
			}
		}
		// Attach the freshly fetched bodies back onto the cache (metadata
		// is unchanged from what Sync just stored, so this only warms
		// Body/HasAttachments without bumping Rev) so a subsequent
		// classic-path load doesn't re-fetch them live.
		warmEntries := make([]mailcache.Entry, 0, len(needBodies))
		for i, e := range result.New {
			if c, ok := contents[e.UID]; ok && c.Body != "" {
				e.Body = c.Body
				e.BodyMode = c.BodyMode
				e.HasAttachments = c.HasAttachments
				e.PGPEncrypted = c.PGPEncrypted
				e.PGPSigned = c.PGPSigned
				e.PGPVerified = c.PGPVerified
				e.PGPSignerFingerprint = c.PGPSignerFingerprint
				e.PGPProtectedSubject = c.PGPProtectedSubject
				result.New[i] = e
				warmEntries = append(warmEntries, e)
			}
		}
		if len(warmEntries) > 0 {
			if err := cache.Upsert(cacheKey, stampKeyGen(warmEntries)); err != nil {
				s.logger.Error("failed to warm mail cache from delta fetch", "error", err.Error())
			}
		}
	}

	for _, e := range result.New {
		body := e.Body
		bodyMode := e.BodyMode
		hasAttachments := e.HasAttachments
		pgpEncrypted, pgpSigned, pgpVerified := e.PGPEncrypted, e.PGPSigned, e.PGPVerified
		pgpSignerFingerprint := e.PGPSignerFingerprint
		pgpProtectedSubject := e.PGPProtectedSubject
		var pgpDecryptError string
		if body == "" {
			if c, ok := contents[e.UID]; ok {
				body = c.Body
				bodyMode = c.BodyMode
				hasAttachments = c.HasAttachments
				pgpEncrypted = c.PGPEncrypted
				pgpSigned = c.PGPSigned
				pgpVerified = c.PGPVerified
				pgpSignerFingerprint = c.PGPSignerFingerprint
				pgpProtectedSubject = c.PGPProtectedSubject
				pgpDecryptError = c.PGPDecryptError
			}
		}
		bucket(e.Keywords, inboxEmail{
			MessageID:            e.MessageID,
			Sender:               e.Sender,
			SentTo:               e.SentTo,
			CC:                   e.CC,
			BCC:                  e.BCC,
			Subject:              inboxSubject(e.Subject, pgpProtectedSubject),
			Body:                 body,
			BodyMode:             bodyMode,
			Status:               e.Status,
			AtUTC:                e.AtUTC,
			HasAttachments:       hasAttachments,
			PGPEncrypted:         pgpEncrypted,
			PGPSigned:            pgpSigned,
			PGPVerified:          pgpVerified,
			PGPSignerFingerprint: pgpSignerFingerprint,
			PGPDecryptError:      pgpDecryptError,
			ChangeType:           "new",
		})
	}
	for _, e := range result.Updated {
		bucket(e.Keywords, inboxEmail{
			MessageID:            e.MessageID,
			Sender:               e.Sender,
			SentTo:               e.SentTo,
			CC:                   e.CC,
			BCC:                  e.BCC,
			Subject:              inboxSubject(e.Subject, e.PGPProtectedSubject),
			Status:               e.Status,
			AtUTC:                e.AtUTC,
			HasAttachments:       e.HasAttachments,
			PGPEncrypted:         e.PGPEncrypted,
			PGPSigned:            e.PGPSigned,
			PGPVerified:          e.PGPVerified,
			PGPSignerFingerprint: e.PGPSignerFingerprint,
			ChangeType:           "updated",
		})
	}

	removed := make([]string, 0, len(result.Removed))
	for _, e := range result.Removed {
		removed = append(removed, e.MessageID)
	}

	tabs = append(tabs, inboxUncategorizedTab)
	writeJSON(w, http.StatusOK, map[string]any{
		"tabs":    tabs,
		"byTab":   byTab,
		"delta":   true,
		"cursor":  result.Cursor,
		"removed": removed,
	})
}

// writeMailboxError distinguishes a folder name this server refused to send
// (imapadapter.ErrUnsafeMailbox — the caller's input is bad, 400) from one the
// IMAP server itself rejected (502). Both used to be 502, which told a user who
// typed a folder name containing a stray control character that their mail
// provider was at fault.
func writeMailboxError(w http.ResponseWriter, err error) {
	if errors.Is(err, imapadapter.ErrUnsafeMailbox) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Error(w, err.Error(), http.StatusBadGateway)
}

func (s *Server) handleInboxFolders(w http.ResponseWriter, r *http.Request) {
	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		parent := strings.TrimSpace(r.URL.Query().Get("parent"))

		folders, err := mailClient.ListSubfolders(r.Context(), parent)
		if err != nil {
			http.Error(w, "failed to fetch inbox folders", http.StatusBadGateway)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"parent":  parent,
			"folders": toInboxFolders(folders),
		})
	case http.MethodPost:
		var req struct {
			Parent string `json:"parent"`
			Name   string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		parent := strings.TrimSpace(req.Parent)
		name := strings.TrimSpace(req.Name)
		if name == "" {
			http.Error(w, "folder name is required", http.StatusBadRequest)
			return
		}

		folder, err := mailClient.CreateFolder(r.Context(), parent, name)
		if err != nil {
			writeMailboxError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"parent": parent,
			"name":   name,
			"folder": folder,
		})
	case http.MethodPut:
		var req struct {
			Folder string `json:"folder"`
			Name   string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		folder := strings.TrimSpace(req.Folder)
		name := strings.TrimSpace(req.Name)
		if folder == "" || name == "" {
			http.Error(w, "folder and name are required", http.StatusBadRequest)
			return
		}
		if isBuiltinMailbox(folder) {
			http.Error(w, "built-in folders cannot be renamed", http.StatusBadRequest)
			return
		}
		if mailboxParentPath(folder) == "" {
			http.Error(w, "folder must have a parent mailbox", http.StatusBadRequest)
			return
		}

		renamed, err := mailClient.RenameFolder(r.Context(), folder, name)
		if err != nil {
			writeMailboxError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"folder":  folder,
			"renamed": renamed,
			"parent":  mailboxParentPath(renamed),
		})
	case http.MethodDelete:
		folder := strings.TrimSpace(r.URL.Query().Get("folder"))
		if folder == "" {
			http.Error(w, "folder is required", http.StatusBadRequest)
			return
		}
		if isBuiltinMailbox(folder) {
			http.Error(w, "built-in folders cannot be deleted", http.StatusBadRequest)
			return
		}
		if mailboxParentPath(folder) == "" {
			http.Error(w, "folder must have a parent mailbox", http.StatusBadRequest)
			return
		}
		if err := mailClient.DeleteFolder(r.Context(), folder); err != nil {
			writeMailboxError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"folder": folder,
			"parent": mailboxParentPath(folder),
		})
	}
}

func (s *Server) handleInboxActions(w http.ResponseWriter, r *http.Request) {
	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Action        string   `json:"action"`
		MessageIDs    []string `json:"messageIds"`
		Mailbox       string   `json:"mailbox"`
		TargetMailbox string   `json:"targetMailbox"`
		Keyword       string   `json:"keyword"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	mailbox := strings.TrimSpace(req.Mailbox)
	targetMailbox := strings.TrimSpace(req.TargetMailbox)
	keyword := strings.TrimSpace(req.Keyword)
	switch action {
	case "delete", "archive", "spam", "read", "move", "label", "unlabel":
	default:
		http.Error(w, "unsupported action", http.StatusBadRequest)
		return
	}
	if action == "move" && targetMailbox == "" {
		http.Error(w, "targetMailbox is required for move action", http.StatusBadRequest)
		return
	}
	if (action == "label" || action == "unlabel") && keyword == "" {
		http.Error(w, "keyword is required for label/unlabel action", http.StatusBadRequest)
		return
	}
	// The adapter refuses an unsafe keyword or mailbox on its own — that is the
	// boundary that matters (the poller applies keywords too). Checking here as
	// well is only about the status code: without it every message in the batch
	// would come back as an individual 502-shaped failure, which reads as "your
	// mail server is broken" rather than "that keyword isn't valid".
	if action == "label" || action == "unlabel" {
		if err := imapadapter.ValidateKeyword(keyword); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	for _, name := range []string{mailbox, targetMailbox} {
		if strings.TrimSpace(name) == "" {
			continue
		}
		if err := imapadapter.ValidateMailboxName(name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	uniqueIDs := make([]string, 0, len(req.MessageIDs))
	seen := map[string]bool{}
	for _, messageID := range req.MessageIDs {
		clean := strings.TrimSpace(messageID)
		if clean == "" {
			continue
		}
		if seen[clean] {
			continue
		}
		seen[clean] = true
		uniqueIDs = append(uniqueIDs, clean)
	}
	if len(uniqueIDs) == 0 {
		http.Error(w, "at least one messageId is required", http.StatusBadRequest)
		return
	}

	type inboxActionFailure struct {
		MessageID string `json:"messageId"`
		Error     string `json:"error"`
	}
	failures := make([]inboxActionFailure, 0)
	processed := 0
	for _, messageID := range uniqueIDs {
		// label/unlabel bypass ApplyInboxAction's switch entirely (it has no
		// concept of a keyword parameter) and call the dedicated keyword
		// methods directly, keeping ApplyInboxAction's folder-fallback logic
		// for the other actions untouched.
		var err error
		switch action {
		case "label":
			err = mailClient.ApplyLabel(r.Context(), messageID, keyword)
		case "unlabel":
			err = mailClient.RemoveLabel(r.Context(), messageID, keyword)
		default:
			err = mailClient.ApplyInboxAction(r.Context(), messageID, action, mailbox, targetMailbox)
		}
		if err != nil {
			failures = append(failures, inboxActionFailure{MessageID: messageID, Error: err.Error()})
			continue
		}
		processed++
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            len(failures) == 0,
		"action":        action,
		"processed":     processed,
		"failed":        failures,
		"targetMailbox": targetMailbox,
	})
}

func (s *Server) handleMailSearch(w http.ResponseWriter, r *http.Request) {
	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query().Get("q")
	if strings.TrimSpace(q) == "" {
		http.Error(w, "q parameter is required", http.StatusBadRequest)
		return
	}

	field := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("field")))
	if field == "" {
		field = "all"
	}
	if field != "subject" && field != "sender" && field != "from" && field != "body" && field != "all" {
		http.Error(w, "invalid field parameter", http.StatusBadRequest)
		return
	}

	mailbox := strings.TrimSpace(r.URL.Query().Get("mailbox"))
	if mailbox == "" {
		mailbox = "INBOX"
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > 200 {
		limit = 200
	}

	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	allowedKeywords := collectAllowedKeywords(s.userLabels(ac.UserID))

	results, err := mailClient.SearchMessages(r.Context(), mailbox, field, q, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("search failed: %v", err), http.StatusServiceUnavailable)
		return
	}

	// Convert Overview to inboxEmail wire format, mirroring handleInbox's label-bucketing
	out := make([]any, 0, len(results))
	for _, overview := range results {
		label := firstMatchingKeyword(overview.Keywords, allowedKeywords)
		if label == "" {
			label = inboxUncategorizedTab
		}
		out = append(out, inboxEmail{
			MessageID:      overview.MessageID,
			Subject:        overview.Subject,
			Sender:         overview.Sender,
			SentTo:         overview.SentTo,
			CC:             overview.CC,
			BCC:            overview.BCC,
			Label:          label,
			Keywords:       overview.Keywords,
			Status:         overview.Status,
			AtUTC:          overview.AtUTC,
			HasAttachments: false,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"results": out,
	})
}
