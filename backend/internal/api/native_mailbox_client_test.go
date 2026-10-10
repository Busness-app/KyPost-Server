package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	imapadapter "github.com/Busnes-app/kypost-server/backend/internal/adapters/imap"
	"github.com/Busnes-app/kypost-server/backend/internal/mailbox"
	"github.com/Busnes-app/kypost-server/backend/internal/mailmsg"
	"github.com/Busnes-app/kypost-server/backend/internal/pgpmail"
	"github.com/Busnes-app/kypost-server/backend/internal/state"
	"github.com/Busnes-app/kypost-server/backend/internal/users"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// Exercise the real permanent store and full mail Client through the unchanged
// router. Only client selection is injected; production still selects IMAP.
func TestNativeMailboxClientAPI(t *testing.T) {
	t.Setenv("STATE_DIR", t.TempDir())
	t.Setenv("CONFIG_DIR", t.TempDir())
	ctx := context.Background()
	srv, owner := mailBodyServer(t, &fakeMailClient{})
	limits := mailbox.Limits{MessageBytes: 1 << 20, PayloadBytes: 4 << 20, Records: 100}
	storePaths := make(map[*mailbox.Store]string)
	open := func(userID string) *mailbox.Store {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "mailbox")
		store, err := mailbox.Open(dir, mailbox.Owner{Issuer: "https://identity.example.test", Subject: userID, Mailbox: userID}, limits)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		storePaths[store] = filepath.Join(dir, "mailbox.db")
		return store
	}
	inject := func(userID string, store *mailbox.Store) {
		t.Helper()
		client, err := mailbox.NewClient(store, "tester@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if err = writeIMAPConfigPayload(srv.userIMAPConfigPath(userID), srv.imapConfigKeyPath, imapConfigPayload{Host: "imap.example.com", Port: 993, Username: "tester@example.com", Password: "test", Mailbox: "INBOX", UpdatedAt: "test"}); err != nil {
			t.Fatal(err)
		}
		nativeState, err := state.NewNative(filepath.Join(t.TempDir(), "fresh-state"), client.MailSourceIdentity())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = nativeState.Close() })
		srv.userMu.Lock()
		srv.userStores[userID] = nativeState
		srv.userMail[userID] = &serverMailEntry{client: client, updatedAt: "test"}
		srv.userMu.Unlock()
	}
	store := open(owner)
	inject(owner, store)
	other, err := srv.users.Create(ctx, "another_mailbox", "another-password-123", users.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	otherStore := open(other.ID)
	inject(other.ID, otherStore)
	attachment := []byte("exact binary\x00bytes")
	raw := mailmsg.Message{From: "Sender <sender@outside.test>", To: []string{"tester@example.com"}, Subject: "real native mail", Body: "owner body <user@example.test>", Attachments: []mailmsg.Attachment{{Name: "file.bin", MimeType: "application/octet-stream", Content: attachment}}}.Build()
	raw = append([]byte("Date: Sat, 03 Oct 2026 12:00:00 +0000\r\n"), raw...)
	importRaw := func(store *mailbox.Store, id string, raw []byte) int64 {
		t.Helper()
		uid, err := store.Import(ctx, mailbox.Receipt{Gateway: "maddy", Delivery: id, Sender: "sender@outside.test", Recipients: []mailbox.Recipient{{Address: "tester@example.com", Generation: 1}}}, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		return uid
	}
	ref := func(store *mailbox.Store, uid int64) string {
		return "n1:" + store.MessageReferenceGeneration() + ":" + strconv.FormatInt(uid, 10)
	}
	uid := importRaw(store, "one", raw)
	snapshotDir := filepath.Join(t.TempDir(), "mailbox")
	if err := os.Mkdir(snapshotDir, 0700); err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(snapshotDir, "mailbox.db")
	db, err := sql.Open("sqlite", storePaths[store])
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("VACUUM INTO ?", snapshotPath)
	if closeErr := db.Close(); err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	otherUID := importRaw(otherStore, "one", mailmsg.Message{From: "private@outside.test", To: []string{"tester@example.com"}, Subject: "other owner's secret", Body: "other owner body"}.Build())
	if uid != otherUID {
		t.Fatal("test must exercise identical IDs in different owners' stores")
	}
	privateUID, err := store.Append(ctx, "Sent", bytes.NewReader(raw), false)
	if err != nil {
		t.Fatal(err)
	}
	device, secret := pairNativeDevice(t, srv, owner, "permanent-mailbox-api")
	routes := srv.routes()
	request := func(method, path string, payload any, native bool, userID string) *httptest.ResponseRecorder {
		t.Helper()
		var data []byte
		if payload != nil {
			data, err = json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		if userID != "" {
			if native {
				setDeviceHeaders(req, device, secret)
			} else {
				authRequestAs(srv, req, userID)
			}
		}
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		return rec
	}
	requireOK := func(rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != 200 {
			t.Fatalf("API status %d: %s", rec.Code, rec.Body.String())
		}
	}
	id := ref(store, uid)
	query := "?mailbox=INBOX&messageId=" + id
	for _, native := range []bool{false, true} {
		body := request("GET", "/api/mail/body"+query, nil, native, owner)
		requireOK(body)
		if !bytes.Contains(body.Body.Bytes(), []byte("owner body")) {
			t.Fatal("owner body missing")
		}
		download := request("GET", "/api/mail/attachment"+query+"&index=0", nil, native, owner)
		requireOK(download)
		if !bytes.Equal(download.Body.Bytes(), attachment) || download.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("attachment wire contract")
		}
		requireOK(request("GET", "/api/mail/attachments"+query, nil, native, owner))
		if rec := request("GET", "/api/mail/body?mailbox=INBOX&messageId="+ref(store, privateUID), nil, native, owner); rec.Code != 404 {
			t.Fatal("wrong folder body served")
		}
		first := request("GET", "/api/inbox?mailbox=INBOX&since=0&bodies=0", nil, native, owner)
		requireOK(first)
		snapshot := decodeInboxResponse(t, first)
		if len(allEmails(snapshot)) != 1 || allEmails(snapshot)[0].Body != "" || allEmails(snapshot)[0].MessageID != id {
			t.Fatal("lazy inbox shape")
		}
		unchanged := request("GET", "/api/inbox?mailbox=INBOX&since="+"999999&bodies=0", nil, native, owner)
		requireOK(unchanged)
		if got := decodeInboxResponse(t, unchanged); len(allEmails(got)) != 1 || got.Cursor != 0 || got.Delta {
			t.Fatal("native snapshot must not trust an unscoped cursor")
		}
		search := request("GET", "/api/mail/search?mailbox=INBOX&field=from&q=sender", nil, native, owner)
		requireOK(search)
		if !bytes.Contains(search.Body.Bytes(), []byte("real native mail")) || !bytes.Contains(search.Body.Bytes(), []byte(id)) {
			t.Fatal("from search alias missing")
		}
		requireOK(request("GET", "/api/inbox/folders?parent=INBOX", nil, native, owner))
		older := request("GET", "/api/inbox?mailbox=INBOX&before="+id, nil, native, owner)
		requireOK(older)
		if got := allEmails(decodeInboxResponse(t, older)); len(got) != 0 || !bytes.Contains(older.Body.Bytes(), []byte(`"hasMore":false`)) {
			t.Fatalf("nothing is older than the only message: %s", older.Body.String())
		}
		if rec := request("GET", "/api/inbox?mailbox=INBOX&before="+strconv.FormatInt(uid, 10), nil, native, owner); rec.Code != 400 {
			t.Fatalf("bare numeric before reference: status %d, want 400", rec.Code)
		}
	}
	// A classic caller must also receive a live snapshot, even with a warmed cache.
	classic := request("GET", "/api/inbox?mailbox=INBOX&bodies=0", nil, false, owner)
	requireOK(classic)
	if got := decodeInboxResponse(t, classic); len(allEmails(got)) != 1 || got.Cursor != 0 || got.Delta {
		t.Fatal("classic native snapshot")
	}
	if rec := request("GET", "/api/mail/body"+query, nil, false, other.ID); rec.Code != 400 {
		t.Fatal("foreign generation accepted", rec.Code)
	}
	otherBody := request("GET", "/api/mail/body?mailbox=INBOX&messageId="+ref(otherStore, otherUID), nil, false, other.ID)
	requireOK(otherBody)
	if !bytes.Contains(otherBody.Body.Bytes(), []byte("other owner body")) || bytes.Contains(otherBody.Body.Bytes(), []byte("owner body <")) {
		t.Fatal("identical IDs leaked across owners")
	}
	if rec := request("GET", "/api/mail/body"+query, nil, false, ""); rec.Code != 401 {
		t.Fatal("unauthenticated native body served")
	}
	for _, action := range []struct{ action, keyword string }{{"label", "Travel"}, {"read", ""}} {
		rec := request("POST", "/api/inbox/actions", map[string]any{"action": action.action, "keyword": action.keyword, "mailbox": "INBOX", "messageIds": []string{id}}, true, owner)
		requireOK(rec)
		if !bytes.Contains(rec.Body.Bytes(), []byte(`"processed":1`)) {
			t.Fatal("native action failed")
		}
	}
	full := request("GET", "/api/inbox?mailbox=INBOX&since=0", nil, false, owner)
	requireOK(full)
	emails := allEmails(decodeInboxResponse(t, full))
	if len(emails) != 1 || emails[0].Status != "read" || !strings.Contains(emails[0].Body, "owner body") {
		t.Fatalf("changed body/flags: %+v", emails)
	}
	requireOK(request("POST", "/api/inbox/actions", map[string]any{"action": "unread", "mailbox": "INBOX", "messageIds": []string{id}}, true, owner))
	if got := allEmails(decodeInboxResponse(t, request("GET", "/api/inbox?mailbox=INBOX&since=0&bodies=0", nil, false, owner))); len(got) != 1 || got[0].Status != "unread" {
		t.Fatalf("unread action: %+v", got)
	}
	requireOK(request("POST", "/api/inbox/actions", map[string]any{"action": "read", "mailbox": "INBOX", "messageIds": []string{id}}, true, owner))
	requireOK(request("POST", "/api/inbox/folders", map[string]string{"parent": "INBOX", "name": "Work"}, true, owner))
	requireOK(request("POST", "/api/inbox/actions", map[string]any{"action": "move", "mailbox": "INBOX", "targetMailbox": "INBOX/Work", "messageIds": []string{id}}, true, owner))
	if rec := request("GET", "/api/mail/body"+query, nil, true, owner); rec.Code != 404 {
		t.Fatal("move left stale body reference")
	}
	moved := request("GET", "/api/inbox?mailbox=INBOX&since=999999&bodies=0", nil, true, owner)
	requireOK(moved)
	if got := decodeInboxResponse(t, moved); len(allEmails(got)) != 0 || got.Delta || got.Cursor != 0 {
		t.Fatal("stale cursor retained moved mail")
	}
	requireOK(request("PUT", "/api/inbox/folders", map[string]string{"folder": "INBOX/Work", "name": "Personal"}, false, owner))
	requireOK(request("DELETE", "/api/inbox/folders?folder=INBOX/Personal", nil, true, owner))
	requireOK(request("GET", "/api/mail/body"+query, nil, true, owner))
	draft := request("POST", "/api/mail/draft", map[string]any{"to": "recipient@outside.test", "subject": "API draft", "body": "saved local draft", "mode": "plain"}, false, owner)
	requireOK(draft)
	drafts, err := store.List(ctx, "Drafts", 0, 10)
	if err != nil || len(drafts) != 1 || !drafts[0].Draft {
		t.Fatalf("API draft not committed: %+v %v", drafts, err)
	}
	bad := importRaw(store, "malformed", []byte("From: sender@outside.test\r\nContent-Type: multipart/mixed\r\n\r\ninvalid MIME"))
	malformed := request("GET", "/api/mail/body?mailbox=INBOX&messageId="+ref(store, bad), nil, true, owner)
	if malformed.Code != 422 || !bytes.Contains(malformed.Body.Bytes(), []byte("original mail retained")) {
		t.Fatalf("malformed body: %d %s", malformed.Code, malformed.Body.String())
	}
	requireOK(request("GET", "/api/inbox?mailbox=INBOX&since=0", nil, true, owner))
	page := request("GET", "/api/inbox?mailbox=INBOX&limit=1&before="+ref(store, bad), nil, true, owner)
	requireOK(page)
	if got := allEmails(decodeInboxResponse(t, page)); len(got) != 1 || got[0].MessageID != id || got[0].Body != "" ||
		!bytes.Contains(page.Body.Bytes(), []byte(`"nextBefore":"`+id+`"`)) {
		t.Fatalf("before page: %s", page.Body.String())
	}

	sender, err := pgpmail.GenerateIdentity("Sender", "sender@outside.test")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pgpmail.SignMIME(raw, sender)
	if err != nil {
		t.Fatal(err)
	}
	signedUID := importRaw(store, "signed", signed)
	signedResponse := request("GET", "/api/mail/pgp-payload?mailbox=INBOX&messageId="+ref(store, signedUID), nil, true, owner)
	requireOK(signedResponse)
	var payload struct {
		SignedPartBase64, SignaturePayload, EncryptedPayload, Body string
		ResolvedSender                                             string
	}
	if err = json.Unmarshal(signedResponse.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	signedPart, err := base64.StdEncoding.DecodeString(payload.SignedPartBase64)
	if err != nil {
		t.Fatal(err)
	}
	signerKey, err := crypto.NewKeyFromArmored(sender.ArmoredPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := crypto.NewKeyRing(signerKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := crypto.PGP().Verify().VerificationKeys(ring).New()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.VerifyDetached(signedPart, []byte(payload.SignaturePayload), crypto.Auto)
	if err != nil {
		t.Fatal(err)
	}
	if err = verified.SignatureError(); err != nil {
		t.Fatal(err)
	}
	if payload.Body != "" || payload.ResolvedSender != "sender@outside.test" {
		t.Fatal("signed response render/binding changed")
	}
	ownerKey, err := pgpmail.GenerateIdentity("Owner", "tester@example.com")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := pgpmail.EncryptMIME(raw, []string{ownerKey.ArmoredPublicKey}, sender)
	if err != nil {
		t.Fatal(err)
	}
	encryptedUID := importRaw(store, "encrypted", encrypted)
	encryptedPath := "/api/mail/pgp-payload?mailbox=INBOX&messageId=" + ref(store, encryptedUID)
	if rec := request("GET", encryptedPath, nil, true, owner); rec.Code != 409 {
		t.Fatal("legacy server-custody ciphertext gate changed")
	}
	// The opaque wrapping fixture selects existing client-custody behavior; this
	// test checks MIME delivery, not wrapping/enrollment cryptography.
	if _, err = srv.users.SetPGPIdentityClientProtected(owner, ownerKey.Fingerprint, ownerKey.KeyID, ownerKey.ArmoredPublicKey, `{"v":2}`, "generated", "2026-10-03T00:00:00Z", nil); err != nil {
		t.Fatal(err)
	}
	encryptedResponse := request("GET", encryptedPath, nil, true, owner)
	requireOK(encryptedResponse)
	payload = struct {
		SignedPartBase64, SignaturePayload, EncryptedPayload, Body string
		ResolvedSender                                             string
	}{}
	if err = json.Unmarshal(encryptedResponse.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.EncryptedPayload, "-----BEGIN PGP MESSAGE-----") || payload.Body != "" {
		t.Fatal("ciphertext read lost payload or exposed plaintext")
	}
	decrypted, err := pgpmail.DecryptMIME(payload.EncryptedPayload, ownerKey, []string{sender.ArmoredPublicKey})
	if err != nil || !decrypted.Verified || decrypted.SignerFingerprint != sender.Fingerprint {
		t.Fatalf("endpoint ciphertext failed decrypt/signature/body check: %v", err)
	}
	decryptedBody, _, _, err := pgpmail.ParseContent(decrypted.Content)
	if err != nil || decryptedBody != "owner body <user@example.test>" {
		t.Fatalf("endpoint decrypted body mismatch: %v", err)
	}
	encryptedBody := request("GET", "/api/mail/body?mailbox=INBOX&messageId="+ref(store, encryptedUID), nil, true, owner)
	requireOK(encryptedBody)
	if bytes.Contains(encryptedBody.Body.Bytes(), []byte("owner body")) {
		t.Fatal("encrypted lazy body exposed plaintext")
	}
	// An iMIP invite as an undisposed multipart/alternative part is listed as
	// invite.ics and downloads as text/calendar, still as an attachment.
	invite := importRaw(store, "invite", []byte("From: organizer@outside.test\r\nTo: tester@example.com\r\nSubject: Invitation\r\nMIME-Version: 1.0\r\n"+
		"Content-Type: multipart/alternative; boundary=A\r\n\r\n--A\r\nContent-Type: text/plain\r\n\r\ninvited\r\n"+
		"--A\r\nContent-Type: text/calendar; method=REQUEST\r\n\r\nBEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:e1\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n--A--\r\n"))
	inviteQuery := "?mailbox=INBOX&messageId=" + ref(store, invite)
	inviteList := request("GET", "/api/mail/attachments"+inviteQuery, nil, true, owner)
	requireOK(inviteList)
	if !bytes.Contains(inviteList.Body.Bytes(), []byte(`"name":"invite.ics","mimeType":"text/calendar"`)) || !bytes.Contains(inviteList.Body.Bytes(), []byte(`"calendarMethod":"REQUEST"`)) {
		t.Fatalf("invite not listed: %s", inviteList.Body.String())
	}
	ics := request("GET", "/api/mail/attachment"+inviteQuery+"&index=0", nil, true, owner)
	requireOK(ics)
	if ics.Header().Get("Content-Type") != "text/calendar" || !strings.HasPrefix(ics.Header().Get("Content-Disposition"), "attachment") ||
		ics.Header().Get("X-Content-Type-Options") != "nosniff" || !bytes.HasPrefix(ics.Body.Bytes(), []byte("BEGIN:VCALENDAR")) {
		t.Fatalf("invite download headers %v body %q", ics.Header(), ics.Body.String())
	}
	requireOK(request("POST", "/api/mail/draft", map[string]any{"to": "tester@example.com", "pgpDraft": string(encrypted)}, false, owner))
	copies, err := store.List(ctx, "Drafts", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	exact, err := store.Raw(ctx, "Drafts", copies[0].ID)
	if err != nil || !bytes.Equal(exact, []byte(strings.TrimSpace(string(encrypted)))) {
		t.Fatal("client encrypted draft reconstructed")
	}
	// Snapshot retained UID1 before the signed INBOX message existed; restore
	// rewinds allocation until that same folder/UID points at a new ordinary mail.
	// Inject only client selection, preserving authentication/state/cache to prove
	// this rejects references by generation, not by a different source or logout.
	// This is not runtime hold release or complete restored-authority qualification.
	requireOK(request("GET", "/api/inbox?since=0", nil, false, owner)) // Warm signed content before rollback.
	originalClient, err := mailbox.NewClient(store, "tester@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := mailbox.RotateRestoredMessageReferences(snapshotPath, originalClient.MailSourceIdentity()); err != nil {
		t.Fatal(err)
	}
	restored, err := mailbox.OpenExisting(snapshotDir, store.Owner(), limits, originalClient.MailSourceIdentity())
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var reused int64
	for reused < signedUID {
		reused = importRaw(restored, "after-rollback-"+strconv.FormatInt(reused, 10), raw)
	}
	if reused != signedUID {
		t.Fatal("rollback fixture did not reuse signed INBOX ID", reused, signedUID)
	}
	restoredClient, err := mailbox.NewClient(restored, "tester@example.com")
	if err != nil {
		t.Fatal(err)
	}
	srv.userMu.Lock()
	srv.userMail[owner] = &serverMailEntry{client: restoredClient, updatedAt: "test"}
	srv.userMu.Unlock()
	for _, native := range []bool{false, true} {
		for _, stale := range []string{ref(store, signedUID), strconv.FormatInt(signedUID, 10), ref(otherStore, signedUID), "n1:" + restored.MessageReferenceGeneration() + ":0", "n1:" + restored.MessageReferenceGeneration() + ":02"} {
			for _, path := range []string{"/api/mail/body", "/api/mail/attachments", "/api/mail/attachment", "/api/mail/pgp-payload"} {
				rec := request("GET", path+"?mailbox=INBOX&messageId="+stale+"&index=0", nil, native, owner)
				if rec.Code != 400 || bytes.Contains(rec.Body.Bytes(), []byte("owner body")) {
					t.Fatal("stale read served", path, rec.Code, rec.Body.String())
				}
			}
			for _, action := range []string{"read", "label", "unlabel", "move", "delete"} {
				rec := request("POST", "/api/inbox/actions", map[string]any{"action": action, "keyword": "Travel", "mailbox": "INBOX", "targetMailbox": "Sent", "messageIds": []string{stale}}, native, owner)
				requireOK(rec)
				if !bytes.Contains(rec.Body.Bytes(), []byte(`"processed":0`)) || !bytes.Contains(rec.Body.Bytes(), []byte(stale)) {
					t.Fatal("stale mutation accepted", action, rec.Body.String())
				}
			}
		}
		fullRestored := request("GET", "/api/inbox?since=0", nil, native, owner)
		requireOK(fullRestored)
		for _, email := range allEmails(decodeInboxResponse(t, fullRestored)) {
			if email.MessageID == ref(restored, reused) && (email.PGPSigned || email.PGPEncrypted || email.Body != "owner body <user@example.test>") {
				t.Fatal("fresh ID laundered cached body/PGP verdict", email)
			}
		}
		fresh := ref(restored, reused)
		requireOK(request("GET", "/api/mail/body?mailbox=INBOX&messageId="+fresh, nil, native, owner))
		freshInbox := request("GET", "/api/inbox?since=999999&bodies=0", nil, native, owner)
		requireOK(freshInbox)
		if !bytes.Contains(freshInbox.Body.Bytes(), []byte(fresh)) || bytes.Contains(freshInbox.Body.Bytes(), []byte(ref(store, reused))) {
			t.Fatal("snapshot emitted stale IDs")
		}
	}
	retained, err := restored.List(ctx, "INBOX", 0, 10)
	if err != nil || len(retained) != int(signedUID) || retained[0].Seen || len(retained[0].Labels) != 0 {
		t.Fatal("stale actions changed new mail", retained, err)
	}
	srv.userMu.Lock()
	srv.userMail[owner] = &serverMailEntry{client: originalClient, updatedAt: "test"}
	srv.userMu.Unlock()
	// Liveness remains enforced by the existing router before selecting a store.
	if _, err = srv.users.Deactivate(other.ID); err != nil {
		t.Fatal(err)
	}
	if rec := request("GET", "/api/mail/body"+query, nil, false, other.ID); rec.Code != 401 && rec.Code != 403 {
		t.Fatalf("disabled mailbox accessible: %d", rec.Code)
	}
	// Replacing the selected database (even with coincident IDs) or selecting
	// IMAP cannot reuse this account's source-bound references/cache/checkpoints.
	replacement, err := mailbox.NewClient(otherStore, "tester@example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []imapadapter.Client{replacement, &fakeMailClient{bodies: map[int]string{int(uid): "wrong source"}}} {
		srv.userMu.Lock()
		srv.userMail[owner] = &serverMailEntry{client: candidate, updatedAt: "test"}
		srv.userMu.Unlock()
		for _, endpoint := range []struct {
			method, path string
			payload      any
		}{
			{"GET", "/api/inbox?since=999999", nil},
			{"GET", "/api/mail/body" + query, nil},
			{"GET", "/api/mail/pgp-payload" + query, nil},
			{"GET", "/api/mail/attachments" + query, nil},
			{"GET", "/api/mail/attachment" + query + "&index=0", nil},
			{"GET", "/api/mail/search?field=from&q=sender", nil},
			{"GET", "/api/inbox/folders", nil},
			{"POST", "/api/inbox/actions", map[string]any{"action": "delete", "mailbox": "INBOX", "messageIds": []string{id}}},
			{"POST", "/api/mail/draft", map[string]any{"to": "recipient@outside.test", "subject": "blocked", "body": "blocked", "mode": "plain"}},
		} {
			rec := request(endpoint.method, endpoint.path, endpoint.payload, true, owner)
			if rec.Code != 409 || !bytes.Contains(rec.Body.Bytes(), []byte("source switching is disabled")) {
				t.Fatalf("source conflict %s: %d %s", endpoint.path, rec.Code, rec.Body.String())
			}
		}
	}
	if _, err = otherStore.Raw(ctx, "INBOX", otherUID); err != nil {
		t.Fatal("rejected source deleted another owner's mail", err)
	}

}

func TestInboxMailStateFailureExplicit(t *testing.T) {
	srv, owner := mailBodyServer(t, &fakeMailClient{})
	if err := os.MkdirAll(srv.userStateDir(owner), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srv.userStateDir(owner), "mailcache.json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/inbox", nil)
	authRequestAs(srv, req, owner)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != 503 || !bytes.Contains(rec.Body.Bytes(), []byte("check account state")) {
		t.Fatalf("state error hidden as empty inbox: %d %s", rec.Code, rec.Body.String())
	}
}
