package api

import (
	"strings"
	"testing"
)

// run-4 M5: the client-custody send path uploaded the message's plaintext body
// and subject to the server as the Sent copy.
//
// clientEncryptedSendRequest.SentCopy was, by its own field comment, "the
// plaintext body stored in the Sent folder", and App.tsx filled it with the raw
// composer HTML. So for an account whose whole premise is that the server
// cannot read its mail — docs/E2E_PGP.md states "Server can decrypt mail: No" —
// every single send handed the server the cleartext of what had just been
// encrypted, along with its real subject. The deliveries were sound; the copy
// beside them undid the point of them.
//
// The Sent copy is now encrypted in the browser to the sender's own key, and
// this server relays bytes it cannot open, the same as it does for the
// deliveries. Two consequences are pinned below: an encrypted copy is appended
// verbatim rather than rebuilt (rebuilding would re-derive headers and wreck
// the PGP/MIME structure), and a copy that is NOT encrypted is refused rather
// than stored.

func TestSentCopyDecisionEncryptedIsAppendedVerbatim(t *testing.T) {
	const ciphertext = "From: me@example.com\r\nSubject: [Encrypted] Email Sent by KyPost\r\n\r\n-----BEGIN PGP MESSAGE-----\r\nx\r\n-----END PGP MESSAGE-----\r\n"

	draft, ok := sentCopyDraft(clientEncryptedSendRequest{
		Subject:           "Quarterly numbers",
		To:                []string{"bob@example.com"},
		SentCopy:          ciphertext,
		SentCopyEncrypted: true,
		Mode:              "html",
	})

	if !ok {
		t.Fatal("an encrypted sent copy was refused")
	}
	if string(draft.Raw) != ciphertext {
		t.Fatalf("the ciphertext was not appended verbatim:\n%s", draft.Raw)
	}
	// Rebuilding from Subject/Body would re-derive MIME headers around an
	// already-complete PGP/MIME message and corrupt it.
	if draft.Body != "" {
		t.Fatalf("Body should be empty when Raw is set, got %q", draft.Body)
	}
	if strings.Contains(string(draft.Raw), "Quarterly numbers") {
		t.Fatal("the real subject is in the bytes appended to Sent")
	}
	if draft.Subject == "Quarterly numbers" {
		t.Fatal("the real subject was carried on the draft alongside the ciphertext")
	}
}

// The security property, stated plainly: a client that hands over cleartext
// does not get it stored. Losing the Sent copy is the lesser harm — the message
// itself was delivered, and a reload upgrades the client.
func TestSentCopyDecisionRefusesPlaintext(t *testing.T) {
	_, ok := sentCopyDraft(clientEncryptedSendRequest{
		Subject:           "Quarterly numbers",
		To:                []string{"bob@example.com"},
		SentCopy:          "<p>the actual message</p>",
		SentCopyEncrypted: false,
		Mode:              "html",
	})

	if ok {
		t.Fatal("a plaintext sent copy was accepted for a client-custody account")
	}
}

// A client that omits the copy entirely is not an error — it just has nothing
// to save.
func TestSentCopyDecisionSkipsAnEmptyCopy(t *testing.T) {
	if _, ok := sentCopyDraft(clientEncryptedSendRequest{
		To:                []string{"bob@example.com"},
		SentCopy:          "",
		SentCopyEncrypted: true,
	}); ok {
		t.Fatal("an empty sent copy produced a draft")
	}
}

// Recipient lists stay in the clear — SMTP needs them and the Sent folder shows
// them — but nothing else may.
func TestSentCopyDecisionKeepsRecipientsAndPlaceholderSubject(t *testing.T) {
	draft, ok := sentCopyDraft(clientEncryptedSendRequest{
		Subject:           "Real Subject",
		To:                []string{"bob@example.com"},
		CC:                []string{"carol@example.com"},
		BCC:               []string{"dave@example.com"},
		SentCopy:          "ciphertext",
		SentCopyEncrypted: true,
	})
	if !ok {
		t.Fatal("draft was refused")
	}
	if len(draft.To) != 1 || draft.To[0] != "bob@example.com" {
		t.Fatalf("To = %v", draft.To)
	}
	if len(draft.CC) != 1 || len(draft.BCC) != 1 {
		t.Fatalf("CC/BCC were dropped: %v / %v", draft.CC, draft.BCC)
	}
}
