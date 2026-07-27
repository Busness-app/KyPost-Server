package mailcache

import (
	"strings"
	"testing"
)

// run-4 finding M1: the client-sealed pickup flow puts the AES key in the URL
// fragment of the link, and its whole security claim rests on that key never
// reaching the server's disk — pickup_client_sealed.go says so directly: "the
// key is never written to disk, so an attacker who obtains the volume, a
// backup, or the box later gets ciphertext. Only a server compromised at the
// moment of sending sees the key."
//
// The notification carrying that link is ordinary mail (encrypt:false,
// mode:"plain"), and warmBody stripped only PGPEncrypted bodies — so the cache
// persisted the link, key and all, as plain JSON in the user's state directory,
// on the same volume as the ciphertext it was protecting. "Only at the moment
// of sending" quietly became "any time in the next several days".
//
// Two independent defenses, because they cover different mailboxes:
//   - fragments are redacted from any cached body (this file), which covers the
//     case where the recipient is another user on this same instance and the
//     notice lands in their INBOX;
//   - Sent bodies are not cached at all (below), which covers the sender.

func TestRedactPickupLinkFragmentsStripsTheKey(t *testing.T) {
	const key = "8Zb1QwUvKQ0hn3xPmA2rTgYs5cLdEfGh"
	body := "Read it once at the link below:\n\n" +
		"https://mail.example.com/pickup/2f1b9a3c-1111-4222-8333-444455556666?t=abc.def#" + key +
		"\n\nThis link expires in 7 days."

	got := redactPickupLinkFragments(body)

	if strings.Contains(got, key) {
		t.Fatalf("the fragment key survived redaction:\n%s", got)
	}
	// The rest of the link must survive — a redacted body is still shown to the
	// user in their own mailbox, and a mangled URL reads like corruption.
	if !strings.Contains(got, "/pickup/2f1b9a3c-1111-4222-8333-444455556666?t=abc.def") {
		t.Fatalf("redaction damaged the link:\n%s", got)
	}
}

func TestRedactPickupLinkFragmentsHandlesHTMLHrefs(t *testing.T) {
	const key = "8Zb1QwUvKQ0hn3xPmA2rTgYs5cLdEfGh"
	body := `<p>Read it <a href="https://mail.example.com/pickup/abc-123?t=tok#` + key + `">here</a>.</p>`

	got := redactPickupLinkFragments(body)

	if strings.Contains(got, key) {
		t.Fatalf("the fragment key survived redaction:\n%s", got)
	}
	// The attribute must stay well-formed: cutting at the '#' and swallowing
	// the closing quote would turn the cached body into broken markup.
	if !strings.Contains(got, `">here</a>`) {
		t.Fatalf("redaction broke the surrounding markup:\n%s", got)
	}
}

func TestRedactPickupLinkFragmentsRedactsEveryLink(t *testing.T) {
	body := "one https://h/pickup/a?t=1#KEY_ONE and two https://h/pickup/b?t=2#KEY_TWO"

	got := redactPickupLinkFragments(body)

	if strings.Contains(got, "KEY_ONE") || strings.Contains(got, "KEY_TWO") {
		t.Fatalf("a fragment survived:\n%s", got)
	}
}

// Redaction is anchored on this server's own /pickup/ URL shape. Ordinary mail
// full of anchors and deep links must come through untouched, or the cache
// starts quietly corrupting unrelated messages.
func TestRedactPickupLinkFragmentsLeavesOrdinaryLinksAlone(t *testing.T) {
	body := `See <a href="https://docs.example.com/guide#installation">the guide</a> ` +
		"and https://example.com/spec#section-4 for details."

	if got := redactPickupLinkFragments(body); got != body {
		t.Fatalf("ordinary fragments were altered:\ngot:  %s\nwant: %s", got, body)
	}
}

func TestWarmBodyRedactsPickupKeyForInbox(t *testing.T) {
	const key = "8Zb1QwUvKQ0hn3xPmA2rTgYs5cLdEfGh"
	in := Entry{Body: "link: https://mail.example.com/pickup/id-1?t=tok#" + key}

	if got := warmBody("INBOX", in); strings.Contains(got, key) {
		t.Fatalf("warmBody persisted the pickup key:\n%s", got)
	}
}

// The Sent folder holds every message the user has ever sent, in plaintext, on
// the disk of a server whose whole claim for client-custody mail is that it
// cannot read it. Caching those bodies buys a rarely-used folder some speed at
// the cost of that claim.
func TestWarmBodyDropsSentBodiesEntirely(t *testing.T) {
	in := Entry{Body: "an ordinary message I sent"}

	for _, mailbox := range []string{"Sent", "sent", "Sent Items", "[Gmail]/Sent Mail", "INBOX.Sent"} {
		if got := warmBody(mailbox, in); got != "" {
			t.Fatalf("warmBody(%q) = %q, want empty", mailbox, got)
		}
	}
}

func TestWarmBodyKeepsOrdinaryInboxBodies(t *testing.T) {
	in := Entry{Body: "an ordinary message"}

	for _, mailbox := range []string{"INBOX", "Archive", "Presentations"} {
		if got := warmBody(mailbox, in); got != in.Body {
			t.Fatalf("warmBody(%q) = %q, want the body kept", mailbox, got)
		}
	}
}

// The pre-existing rule must survive the signature change.
func TestWarmBodyStillDropsPGPEncryptedBodies(t *testing.T) {
	in := Entry{Body: "-----BEGIN PGP MESSAGE-----", PGPEncrypted: true}

	if got := warmBody("INBOX", in); got != "" {
		t.Fatalf("warmBody = %q, want empty for a PGP-encrypted body", got)
	}
}

// End-to-end through the store, since warmBody is unexported plumbing and the
// property that matters is what lands in the file.
func TestUpsertDoesNotPersistPickupKey(t *testing.T) {
	const key = "8Zb1QwUvKQ0hn3xPmA2rTgYs5cLdEfGh"
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := store.Upsert("INBOX", []Entry{{
		UID:       1,
		MessageID: "1",
		Body:      "link: https://mail.example.com/pickup/id-1?t=tok#" + key,
	}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	entries, _ := store.Snapshot("INBOX", 1)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if strings.Contains(entries[0].Body, key) {
		t.Fatalf("the pickup key reached the cache:\n%s", entries[0].Body)
	}
}
