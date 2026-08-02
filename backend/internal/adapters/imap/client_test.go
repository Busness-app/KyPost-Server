package imap

import (
	"reflect"
	"strings"
	"testing"

	goimap "github.com/BrianLeishman/go-imap"

	"kypost-server/backend/internal/mailmsg"
)

func TestPgpDetectSignature(t *testing.T) {
	t.Run("no attachments", func(t *testing.T) {
		if sig := pgpDetectSignature(nil); sig != "" {
			t.Fatalf("expected empty signature, got %q", sig)
		}
	})

	t.Run("no signature attachment", func(t *testing.T) {
		attachments := []goimap.Attachment{
			{Name: "photo.png", MimeType: "image/png", Content: []byte{0x89, 0x50, 0x4e, 0x47}},
		}
		if sig := pgpDetectSignature(attachments); sig != "" {
			t.Fatalf("expected empty signature, got %q", sig)
		}
	})

	t.Run("armored signature attachment", func(t *testing.T) {
		armored := "-----BEGIN PGP SIGNATURE-----\n\nfakebase64data\n-----END PGP SIGNATURE-----\n"
		attachments := []goimap.Attachment{
			{Name: "unrelated.txt", MimeType: "text/plain", Content: []byte("hello")},
			{Name: "signature.asc", MimeType: "application/pgp-signature", Content: []byte(armored)},
		}
		got := pgpDetectSignature(attachments)
		if got != armored {
			t.Fatalf("expected %q, got %q", armored, got)
		}
	})

	t.Run("leading whitespace still detected", func(t *testing.T) {
		armored := "  \n-----BEGIN PGP SIGNATURE-----\n\nfakebase64data\n-----END PGP SIGNATURE-----\n"
		attachments := []goimap.Attachment{
			{Name: "signature.asc", MimeType: "application/pgp-signature", Content: []byte(armored)},
		}
		if got := pgpDetectSignature(attachments); got != armored {
			t.Fatalf("expected %q, got %q", armored, got)
		}
	})
}

// TestEmailContentSize exercises the size-accounting GetMessageBodies and
// fetchAttachments both gate on before ever handing content back to a
// caller. GetMessageBodies/fetchAttachments/GetAttachment themselves can't
// be driven directly in this package's tests without a live (or fake)
// *goimap.Dialer connection — none exists in this test suite today, and
// standing one up is out of scope for this change — so this pins down the
// exact arithmetic those call sites depend on: the total of HTML, text, and
// every attachment's content, which is what a real oversized message would
// trip.
func TestEmailContentSize(t *testing.T) {
	t.Run("sums HTML, text, and every attachment", func(t *testing.T) {
		e := &goimap.Email{
			HTML: strings.Repeat("h", 10),
			Text: strings.Repeat("t", 5),
			Attachments: []goimap.Attachment{
				{Content: make([]byte, 3)},
				{Content: make([]byte, 7)},
			},
		}
		got := emailContentSize(e)
		want := int64(10 + 5 + 3 + 7)
		if got != want {
			t.Fatalf("got %d, want %d", got, want)
		}
	})

	t.Run("empty email sizes to zero", func(t *testing.T) {
		if got := emailContentSize(&goimap.Email{}); got != 0 {
			t.Fatalf("got %d, want 0", got)
		}
	})

	t.Run("many small attachments add up like one big one", func(t *testing.T) {
		withLoweredMaxInboundMessageBytes(t, 20)
		e := &goimap.Email{}
		for i := 0; i < 5; i++ {
			e.Attachments = append(e.Attachments, goimap.Attachment{Content: make([]byte, 5)})
		}
		// 5 attachments * 5 bytes = 25 bytes total, over the 20-byte cap,
		// even though no single attachment is anywhere near it.
		if size := emailContentSize(e); size <= mailmsg.MaxInboundMessageBytes {
			t.Fatalf("expected aggregate size %d to exceed cap %d", size, mailmsg.MaxInboundMessageBytes)
		}
	})

	t.Run("exactly at the cap does not overflow it", func(t *testing.T) {
		withLoweredMaxInboundMessageBytes(t, 16)
		e := &goimap.Email{HTML: strings.Repeat("a", 16)}
		if size := emailContentSize(e); size > mailmsg.MaxInboundMessageBytes {
			t.Fatalf("expected size %d not to exceed cap %d", size, mailmsg.MaxInboundMessageBytes)
		}
	})
}

// TestPartitionUIDsBySize exercises the pure split ListUnreadInbox uses to
// decide which UIDs are safe to pass to go-imap's GetEmails (which fully
// buffers each message's body/attachments into memory) versus which were
// already identified as oversized by the server-side "UNSEEN LARGER <cap>"
// SEARCH and so must never reach GetEmails at all.
//
// This is the seam that proves the expensive fetch is genuinely skipped for
// an oversized UID — not just checked-and-discarded afterwards: toFetch is
// the exact, and only, slice ListUnreadInbox passes to GetEmails, so any UID
// this function places in tooLarge instead structurally cannot appear in
// that call. ListUnreadInbox itself can't be driven end-to-end in this
// package's tests without a live/fake *goimap.Dialer (see TestEmailContentSize
// above), so partitionUIDsBySize is deliberately factored out as ordinary,
// connection-free logic to make that guarantee directly testable.
func TestPartitionUIDsBySize(t *testing.T) {
	t.Run("oversized UIDs are excluded from toFetch and routed to tooLarge", func(t *testing.T) {
		filtered := []int{1, 2, 3, 4, 5}
		oversized := []int{2, 4}

		toFetch, tooLarge := partitionUIDsBySize(filtered, oversized)

		wantFetch := []int{1, 3, 5}
		wantLarge := []int{2, 4}
		if !reflect.DeepEqual(toFetch, wantFetch) {
			t.Fatalf("toFetch = %v, want %v", toFetch, wantFetch)
		}
		if !reflect.DeepEqual(tooLarge, wantLarge) {
			t.Fatalf("tooLarge = %v, want %v", tooLarge, wantLarge)
		}
		// The defining property: no UID present in tooLarge may also be
		// present in toFetch — that would mean an oversized message's body
		// still gets fetched.
		large := make(map[int]bool, len(tooLarge))
		for _, uid := range tooLarge {
			large[uid] = true
		}
		for _, uid := range toFetch {
			if large[uid] {
				t.Fatalf("uid %d present in both toFetch and tooLarge", uid)
			}
		}
	})

	t.Run("no oversized UIDs: everything goes to toFetch", func(t *testing.T) {
		filtered := []int{10, 20, 30}
		toFetch, tooLarge := partitionUIDsBySize(filtered, nil)
		if !reflect.DeepEqual(toFetch, filtered) {
			t.Fatalf("toFetch = %v, want %v", toFetch, filtered)
		}
		if len(tooLarge) != 0 {
			t.Fatalf("expected no oversized UIDs, got %v", tooLarge)
		}
	})

	t.Run("all UIDs oversized: toFetch is empty", func(t *testing.T) {
		filtered := []int{7, 8}
		toFetch, tooLarge := partitionUIDsBySize(filtered, []int{7, 8})
		if len(toFetch) != 0 {
			t.Fatalf("expected empty toFetch, got %v", toFetch)
		}
		if !reflect.DeepEqual(tooLarge, filtered) {
			t.Fatalf("tooLarge = %v, want %v", tooLarge, filtered)
		}
	})

	t.Run("oversized UID outside this batch is ignored, not fabricated", func(t *testing.T) {
		// The LARGER search is scoped by UNSEEN but not by the checkpoint
		// filter, so it can report a UID that raced out of this batch
		// between the two round trips (e.g. no longer unseen). It must not
		// show up in either output slice.
		filtered := []int{1, 2}
		oversized := []int{2, 99}
		toFetch, tooLarge := partitionUIDsBySize(filtered, oversized)
		if !reflect.DeepEqual(toFetch, []int{1}) {
			t.Fatalf("toFetch = %v, want [1]", toFetch)
		}
		if !reflect.DeepEqual(tooLarge, []int{2}) {
			t.Fatalf("tooLarge = %v, want [2]", tooLarge)
		}
	})

	t.Run("empty filtered returns empty slices regardless of oversized input", func(t *testing.T) {
		toFetch, tooLarge := partitionUIDsBySize(nil, []int{1, 2, 3})
		if len(toFetch) != 0 || len(tooLarge) != 0 {
			t.Fatalf("expected both empty, got toFetch=%v tooLarge=%v", toFetch, tooLarge)
		}
	})
}

// TestUidSetCriteria pins down the exact IMAP sequence-set rendering
// GetMessageBodies (and FetchRawMessage) rely on to scope their pre-fetch
// oversized-message SEARCH to precisely the UIDs they were asked about.
func TestUidSetCriteria(t *testing.T) {
	t.Run("single uid", func(t *testing.T) {
		if got := uidSetCriteria([]int{42}); got != "42" {
			t.Fatalf("got %q, want %q", got, "42")
		}
	})

	t.Run("multiple uids are comma separated", func(t *testing.T) {
		if got := uidSetCriteria([]int{1, 2, 3}); got != "1,2,3" {
			t.Fatalf("got %q, want %q", got, "1,2,3")
		}
	})

	t.Run("empty slice renders as empty string", func(t *testing.T) {
		if got := uidSetCriteria(nil); got != "" {
			t.Fatalf("got %q, want empty string", got)
		}
	})
}

// TestGetMessageBodiesOversizedSearchCriteria pins down the exact server-side
// SEARCH criteria GetMessageBodies composes to identify oversized UIDs among
// the ones it's asked about *before* ever calling go-imap's buffering
// GetEmails — the UID-set-scoped counterpart to ListUnreadInbox's
// "UNSEEN LARGER <cap>" criteria. IMAP ANDs search keys together, so
// "UID <set> LARGER <cap>" restricts the oversized check to exactly this
// call's requested UIDs rather than the whole mailbox.
func TestGetMessageBodiesOversizedSearchCriteria(t *testing.T) {
	withLoweredMaxInboundMessageBytes(t, 100)
	uids := []int{5, 10, 15}
	sb := goimap.Search().UID(uidSetCriteria(uids)).Larger(int(mailmsg.MaxInboundMessageBytes))
	got := sb.Build()
	want := "UID 5,10,15 LARGER 100"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestGetMessageBodiesExcludesOversizedUIDFromBufferingFetch drives
// partitionUIDsBySize exactly as GetMessageBodies does: the requested UID
// batch as filtered, and the result of the "UID <set> LARGER <cap>" SEARCH
// (TestGetMessageBodiesOversizedSearchCriteria above) as oversized.
//
// This is the fix for the final-review finding that GetMessageBodies (unlike
// ListUnreadInbox) had no pre-fetch size bound: an oversized message
// delivered to a victim's mailbox would previously be fully buffered by
// GetEmails on every inbox-cache-sync or rules-run pass, before any size
// check ran. GetMessageBodies itself can't be driven end-to-end without a
// live/fake *goimap.Dialer (see TestPartitionUIDsBySize above), so this pins
// down — at the same pure-function seam that test uses for ListUnreadInbox —
// that an oversized UID the SEARCH reports is structurally excluded from the
// toFetch slice, and therefore never reaches GetEmails at all.
func TestGetMessageBodiesExcludesOversizedUIDFromBufferingFetch(t *testing.T) {
	requested := []int{101, 102, 103, 104}
	// Simulates what
	// d.SearchUIDs(goimap.Search().UID(uidSetCriteria(requested)).Larger(cap))
	// would return: only UID 103 is oversized.
	oversized := []int{103}

	toFetch, tooLarge := partitionUIDsBySize(requested, oversized)

	if !reflect.DeepEqual(toFetch, []int{101, 102, 104}) {
		t.Fatalf("toFetch = %v, want [101 102 104]", toFetch)
	}
	if !reflect.DeepEqual(tooLarge, []int{103}) {
		t.Fatalf("tooLarge = %v, want [103]", tooLarge)
	}
	for _, uid := range toFetch {
		if uid == 103 {
			t.Fatal("oversized uid 103 must never appear in toFetch — it would be buffered by GetEmails")
		}
	}
}

// inboxBodies is the poller's view of a fetched message's content, and it is
// deliberately not the same view the clients get.
//
// ListUnreadInbox (the poller's source) prefers the text/plain part, while
// every client-facing path — ListUnreadMessages and GetMessageBodies — prefers
// text/html. So a multipart/alternative message can hand the poller an
// innocuous plain-text part while the clients render a hostile HTML one. That
// asymmetry is why Message carries both: an anti-phishing scan that read only
// Body would systematically miss a kypost:// pairing link planted in the HTML
// part, which is exactly the attack the scan exists to catch.
//
// Body's text-first preference is preserved as-is here on purpose — it is what
// gets classified and warmed into the mail cache, and changing it is a
// different change with different blast radius.
func TestInboxBodies(t *testing.T) {
	t.Run("prefers text for Body and reports HTML separately", func(t *testing.T) {
		body, bodyHTML := inboxBodies(&goimap.Email{
			Text: "  plain part  ",
			HTML: "  <p>html part</p>  ",
		})
		if body != "plain part" {
			t.Fatalf("Body = %q, want the trimmed text part", body)
		}
		if bodyHTML != "<p>html part</p>" {
			t.Fatalf("BodyHTML = %q, want the trimmed html part", bodyHTML)
		}
	})

	t.Run("falls back to HTML for Body when there is no text part", func(t *testing.T) {
		body, bodyHTML := inboxBodies(&goimap.Email{HTML: "<p>only html</p>"})
		if body != "<p>only html</p>" {
			t.Fatalf("Body = %q, want the html fallback", body)
		}
		if bodyHTML != "<p>only html</p>" {
			t.Fatalf("BodyHTML = %q, want the html part", bodyHTML)
		}
	})

	t.Run("reports no HTML for a text-only message", func(t *testing.T) {
		body, bodyHTML := inboxBodies(&goimap.Email{Text: "only text"})
		if body != "only text" {
			t.Fatalf("Body = %q, want the text part", body)
		}
		if bodyHTML != "" {
			t.Fatalf("BodyHTML = %q, want empty", bodyHTML)
		}
	})

	t.Run("empty email yields both empty", func(t *testing.T) {
		body, bodyHTML := inboxBodies(&goimap.Email{})
		if body != "" || bodyHTML != "" {
			t.Fatalf("got Body=%q BodyHTML=%q, want both empty", body, bodyHTML)
		}
	})
}

// TestClampCheckpoint covers the rule that makes "the next tick retries it"
// true: ListUnreadInbox returns only UIDs above the checkpoint it is given and
// advances its own to the highest UID it FETCHED, so a checkpoint written
// without regard for what the caller actually handled retires the messages the
// caller deliberately left alone.
func TestClampCheckpoint(t *testing.T) {
	t.Run("nothing deferred advances to the fetched checkpoint", func(t *testing.T) {
		if got := ClampCheckpoint("10", "20", nil); got != "20" {
			t.Fatalf("ClampCheckpoint = %q, want %q", got, "20")
		}
	})

	t.Run("holds one below the lowest deferred uid", func(t *testing.T) {
		// 14 is left for a later tick, so the checkpoint must stay below it —
		// 15..20 are refetched and filtered by the processed set.
		if got := ClampCheckpoint("10", "20", []string{"18", "14", "16"}); got != "13" {
			t.Fatalf("ClampCheckpoint = %q, want %q", got, "13")
		}
	})

	t.Run("a deferred message is returned again by the next fetch", func(t *testing.T) {
		// The property that actually matters, stated in ListUnreadInbox's own
		// terms: UID > checkpoint.
		next := ClampCheckpoint("10", "20", []string{"14"})
		if minUID := parseCheckpointUID(next); 14 <= minUID {
			t.Fatalf("checkpoint %q excludes the deferred UID 14 (minUID=%d)", next, minUID)
		}
	})

	t.Run("never rewinds below the previous checkpoint", func(t *testing.T) {
		// The lowest deferred UID is the first of the batch, so there is no
		// room to advance at all — but rewinding would re-scan mail already
		// retired on an earlier tick.
		if got := ClampCheckpoint("10", "20", []string{"11"}); got != "10" {
			t.Fatalf("ClampCheckpoint = %q, want the previous checkpoint %q", got, "10")
		}
	})

	t.Run("never advances past what was fetched", func(t *testing.T) {
		if got := ClampCheckpoint("10", "20", []string{"99"}); got != "20" {
			t.Fatalf("ClampCheckpoint = %q, want %q", got, "20")
		}
	})

	t.Run("an unparseable id holds the checkpoint rather than guessing", func(t *testing.T) {
		// Cannot prove the message would come back, and retiring it is the
		// unrecoverable direction.
		if got := ClampCheckpoint("10", "20", []string{"not-a-uid"}); got != "10" {
			t.Fatalf("ClampCheckpoint = %q, want the previous checkpoint %q", got, "10")
		}
	})

	t.Run("an empty previous checkpoint is a valid floor", func(t *testing.T) {
		if got := ClampCheckpoint("", "20", []string{"1"}); got != "" {
			t.Fatalf("ClampCheckpoint = %q, want an empty checkpoint", got)
		}
		if got := ClampCheckpoint("", "20", []string{"5"}); got != "4" {
			t.Fatalf("ClampCheckpoint = %q, want %q", got, "4")
		}
	})
}
