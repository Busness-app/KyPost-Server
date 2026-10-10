package mailmsg

import (
	"fmt"
	"strings"
	"testing"
)

func TestReplyThreading(t *testing.T) {
	irt, refs := ReplyThreading("<b@x.test>", "<root@x.test> <a@x.test>", "")
	if irt != "<b@x.test>" || strings.Join(refs, " ") != "<root@x.test> <a@x.test> <b@x.test>" {
		t.Fatalf("chain: %q %v", irt, refs)
	}
	// No References: fall back to a single In-Reply-To parent.
	if _, refs = ReplyThreading("<b@x.test>", "", "<a@x.test>"); strings.Join(refs, " ") != "<a@x.test> <b@x.test>" {
		t.Fatalf("in-reply-to fallback: %v", refs)
	}
	// Nothing well formed to reply to: no threading at all.
	for _, id := range []string{"", "not-an-id", "<a@x.test> <b@x.test>", "<no-at-sign>"} {
		if irt, refs := ReplyThreading(id, "<r@x.test>", ""); irt != "" || refs != nil {
			t.Fatalf("Message-ID %q threaded: %q %v", id, irt, refs)
		}
	}
}

// Header text comes from a sender-controlled message. Only msg-ids survive,
// so a CR/LF or a forged header in the original cannot reach the reply.
func TestMessageIDsDropInjection(t *testing.T) {
	got := MessageIDs("<a@x.test>\r\nBcc: victim@x.test\r\n (comment) <b@x.test>junk<c d@x.test>")
	if strings.Join(got, "|") != "<a@x.test>|<b@x.test>" {
		t.Fatalf("got %q", got)
	}
}

func TestBuildWritesThreadingHeadersSafely(t *testing.T) {
	refs := []string{}
	for i := 0; i < 30; i++ {
		refs = append(refs, fmt.Sprintf("<r%d@x.test>", i))
	}
	raw := string(Message{
		From: "a@x.test", To: []string{"b@x.test"}, Subject: "Re: s", Body: "b",
		InReplyTo:  "<r29@x.test>\r\nBcc: victim@x.test",
		References: refs,
	}.Build())
	if strings.Contains(raw, "victim") {
		t.Fatalf("injected header reached the message:\n%s", raw)
	}
	if !strings.Contains(raw, "In-Reply-To: <r29@x.test>\r\n") {
		t.Fatalf("In-Reply-To missing:\n%s", raw)
	}
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	refLine := head[strings.Index(head, "References: "):]
	if n := strings.Count(refLine, "@x.test>"); n < maxReferences || !strings.Contains(refLine, "<r0@x.test>") || strings.Contains(refLine, "<r1@x.test>") {
		t.Fatalf("References not capped to root + newest: %d ids\n%s", n, refLine)
	}
	for _, line := range strings.Split(head, "\r\n") {
		if len(line) > 998 {
			t.Fatalf("header line over 998 octets: %d", len(line))
		}
	}
	if plain := string(Message{From: "a@x.test", To: []string{"b@x.test"}, Body: "b"}.Build()); strings.Contains(plain, "In-Reply-To") || strings.Contains(plain, "References") {
		t.Fatal("threading headers on a message that is not a reply")
	}
}

// A long References chain keeps its root and its newest ids; the scan must not
// stop early and drop the newest end.
func TestReplyThreadingLongChainKeepsNewest(t *testing.T) {
	refs := make([]string, 100)
	for i := range refs {
		refs[i] = fmt.Sprintf("<r%d@x.test>", i)
	}
	_, got := ReplyThreading("<orig@x.test>", strings.Join(refs, " "), "")
	want := append(append([]string{"<r0@x.test>"}, refs[82:]...), "<orig@x.test>")
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}
