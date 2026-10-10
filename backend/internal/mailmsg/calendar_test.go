package mailmsg

import (
	"bytes"
	"errors"
	"mime"
	"strings"
	"testing"

	"github.com/jhillyerd/enmime/v2"
)

const validReply = "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//KyPost//EN\nMETHOD:REPLY\nBEGIN:VEVENT\nUID:e1@x.test\nATTENDEE;PARTSTAT=ACCEPTED:mailto:b@x.test\n DESCRIPTION folded\nEND:VEVENT\nEND:VCALENDAR\n"

func TestCalendarReplyNormalisesAValidReply(t *testing.T) {
	got, err := CalendarReply(validReply)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ReplaceAll(string(got), "\r\n", ""), "\n") || !strings.HasSuffix(string(got), "END:VCALENDAR\r\n") {
		t.Fatalf("not CRLF-normalised: %q", got)
	}
}

func TestCalendarReplyRefusals(t *testing.T) {
	swap := func(old, new string) string { return strings.Replace(validReply, old, new, 1) }
	for name, ics := range map[string]string{
		"too large":         validReply + strings.Repeat("X", MaxCalendarReplyBytes),
		"not UTF-8":         swap("PRODID:-//KyPost//EN", "PRODID:\xff"),
		"control character": swap("PRODID:-//KyPost//EN", "PRODID:a\x00b"),
		"header injection":  swap("PRODID:-//KyPost//EN", "PRODID:x\r\n\r\nBcc: victim@x.test"),
		"request not reply": swap("METHOD:REPLY", "METHOD:REQUEST"),
		"no method":         swap("METHOD:REPLY\n", ""),
		"two methods":       swap("METHOD:REPLY", "METHOD:REPLY\nMETHOD:REPLY"),
		"method in event":   swap("METHOD:REPLY\nBEGIN:VEVENT", "BEGIN:VEVENT\nMETHOD:REPLY"),
		"no event":          swap("BEGIN:VEVENT\nUID:e1@x.test\nATTENDEE;PARTSTAT=ACCEPTED:mailto:b@x.test\n DESCRIPTION folded\nEND:VEVENT\n", ""),
		"two events":        swap("END:VEVENT", "END:VEVENT\nBEGIN:VEVENT\nUID:e2\nEND:VEVENT"),
		"unbalanced":        swap("END:VEVENT\n", ""),
		"trailing content":  validReply + "BEGIN:VCALENDAR\n",
		"not a calendar":    "hello",
		"leading fold":      " " + validReply,
		"too deep":          swap("BEGIN:VEVENT\n", "BEGIN:VEVENT\n"+strings.Repeat("BEGIN:X\n", 8)+strings.Repeat("END:X\n", 8)),
	} {
		if _, err := CalendarReply(ics); !errors.Is(err, ErrCalendarReply) {
			t.Errorf("%s: err = %v, want ErrCalendarReply", name, err)
		}
	}
}

// The reply must be a text/calendar; method=REPLY part alternative to the
// text body, inside multipart/mixed when there are attachments.
func TestBuildCalendarReplyMIME(t *testing.T) {
	ics, err := CalendarReply(validReply)
	if err != nil {
		t.Fatal(err)
	}
	for _, withAttachment := range []bool{false, true} {
		m := Message{From: "b@x.test", To: []string{"organizer@x.test"}, Subject: "Accepted: e1", Body: "Accepted", CalendarReply: ics}
		if withAttachment {
			m.Attachments = []Attachment{{Name: "note.txt", MimeType: "text/plain", Content: []byte("n")}}
		}
		raw := m.Build()
		env, err := enmime.ReadEnvelope(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		var cal *enmime.Part
		var walk func(p *enmime.Part)
		walk = func(p *enmime.Part) {
			for ; p != nil; p = p.NextSibling {
				if p.ContentType == "text/calendar" {
					cal = p
				}
				walk(p.FirstChild)
			}
		}
		walk(env.Root)
		if cal == nil || cal.Parent == nil || cal.Parent.ContentType != "multipart/alternative" || !bytes.Equal(cal.Content, ics) {
			t.Fatalf("attachment=%v: calendar part missing or misplaced:\n%s", withAttachment, raw)
		}
		_, params, _ := mime.ParseMediaType(cal.Header.Get("Content-Type"))
		if params["method"] != "REPLY" || params["charset"] != "UTF-8" {
			t.Fatalf("calendar params = %v", params)
		}
		if env.Text != "Accepted" || (withAttachment && len(env.Attachments) != 1) {
			t.Fatalf("attachment=%v: body %q attachments %d", withAttachment, env.Text, len(env.Attachments))
		}
	}
}
