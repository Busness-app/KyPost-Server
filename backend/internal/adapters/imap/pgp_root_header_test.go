package imap

import (
	"sort"
	"testing"

	goimap "github.com/BrianLeishman/go-imap"
)

// Encryption status used to be inferred from the shape of a message's
// attachments, because goimap does not parse root headers. A bodyless message
// carrying one armored .pgp attachment is indistinguishable from a real
// PGP/MIME envelope that way — so a sender could build one, and be rewarded
// with a padlock in the reader and a message the poller skips classifying.
//
// It is decided by the root Content-Type now (RFC 3156). These cover the two
// halves that decision is made of: reading the header, and what to do with the
// answer.

func TestIsPGPMIMERootContentType(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "the RFC 3156 root",
			raw:  `multipart/encrypted; protocol="application/pgp-encrypted"; boundary=abc`,
			want: true,
		},
		{
			name: "full header line, as FetchHeaderFields returns it",
			raw:  `Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=abc`,
			want: true,
		},
		{
			name: "unquoted protocol parameter",
			raw:  `multipart/encrypted; protocol=application/pgp-encrypted`,
			want: true,
		},
		{
			name: "case and whitespace are not significant",
			raw:  `  Content-Type:   MULTIPART/ENCRYPTED; PROTOCOL="APPLICATION/PGP-ENCRYPTED"  `,
			want: true,
		},
		{
			// S/MIME is also multipart/encrypted. Treating it as OpenPGP would
			// hand the reader a payload it cannot decrypt while telling the
			// user it can.
			name: "multipart/encrypted with another protocol",
			raw:  `multipart/encrypted; protocol="application/pkcs7-mime"`,
			want: false,
		},
		{
			name: "multipart/encrypted with no protocol at all",
			raw:  `multipart/encrypted; boundary=abc`,
			want: false,
		},
		{
			// The forgery: an ordinary message carrying an armored attachment.
			name: "ordinary multipart/mixed",
			raw:  `multipart/mixed; boundary=abc`,
			want: false,
		},
		{name: "signed, not encrypted", raw: `multipart/signed; protocol="application/pgp-signature"`, want: false},
		{name: "plain text", raw: "text/plain; charset=utf-8", want: false},
		{name: "empty", raw: "", want: false},
		{name: "unparseable", raw: "multipart/encrypted; protocol=", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPGPMIMERootContentType(tc.raw); got != tc.want {
				t.Fatalf("isPGPMIMERootContentType(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func armoredAttachment() goimap.Attachment {
	return goimap.Attachment{
		Name:     "encrypted.asc",
		MimeType: "application/octet-stream",
		Content:  []byte("-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----\n"),
	}
}

// Only the messages that could possibly be envelopes cost a header fetch. This
// is what keeps the correct test affordable: it runs on nothing but the rare
// bodyless message whose every part looks like envelope machinery.
func TestPGPEnvelopeCandidatesAreNarrow(t *testing.T) {
	emails := map[int]*goimap.Email{
		1: {Attachments: []goimap.Attachment{armoredAttachment()}},
		2: {Attachments: []goimap.Attachment{armoredAttachment()}},
		3: {Attachments: []goimap.Attachment{
			armoredAttachment(),
			{Name: "report.xlsx", MimeType: "application/vnd.ms-excel", Content: []byte("PK")},
		}},
		4: {Attachments: []goimap.Attachment{{Name: "photo.png", MimeType: "image/png", Content: []byte{0x89}}}},
		5: nil,
	}
	bodies := map[int]string{
		1: "",
		2: "here is the quarterly report", // has a body: not a whole-message envelope
		3: "",
		4: "",
	}

	candidates, payloads := pgpEnvelopeCandidates(emails, bodies)
	sort.Ints(candidates)

	if len(candidates) != 1 || candidates[0] != 1 {
		t.Fatalf("candidates = %v, want just [1]", candidates)
	}
	if payloads[1] == "" {
		t.Fatal("the candidate carried no ciphertext payload")
	}
}

// The point of the whole change: a candidate whose root Content-Type says
// otherwise is NOT an envelope.
func TestEnvelopeConfirmationRejectsAForgedShape(t *testing.T) {
	candidates := []int{10, 11}
	payloads := map[int]string{10: "ciphertext-10", 11: "ciphertext-11"}
	// 10 is a real PGP/MIME message; 11 is ordinary mail with an armored
	// attachment, built to look like one.
	confirmed := map[int]bool{10: true}

	got := applyEnvelopeConfirmation(candidates, payloads, confirmed, true)

	if got[10].Payload != "ciphertext-10" {
		t.Fatal("a genuine PGP/MIME message lost its payload")
	}
	if got[11].Payload != "" {
		t.Fatal("a forged envelope shape was still reported as encrypted")
	}
}

// When the header fetch itself fails, every candidate keeps the old
// attachment-only verdict. An IMAP blip must not strip the encrypted marking
// off every real encrypted message in the batch — a far likelier and worse
// outcome than the forgery this narrows, and not something a message can
// provoke.
func TestEnvelopeConfirmationFallsBackWhenHeadersCannotBeRead(t *testing.T) {
	candidates := []int{10, 11}
	payloads := map[int]string{10: "ciphertext-10", 11: "ciphertext-11"}

	got := applyEnvelopeConfirmation(candidates, payloads, nil, false)

	if got[10].Payload == "" || got[11].Payload == "" {
		t.Fatal("a failed header fetch unmarked encrypted mail instead of falling back")
	}
}
