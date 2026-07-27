package imap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
)

// run-4 findings H3 and M10: a DKIM pass proves only that the headers the
// signature actually covered are intact. RFC 6376 hashes just the headers
// named in h=, takes the LAST occurrence of each, and tolerates extra fields —
// so an attacker can staple an unsigned duplicate above a signed one, or
// replace a header the signer never covered, and the signature still verifies.
//
// Send-as verification trusted a Subject located by IMAP SEARCH, and Autocrypt
// harvest trusted an Autocrypt header, on the strength of a d= match alone.
// Neither header need have been signed.
func TestVerifyDKIMCoversHeader(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	lookup := func(string) ([]string, error) {
		return []string{"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub)}, nil
	}

	const body = "From: newsletter@bank.com\r\n" +
		"To: mallory@evil.test\r\n" +
		"Subject: Your monthly statement\r\n" +
		"Date: Sat, 26 Jul 2026 10:00:00 +0000\r\n" +
		"\r\nHello.\r\n"

	sign := func(headers []string) string {
		var out strings.Builder
		if err := dkim.Sign(&out, strings.NewReader(body), &dkim.SignOptions{
			Domain: "bank.com", Selector: "sel", Signer: priv, HeaderKeys: headers,
		}); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return out.String()
	}

	t.Run("unsigned header replaced", func(t *testing.T) {
		// Subject absent from h=, so the attacker simply rewrites it.
		signed := sign([]string{"from", "to", "date"})
		tampered := strings.Replace(signed, "Subject: Your monthly statement", "Subject: KYPOST-VERIFY-9f3a21", 1)
		if verifyDKIMCoversHeaderWithLookup([]byte(tampered), "bank.com", "Subject", lookup) {
			t.Error("accepted a Subject the signature never covered")
		}
	})

	t.Run("duplicate header prepended above the signed one", func(t *testing.T) {
		// Subject signed once (go-msgauth's default, and what most senders do).
		// The verifier hashes the last occurrence; IMAP SEARCH matches the
		// attacker's prepended one.
		signed := sign([]string{"from", "to", "subject", "date"})
		tampered := "Subject: KYPOST-VERIFY-9f3a21\r\n" + signed
		if verifyDKIMCoversHeaderWithLookup([]byte(tampered), "bank.com", "Subject", lookup) {
			t.Error("accepted a message carrying a second, unsigned Subject above the signed one")
		}
	})

	t.Run("genuinely signed single header", func(t *testing.T) {
		signed := sign([]string{"from", "to", "subject", "date"})
		if !verifyDKIMCoversHeaderWithLookup([]byte(signed), "bank.com", "Subject", lookup) {
			t.Error("rejected a Subject that the signature does cover")
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		signed := sign([]string{"from", "to", "subject", "date"})
		if verifyDKIMCoversHeaderWithLookup([]byte(signed), "other.example", "Subject", lookup) {
			t.Error("accepted a signature from a domain that is not the one asked about")
		}
	})
}
