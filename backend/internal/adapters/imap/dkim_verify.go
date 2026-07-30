package imap

import (
	"bytes"
	"net/mail"
	"net/textproto"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

// VerifyDKIMForDomain reports whether raw (a complete RFC 5322 message,
// headers + body) carries at least one cryptographically valid DKIM
// signature whose d= domain exactly matches domain.
//
// This replaces trusting a stored/claimed Authentication-Results header
// (which an account holder can forge into their own mailbox via IMAP
// APPEND, with zero MTA involvement) with real verification: dkim.Verify
// looks up the signing domain's public key from DNS and recomputes the
// signature over the message's canonicalized headers/body. An attacker
// without that domain's private key cannot produce a signature this
// function will accept, regardless of what headers they can write into
// their own mailbox.
//
// Exact-match on domain (no subdomain/suffix matching) — domain is always
// the candidate send-as address's own domain, and DKIM's own identity-
// alignment concept (DMARC's "relaxed" vs "strict" alignment) isn't needed
// for this one-address-at-a-time check.
func VerifyDKIMForDomain(raw []byte, domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || len(raw) == 0 {
		return false
	}
	return verifyDKIMForDomainWithLookup(raw, domain, nil)
}

// verifyDKIMForDomainWithLookup is VerifyDKIMForDomain's testable core: a
// nil lookupTXT defers to dkim.Verify's own default (net.LookupTXT); tests
// in this package inject a fake lookup instead of requiring live DNS.
// maxDKIMVerifications caps how many signatures on one message we will verify.
// A legitimate message carries one or two; the cap exists so a hostile one
// cannot turn each extra header into a goroutine and a DNS query.
const maxDKIMVerifications = 3

func verifyDKIMForDomainWithLookup(raw []byte, domain string, lookupTXT func(string) ([]string, error)) bool {
	var verifications []*dkim.Verification
	var err error
	// MaxVerifications is load-bearing, not tidiness: go-msgauth spawns one
	// goroutine, one io.Pipe and one DNS TXT lookup PER DKIM-Signature header,
	// all concurrently, and the d= filter below only runs once they have all
	// finished. Left unbounded, one inbound message is a goroutine and
	// attacker-chosen-DNS amplifier against the shared daemon. RFC 6376 6.1
	// explicitly allows a verifier to stop early.
	verifications, err = dkim.VerifyWithOptions(bytes.NewReader(raw), &dkim.VerifyOptions{
		LookupTXT:        lookupTXT,
		MaxVerifications: maxDKIMVerifications,
	})
	if err != nil {
		// A malformed message, or dkim.ErrTooManySignatures alongside a
		// partial result — fail closed either way rather than trusting a
		// partial verification list.
		return false
	}
	for _, v := range verifications {
		if v.Err == nil && strings.EqualFold(strings.TrimSpace(v.Domain), domain) {
			return true
		}
	}
	return false
}

// VerifyDKIMCoversHeader reports whether raw carries a valid DKIM signature
// for domain that actually covers header — that is, the header is named in the
// signature's h= tag and appears exactly once in the message.
//
// VerifyDKIMForDomain above answers a narrower question than its callers were
// asking. A DKIM pass proves the headers the signature *covered* are intact;
// it says nothing about a header the signer never included. Per RFC 6376 the
// verifier hashes only the fields named in h=, selects the LAST occurrence of
// each, and tolerates additional fields — so an attacker holding any genuinely
// signed message from the domain can:
//
//   - rewrite a header the signer left out of h= (common for Subject), or
//   - prepend a second copy above the signed one, which the verifier ignores
//     and every other reader (IMAP SEARCH included) sees first,
//
// and the signature still verifies. Two call sites trusted exactly that:
// send-as verification located a challenge code by Subject, and Autocrypt
// harvest read a key out of an Autocrypt header, each gated on a d= match
// alone. Both were forgeable by replaying someone else's signed mail.
//
// The duplicate check is deliberately "exactly once" rather than "the last
// one": if the header appears twice, which copy a given reader honors is not
// something this function can decide for it, so it refuses.
func VerifyDKIMCoversHeader(raw []byte, domain, header string) bool {
	return verifyDKIMCoversHeaderWithLookup(raw, domain, header, nil)
}

func verifyDKIMCoversHeaderWithLookup(raw []byte, domain, header string, lookupTXT func(string) ([]string, error)) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	header = strings.TrimSpace(header)
	if domain == "" || header == "" || len(raw) == 0 {
		return false
	}

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return false
	}
	if len(msg.Header[textproto.CanonicalMIMEHeaderKey(header)]) != 1 {
		return false
	}

	var verifications []*dkim.Verification
	verifications, err = dkim.VerifyWithOptions(bytes.NewReader(raw), &dkim.VerifyOptions{
		LookupTXT:        lookupTXT,
		MaxVerifications: maxDKIMVerifications,
	})
	if err != nil {
		return false
	}
	for _, v := range verifications {
		if v.Err != nil || !strings.EqualFold(strings.TrimSpace(v.Domain), domain) {
			continue
		}
		for _, signed := range v.HeaderKeys {
			if strings.EqualFold(strings.TrimSpace(signed), header) {
				return true
			}
		}
	}
	return false
}
