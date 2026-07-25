package wkdpublish

import (
	"errors"
	"net"
	"strings"
)

// LookupTXT is the DNS resolver seam (overridable in tests).
var LookupTXT = net.LookupTXT

const txtPrefix = "kypost-wkd-verify="

// TXTRecordName is the DNS name that must carry the proof token.
func TXTRecordName(domain string) string {
	return "_kypost-wkd." + normalizeDomain(domain)
}

// CheckTXT reports whether the domain's proof record currently carries token.
// A definitive "not found" result — NXDOMAIN or NODATA on the record name,
// i.e. a *net.DNSError with IsNotFound set — means the proof is genuinely
// absent (the record was deleted, or never existed) and is reported as
// (false, nil): the same outcome as a record that resolves but carries the
// wrong value, since both mean "no valid proof right now" and callers must
// treat them identically for revocation purposes. Any other lookup error
// (timeout, SERVFAIL, network down, etc.) is a transient resolver failure
// and is returned as an error, so callers can avoid flipping a claim on a
// blip.
func CheckTXT(domain, token string) (bool, error) {
	values, err := LookupTXT(TXTRecordName(domain))
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil
		}
		return false, err
	}
	want := txtPrefix + token
	for _, v := range values {
		if strings.TrimSpace(v) == want {
			return true, nil
		}
	}
	return false, nil
}
