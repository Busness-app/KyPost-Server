package wkdpublish

import (
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
// A lookup error is returned (and is not a match) so callers can distinguish
// "record absent / DNS down" from "present but wrong".
func CheckTXT(domain, token string) (bool, error) {
	values, err := LookupTXT(TXTRecordName(domain))
	if err != nil {
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
