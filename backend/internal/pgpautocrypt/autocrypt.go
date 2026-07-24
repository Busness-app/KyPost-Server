// Package pgpautocrypt parses the RFC-Autocrypt `Autocrypt:` mail header,
// extracting the sender's advertised address and public-key bytes.
package pgpautocrypt

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"
)

// ParseAutocryptHeader parses one `Autocrypt` header value (the text after
// "Autocrypt:") into its addr attribute and base64-decoded keydata bytes.
//
// Per the Autocrypt spec, attributes are `;`-separated `name=value` pairs.
// `prefer-encrypt` is parsed and ignored (we only want a usable key). Any
// unknown attribute whose name does NOT start with "_" is "critical" and
// makes the whole header invalid; unknown "_"-prefixed attributes are
// non-critical and ignored. keydata is standard base64, possibly folded with
// whitespace, so all whitespace is stripped before decoding.
func ParseAutocryptHeader(value string) (addr string, keydata []byte, err error) {
	var keyB64 string
	haveAddr, haveKey := false, false
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			return "", nil, fmt.Errorf("autocrypt: malformed attribute %q", part)
		}
		name := strings.TrimSpace(part[:eq])
		v := strings.TrimSpace(part[eq+1:])
		switch strings.ToLower(name) {
		case "addr":
			addr, haveAddr = v, true
		case "keydata":
			keyB64, haveKey = v, true
		case "prefer-encrypt":
			// parsed and ignored
		default:
			if !strings.HasPrefix(name, "_") {
				return "", nil, fmt.Errorf("autocrypt: unknown critical attribute %q", name)
			}
			// non-critical (underscore) attribute: ignore
		}
	}
	if !haveAddr || strings.TrimSpace(addr) == "" {
		return "", nil, fmt.Errorf("autocrypt: missing addr")
	}
	if !haveKey {
		return "", nil, fmt.Errorf("autocrypt: missing keydata")
	}
	keyB64 = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, keyB64)
	decoded, derr := base64.StdEncoding.DecodeString(keyB64)
	if derr != nil {
		return "", nil, fmt.Errorf("autocrypt: keydata base64: %w", derr)
	}
	if len(decoded) == 0 {
		return "", nil, fmt.Errorf("autocrypt: empty keydata")
	}
	return addr, decoded, nil
}
