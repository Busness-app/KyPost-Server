package processor

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// webPushAuthLength is the WebPush authentication secret length in bytes,
// fixed at 16 by RFC 8291 §3.2.
const webPushAuthLength = 16

// decodeWebPushKey decodes a subscription key exactly as webpush-go's own
// decodeSubscriptionKey does: pad to a multiple of four, try the standard
// alphabet, fall back to base64url. Reimplemented rather than approximated so
// validation can never reject key material the sender would have accepted —
// a stricter check here would turn a deliverable notification into a 400 at
// registration.
func decodeWebPushKey(key string) ([]byte, error) {
	buf := bytes.NewBufferString(key)
	if rem := len(key) % 4; rem != 0 {
		buf.WriteString(strings.Repeat("=", 4-rem))
	}
	if decoded, err := base64.StdEncoding.DecodeString(buf.String()); err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.DecodeString(buf.String())
}

// ValidateWebPushKeys checks that p256dh and auth are well-formed WebPush
// (RFC 8291) subscription keys: p256dh must decode to an uncompressed P-256
// point on the curve, auth to a 16-byte secret. Both must be present together
// or both absent — partial key material cannot encrypt anything, so accepting
// it would store a device that silently never receives a notification.
func ValidateWebPushKeys(p256dh, auth string) error {
	p256dh = strings.TrimSpace(p256dh)
	auth = strings.TrimSpace(auth)

	if p256dh == "" && auth == "" {
		return nil
	}
	if p256dh == "" || auth == "" {
		return errors.New("p256dh and auth must both be present or both absent")
	}

	rawKey, err := decodeWebPushKey(p256dh)
	if err != nil {
		return fmt.Errorf("p256dh is not valid base64: %w", err)
	}
	// NewPublicKey enforces the 65-byte length, the 0x04 uncompressed prefix
	// and that the point is actually on P-256 — all three, in one check.
	if _, err := ecdh.P256().NewPublicKey(rawKey); err != nil {
		return fmt.Errorf("p256dh is not an uncompressed P-256 point: %w", err)
	}

	rawAuth, err := decodeWebPushKey(auth)
	if err != nil {
		return fmt.Errorf("auth is not valid base64: %w", err)
	}
	if len(rawAuth) != webPushAuthLength {
		return fmt.Errorf("auth must be %d bytes, got %d", webPushAuthLength, len(rawAuth))
	}
	return nil
}
