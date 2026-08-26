package processor

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// freshSubscriptionKeys returns a p256dh/auth pair shaped exactly as a
// UnifiedPush connector would send them: an uncompressed P-256 public point
// and a 16-byte auth secret, both base64url without padding.
func freshSubscriptionKeys(t *testing.T) (p256dh, auth string) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	authBytes := make([]byte, 16)
	if _, err := rand.Read(authBytes); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		base64.RawURLEncoding.EncodeToString(authBytes)
}

func TestValidateWebPushKeys(t *testing.T) {
	goodP256DH, goodAuth := freshSubscriptionKeys(t)

	cases := []struct {
		name     string
		p256dh   string
		auth     string
		wantErr  bool
		errMatch string
	}{
		{name: "valid pair", p256dh: goodP256DH, auth: goodAuth},
		{name: "both absent is allowed", p256dh: "", auth: ""},
		{name: "whitespace counts as absent", p256dh: "  ", auth: "\t"},
		{
			name: "p256dh without auth", p256dh: goodP256DH, auth: "",
			wantErr: true, errMatch: "both",
		},
		{
			name: "auth without p256dh", p256dh: "", auth: goodAuth,
			wantErr: true, errMatch: "both",
		},
		{
			name:   "p256dh of the wrong length",
			p256dh: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), auth: goodAuth,
			wantErr: true, errMatch: "p256dh",
		},
		{
			name:   "p256dh not an uncompressed point",
			p256dh: base64.RawURLEncoding.EncodeToString(append([]byte{0x02}, make([]byte, 64)...)), auth: goodAuth,
			wantErr: true, errMatch: "p256dh",
		},
		{
			name:   "auth of the wrong length",
			p256dh: goodP256DH, auth: base64.RawURLEncoding.EncodeToString(make([]byte, 8)),
			wantErr: true, errMatch: "auth",
		},
		{
			name: "p256dh not base64", p256dh: "!!!not base64!!!", auth: goodAuth,
			wantErr: true, errMatch: "p256dh",
		},
		{
			name: "auth not base64", p256dh: goodP256DH, auth: "!!!not base64!!!",
			wantErr: true, errMatch: "auth",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateWebPushKeys(c.p256dh, c.auth)
			if (err != nil) != c.wantErr {
				t.Fatalf("ValidateWebPushKeys() error = %v, wantErr %v", err, c.wantErr)
			}
			if c.errMatch != "" && !strings.Contains(err.Error(), c.errMatch) {
				t.Fatalf("error %q does not mention %q", err, c.errMatch)
			}
		})
	}
}

// webpush-go's own decodeSubscriptionKey accepts padded and standard-alphabet
// base64 as well as raw base64url. Validation must be at least as lenient, or
// it would reject key material the sender would happily have used.
func TestValidateWebPushKeysAcceptsEveryBase64AlphabetTheSenderDoes(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	point := priv.PublicKey().Bytes()
	authBytes := make([]byte, 16)
	if _, err := rand.Read(authBytes); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	encodings := map[string]*base64.Encoding{
		"RawURLEncoding": base64.RawURLEncoding,
		"URLEncoding":    base64.URLEncoding,
		"RawStdEncoding": base64.RawStdEncoding,
		"StdEncoding":    base64.StdEncoding,
	}
	for name, enc := range encodings {
		t.Run(name, func(t *testing.T) {
			if err := ValidateWebPushKeys(enc.EncodeToString(point), enc.EncodeToString(authBytes)); err != nil {
				t.Fatalf("ValidateWebPushKeys() with %s = %v, want nil", name, err)
			}
		})
	}
}
