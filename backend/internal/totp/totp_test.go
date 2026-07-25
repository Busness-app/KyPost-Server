package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 Appendix B, SHA1, shared secret = ASCII "12345678901234567890".
// The RFC tabulates 8-digit TOTPs; this package emits 6 digits, i.e. the low
// 6 digits of the RFC value. At T=59s the RFC value is 94287082 -> 287082.
// VERIFY these two triples against RFC 6238 Appendix B before merge.
func TestValidateRFC6238Vectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString([]byte("12345678901234567890"))

	cases := []struct {
		unix int64
		code string
		step int64
	}{
		{59, "287082", 1},                // RFC 94287082
		{1111111109, "081804", 37037036}, // RFC 07081804
	}
	for _, c := range cases {
		step, ok := Validate(secret, c.code, time.Unix(c.unix, 0).UTC())
		if !ok {
			t.Fatalf("Validate(T=%d, %q) = false, want true", c.unix, c.code)
		}
		if step != c.step {
			t.Fatalf("Validate(T=%d) step = %d, want %d", c.unix, step, c.step)
		}
	}
}

func TestValidateRoundTripAndSkew(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	step := uint64(now.Unix() / 30)

	code, err := generateCode(secret, step)
	if err != nil {
		t.Fatalf("generateCode: %v", err)
	}
	got, ok := Validate(secret, code, now)
	if !ok || got != int64(step) {
		t.Fatalf("round trip: got (%d,%v), want (%d,true)", got, ok, step)
	}

	// Previous step still validates (clock skew tolerance).
	prev, err := generateCode(secret, step-1)
	if err != nil {
		t.Fatalf("generateCode prev: %v", err)
	}
	if _, ok := Validate(secret, prev, now); !ok {
		t.Fatalf("expected previous-step code to validate within skew window")
	}

	// Two steps away must NOT validate.
	far, err := generateCode(secret, step-2)
	if err != nil {
		t.Fatalf("generateCode far: %v", err)
	}
	if _, ok := Validate(secret, far, now); ok {
		t.Fatalf("expected code two steps away to be rejected")
	}
}

func TestGenerateSecretDistinctBase32(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	b, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if a == b {
		t.Fatalf("two generated secrets collided: %q", a)
	}
	if len(a) != 32 { // 20 bytes base32 no-pad = 32 chars
		t.Fatalf("secret length = %d, want 32", len(a))
	}
}

func TestProvisioningURI(t *testing.T) {
	uri := ProvisioningURI("KyPost", "alice", "GEZDGNBVGY3TQOJQ")
	if got := uri[:len("otpauth://totp/")]; got != "otpauth://totp/" {
		t.Fatalf("uri prefix = %q", got)
	}
	for _, want := range []string{"secret=GEZDGNBVGY3TQOJQ", "algorithm=SHA1", "digits=6", "period=30"} {
		if !containsSub(uri, want) {
			t.Fatalf("uri %q missing %q", uri, want)
		}
	}
}

func containsSub(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
