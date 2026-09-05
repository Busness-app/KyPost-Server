package users

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/password"
)

func fastParams() password.Params { return password.Params{Memory: 8 * 1024, Time: 1, Threads: 1} }

func TestHashPasswordIsArgon2idAndVerifies(t *testing.T) {
	defer SetHashParamsForTest(fastParams())()
	ctx := context.Background()
	h, err := HashPassword(ctx, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("hash %q is not Argon2id PHC", h)
	}
	if ok, err := VerifySecretHash(ctx, h, "correct horse"); err != nil || !ok {
		t.Fatalf("verify: ok=%v err=%v", ok, err)
	}
	if ok, _ := VerifySecretHash(ctx, h, "wrong"); ok {
		t.Fatal("wrong password verified")
	}
	if NeedsRehash(h) {
		t.Fatal("fresh hash reports NeedsRehash")
	}
}

func TestLegacyScryptStillVerifiesAndWantsRehash(t *testing.T) {
	defer SetHashCostForTest(MinVerifiableScryptN)()
	ctx := context.Background()
	h, err := LegacyScryptHashForTest(ctx, "old password")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifySecretHash(ctx, h, "old password"); err != nil || !ok {
		t.Fatalf("legacy verify: ok=%v err=%v", ok, err)
	}
	if !NeedsRehash(h) {
		t.Fatal("scrypt hash must report NeedsRehash so login upgrades it")
	}
}

func TestMalformedHashIsFalseNotError(t *testing.T) {
	ctx := context.Background()
	for _, h := range []string{"", "$argon2id$garbage", "scrypt$1$2", "sha256:abc"} {
		ok, err := VerifySecretHash(ctx, h, "x")
		if ok || err != nil {
			t.Fatalf("%q: ok=%v err=%v, want false,nil", h, ok, err)
		}
	}
}

func TestBusyIsKDFBusy(t *testing.T) {
	// password.ErrBusy from the library must surface as ErrKDFBusy so callers
	// answer 503 and spend no lockout strike.
	if !errors.Is(mapBusy(password.ErrBusy), ErrKDFBusy) {
		t.Fatal("password.ErrBusy not mapped to ErrKDFBusy")
	}
	if mapBusy(nil) != nil {
		t.Fatal("nil error changed")
	}
}
