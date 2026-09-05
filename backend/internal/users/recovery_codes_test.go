package users

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/mfa"
)

// testRecoveryDigest is the keyed digest the api server holds in production
// (mfa.NewRecoveryCodeDigester), over a key in the test's own temp dir.
func testRecoveryDigest(t *testing.T) func(string) string {
	t.Helper()
	d, err := mfa.NewRecoveryCodeDigester(filepath.Join(t.TempDir(), "totp-secret.key"))
	if err != nil {
		t.Fatalf("NewRecoveryCodeDigester: %v", err)
	}
	return d
}

func TestConsumeRecoveryCodeDigestAndLegacy(t *testing.T) {
	restore := SetHashCostForTest(MinVerifiableScryptN)
	defer restore()
	ctx := context.Background()
	digest := testRecoveryDigest(t)
	s := newTestStore(t)
	u, err := s.Create(ctx, "alice", "alice-testpassword", RoleUser)
	if err != nil {
		t.Fatal(err)
	}

	legacy, err := LegacyScryptHashForTest(ctx, "aaaa-bbbb-cccc")
	if err != nil {
		t.Fatal(err)
	}
	fresh := digest("dddd-eeee-ffff")
	if _, err := s.ReplaceRecoveryCodes(u.ID, []string{legacy, fresh}); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := s.ConsumeRecoveryCode(ctx, u.ID, "DDDD EEEE FFFF", digest); err != nil || !ok {
		t.Fatalf("digest code did not redeem: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := s.ConsumeRecoveryCode(ctx, u.ID, "dddd-eeee-ffff", digest); ok {
		t.Fatal("digest code redeemed twice")
	}
	if _, ok, err := s.ConsumeRecoveryCode(ctx, u.ID, "aaaa-bbbb-cccc", digest); err != nil || !ok {
		t.Fatalf("legacy scrypt code did not redeem: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := s.ConsumeRecoveryCode(ctx, u.ID, "zzzz-zzzz-zzzz", digest); ok {
		t.Fatal("unknown code redeemed")
	}
	got, _ := s.Get(u.ID)
	if len(got.RecoveryCodesHash) != 0 {
		t.Fatalf("%d hashes left, want 0", len(got.RecoveryCodesHash))
	}
}

// TestConsumeRecoveryCodeIsKeyed pins that the store's entries are only
// redeemable by the key that minted them: a digest carried to an install with a
// different SECRET_DIR — or recomputed by someone holding users.json alone —
// does not match.
func TestConsumeRecoveryCodeIsKeyed(t *testing.T) {
	ctx := context.Background()
	minted, other := testRecoveryDigest(t), testRecoveryDigest(t)
	s := newTestStore(t)
	u, err := s.Create(ctx, "bob", "bob-testpassword", RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceRecoveryCodes(u.ID, []string{minted("dddd-eeee-ffff")}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.ConsumeRecoveryCode(ctx, u.ID, "dddd-eeee-ffff", other); err != nil || ok {
		t.Fatalf("a code redeemed under the wrong key: ok=%v err=%v", ok, err)
	}
	if _, ok, err := s.ConsumeRecoveryCode(ctx, u.ID, "dddd-eeee-ffff", minted); err != nil || !ok {
		t.Fatalf("the code did not redeem under its own key: ok=%v err=%v", ok, err)
	}
}
