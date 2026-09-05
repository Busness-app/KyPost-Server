package users

import (
	"context"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/mfa"
)

func TestConsumeRecoveryCodeDigestAndLegacy(t *testing.T) {
	restore := SetHashCostForTest(MinVerifiableScryptN)
	defer restore()
	ctx := context.Background()
	s := newTestStore(t)
	u, err := s.Create(ctx, "alice", "alice-testpassword", RoleUser)
	if err != nil {
		t.Fatal(err)
	}

	legacy, err := LegacyScryptHashForTest(ctx, "aaaa-bbbb-cccc")
	if err != nil {
		t.Fatal(err)
	}
	fresh := mfa.RecoveryCodeDigest("dddd-eeee-ffff")
	if _, err := s.ReplaceRecoveryCodes(u.ID, []string{legacy, fresh}); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := s.ConsumeRecoveryCode(ctx, u.ID, "DDDD EEEE FFFF"); err != nil || !ok {
		t.Fatalf("digest code did not redeem: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := s.ConsumeRecoveryCode(ctx, u.ID, "dddd-eeee-ffff"); ok {
		t.Fatal("digest code redeemed twice")
	}
	if _, ok, err := s.ConsumeRecoveryCode(ctx, u.ID, "aaaa-bbbb-cccc"); err != nil || !ok {
		t.Fatalf("legacy scrypt code did not redeem: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := s.ConsumeRecoveryCode(ctx, u.ID, "zzzz-zzzz-zzzz"); ok {
		t.Fatal("unknown code redeemed")
	}
	got, _ := s.Get(u.ID)
	if len(got.RecoveryCodesHash) != 0 {
		t.Fatalf("%d hashes left, want 0", len(got.RecoveryCodesHash))
	}
}
