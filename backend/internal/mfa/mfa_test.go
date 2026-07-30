package mfa

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestChallengeCreateGetDelete(t *testing.T) {
	s := NewStore()
	ch, err := s.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ch.ID == "" || ch.UserID != "user-1" {
		t.Fatalf("unexpected challenge: %+v", ch)
	}
	got, ok := s.Get(ch.ID)
	if !ok || got.ID != ch.ID {
		t.Fatalf("Get after Create = (%+v, %v)", got, ok)
	}
	s.Delete(ch.ID)
	if _, ok := s.Get(ch.ID); ok {
		t.Fatalf("expected challenge gone after Delete")
	}
}

func TestDeleteByUserRemovesOnlyThatUsersChallenges(t *testing.T) {
	s := NewStore()
	a1, err := s.Create("user-a")
	if err != nil {
		t.Fatalf("Create a1: %v", err)
	}
	a2, err := s.Create("user-a")
	if err != nil {
		t.Fatalf("Create a2: %v", err)
	}
	b1, err := s.Create("user-b")
	if err != nil {
		t.Fatalf("Create b1: %v", err)
	}

	s.DeleteByUser("user-a")

	if _, ok := s.Get(a1.ID); ok {
		t.Fatal("expected user-a's first challenge to be gone")
	}
	if _, ok := s.Get(a2.ID); ok {
		t.Fatal("expected user-a's second challenge to be gone")
	}
	if _, ok := s.Get(b1.ID); !ok {
		t.Fatal("expected user-b's challenge to survive user-a's DeleteByUser")
	}
}

func TestChallengeExpiry(t *testing.T) {
	s := NewStore()
	ch, err := s.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Force the stored entry to be already expired.
	s.mu.Lock()
	entry := s.m[ch.ID]
	entry.ExpiresAt = time.Now().Add(-time.Second)
	s.m[ch.ID] = entry
	s.mu.Unlock()

	if _, ok := s.Get(ch.ID); ok {
		t.Fatalf("expected expired challenge to be rejected by Get")
	}
	if err := s.RecordTOTPAttempt(ch.ID); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("RecordTOTPAttempt on expired = %v, want ErrChallengeNotFound", err)
	}
}

func TestRecordTOTPAttemptLockout(t *testing.T) {
	s := NewStore()
	ch, err := s.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// MaxTOTPAttempts failures are tolerated; the next one locks out.
	for i := 0; i < MaxTOTPAttempts; i++ {
		if err := s.RecordTOTPAttempt(ch.ID); err != nil {
			t.Fatalf("attempt %d = %v, want nil", i+1, err)
		}
	}
	if err := s.RecordTOTPAttempt(ch.ID); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("attempt over cap = %v, want ErrTooManyAttempts", err)
	}
	// Lockout deletes the challenge.
	if _, ok := s.Get(ch.ID); ok {
		t.Fatalf("expected challenge deleted after lockout")
	}
}

func TestConsumeTOTPStep(t *testing.T) {
	s := NewStore()
	ch, err := s.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.ConsumeTOTPStep(ch.ID, 987654); err != nil {
		t.Fatalf("first ConsumeTOTPStep = %v, want nil", err)
	}
	got, ok := s.Get(ch.ID)
	if !ok || got.UsedTOTPStep != 987654 {
		t.Fatalf("UsedTOTPStep = %d (ok=%v), want 987654", got.UsedTOTPStep, ok)
	}

	// A second consume against the same challenge — whether with the same
	// step (replay) or a different one — must be rejected.
	if err := s.ConsumeTOTPStep(ch.ID, 987654); !errors.Is(err, ErrChallengeAlreadyUsed) {
		t.Fatalf("second ConsumeTOTPStep (same step) = %v, want ErrChallengeAlreadyUsed", err)
	}
	if err := s.ConsumeTOTPStep(ch.ID, 111111); !errors.Is(err, ErrChallengeAlreadyUsed) {
		t.Fatalf("second ConsumeTOTPStep (different step) = %v, want ErrChallengeAlreadyUsed", err)
	}

	if err := s.ConsumeTOTPStep("no-such-challenge", 1); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("ConsumeTOTPStep on unknown id = %v, want ErrChallengeNotFound", err)
	}
}

// TestConsumeTOTPStepConcurrentSingleUse is the regression test for the
// TOCTOU race this method exists to close: many goroutines racing to consume
// the same still-valid TOTP code against the same challenge must yield
// exactly one winner, with every other caller told the challenge was already
// used. Run with -race to also catch any reintroduced data race.
func TestConsumeTOTPStepConcurrentSingleUse(t *testing.T) {
	s := NewStore()
	ch, err := s.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successes, alreadyUsed, other int

	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := s.ConsumeTOTPStep(ch.ID, 555555)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrChallengeAlreadyUsed):
				alreadyUsed++
			default:
				other++
			}
		}()
	}
	close(start)
	wg.Wait()

	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1 (successes=%d alreadyUsed=%d other=%d)", successes, successes, alreadyUsed, other)
	}
	if alreadyUsed != goroutines-1 {
		t.Fatalf("alreadyUsed = %d, want %d (successes=%d alreadyUsed=%d other=%d)", alreadyUsed, goroutines-1, successes, alreadyUsed, other)
	}
	if other != 0 {
		t.Fatalf("unexpected other errors = %d", other)
	}
}

func TestPushChallengeLifecycle(t *testing.T) {
	st := NewStore()
	ch, err := st.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if status, ok := st.PushStatus(ch.ID); !ok || status != PushPending {
		t.Fatalf("initial status = %q ok=%v, want pending", status, ok)
	}

	status, err := st.ResolvePush(ch.ID, "dev-1", true)
	if err != nil || status != PushApproved {
		t.Fatalf("ResolvePush = %q err=%v, want approved", status, err)
	}

	// First response wins: a second resolve is rejected with the prior status.
	status2, err := st.ResolvePush(ch.ID, "dev-2", false)
	if !errors.Is(err, ErrChallengeAlreadyResolved) || status2 != PushApproved {
		t.Fatalf("second ResolvePush = %q err=%v, want approved+ErrChallengeAlreadyResolved", status2, err)
	}

	userID, err := st.ConsumePushApproval(ch.ID)
	if err != nil || userID != "user-1" {
		t.Fatalf("ConsumePushApproval = %q err=%v, want user-1", userID, err)
	}
	// Consumed => gone.
	if _, ok := st.PushStatus(ch.ID); ok {
		t.Fatalf("expected challenge deleted after consume")
	}
}

func TestPushConsumeRequiresApproval(t *testing.T) {
	st := NewStore()
	ch, _ := st.Create("user-2")
	if _, err := st.ResolvePush(ch.ID, "dev-1", false); err != nil {
		t.Fatalf("ResolvePush deny: %v", err)
	}
	if status, ok := st.PushStatus(ch.ID); !ok || status != PushDenied {
		t.Fatalf("status = %q ok=%v, want denied", status, ok)
	}
	if _, err := st.ConsumePushApproval(ch.ID); !errors.Is(err, ErrPushNotApproved) {
		t.Fatalf("ConsumePushApproval on denied = %v, want ErrPushNotApproved", err)
	}
}

func TestGenerateRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("len = %d, want 10", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate recovery code %q", c)
		}
		seen[c] = true
		parts := strings.Split(c, "-")
		if len(parts) != 3 {
			t.Fatalf("code %q not xxxx-xxxx-xxxx", c)
		}
		for _, p := range parts {
			if len(p) != 4 {
				t.Fatalf("code %q group wrong length", c)
			}
		}
	}
}

func TestSealOpenTOTPSecretRoundTrip(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "totp-secret.key")
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	enc, err := SealTOTPSecret(secret, keyPath)
	if err != nil {
		t.Fatalf("SealTOTPSecret: %v", err)
	}
	if enc == secret || !strings.Contains(enc, "ciphertext") {
		t.Fatalf("sealed value looks wrong: %q", enc)
	}
	got, err := OpenTOTPSecret(enc, keyPath)
	if err != nil {
		t.Fatalf("OpenTOTPSecret: %v", err)
	}
	if got != secret {
		t.Fatalf("round trip = %q, want %q", got, secret)
	}
}

// TestSupersedeUnansweredPushKeepsAnswersAndTheNewChallenge pins what
// superseding is allowed to throw away. Deleting an approved-but-unconsumed
// challenge would discard a decision the user already made and strand the
// browser that is about to call ConsumePushApproval; deleting a denied one would
// lose the "no" and let the next attempt re-ask as if nothing had happened.
func TestSupersedeUnansweredPushKeepsAnswersAndTheNewChallenge(t *testing.T) {
	s := NewStore()

	pending, err := s.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	approved, err := s.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	denied, err := s.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	other, err := s.Create("user-2")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	current, err := s.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := s.ResolvePush(approved.ID, "dev-a", true); err != nil {
		t.Fatalf("ResolvePush approve: %v", err)
	}
	if _, err := s.ResolvePush(denied.ID, "dev-b", false); err != nil {
		t.Fatalf("ResolvePush deny: %v", err)
	}

	if got := s.SupersedeUnansweredPush("user-1", current.ID); got != 1 {
		t.Fatalf("superseded = %d, want 1 (only the unanswered challenge)", got)
	}

	if _, ok := s.Get(pending.ID); ok {
		t.Fatal("the unanswered challenge must be gone")
	}
	for name, id := range map[string]string{
		"approved":       approved.ID,
		"denied":         denied.ID,
		"another user's": other.ID,
		"the new":        current.ID,
	} {
		if _, ok := s.Get(id); !ok {
			t.Fatalf("%s challenge must survive superseding", name)
		}
	}
}
