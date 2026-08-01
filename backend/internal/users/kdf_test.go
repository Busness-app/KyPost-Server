package users

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// withSaturatedKDF fills every derivation slot and returns a release func. The
// slots stay held until release is called, so anything that asks for one during
// the test must take the shed path.
func withSaturatedKDF(t *testing.T) (release func()) {
	t.Helper()
	for i := 0; i < MaxConcurrentKDF; i++ {
		kdfSlots <- struct{}{}
	}
	released := false
	release = func() {
		if released {
			return
		}
		released = true
		for i := 0; i < MaxConcurrentKDF; i++ {
			<-kdfSlots
		}
	}
	// Registered as cleanup as well as returned: a test that fails an assertion
	// before its own defer runs would otherwise leave the package-level
	// semaphore full and hang every test after it.
	t.Cleanup(release)
	return release
}

// withShortKDFQueueWait shrinks the queue tolerance so a saturation test does
// not have to wait out the production value.
func withShortKDFQueueWait(t *testing.T, d time.Duration) {
	t.Helper()
	previous := KDFMaxQueueWait
	KDFMaxQueueWait = d
	t.Cleanup(func() { KDFMaxQueueWait = previous })
}

// TestEveryDerivationEntryPointSharesTheOneLimit is the test whose absence let
// the ceiling rot.
//
// The limit used to be a semaphore in package api that each caller wrapped by
// hand, and its doc comment listed four callers as though that were all of
// them. It was not: MFA confirmation, the shared password-confirm re-auth,
// recovery-code generation, CardDAV app-password generation, the hash and PGP
// rewrap at the end of a password change, and administrative create/reset all
// reached scrypt.Key without passing through it. Every one of those bypasses
// type-checked, passed review and passed the suite, because nothing anywhere
// asserted that a derivation could not simply be started.
//
// So this does not test the semaphore. It tests the ENTRY POINTS: with every
// slot held, each way this package can be asked to derive a key must report
// ErrKDFBusy rather than proceeding. A new one that forgets the limit — which
// is now only possible by calling scrypt.Key directly — fails here.
func TestEveryDerivationEntryPointSharesTheOneLimit(t *testing.T) {
	// A real hash to verify against, derived before the slots are taken.
	hash, err := HashPassword(context.Background(), "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	legacyUser := User{ID: "u1", Username: "legacy", PasswordHash: hash}
	derivedUser := User{
		ID: "u2", Username: "derived", PasswordHash: hash,
		AuthDerivation: AuthDerivationPBKDF2, LoginSalt: "c2FsdA==", LoginIterations: MinLoginIterations,
	}

	dir := t.TempDir()
	store, err := LoadOrMigrate(context.Background(), dir, dir+"/admin.env")
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	bootstrap, err := store.FirstAdmin()
	if err != nil {
		t.Fatalf("FirstAdmin: %v", err)
	}
	if _, err := store.ReplaceRecoveryCodes(bootstrap.ID, []string{hash}); err != nil {
		t.Fatalf("ReplaceRecoveryCodes: %v", err)
	}

	withShortKDFQueueWait(t, 30*time.Millisecond)
	release := withSaturatedKDF(t)
	defer release()

	ctx := context.Background()
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"HashPassword", func() error {
			_, err := HashPassword(ctx, "anything")
			return err
		}},
		{"VerifyPassword", func() error {
			_, err := VerifyPassword(ctx, legacyUser, "anything")
			return err
		}},
		{"VerifyAuthSecret", func() error {
			_, err := VerifyAuthSecret(ctx, derivedUser, "anything")
			return err
		}},
		{"VerifySecretHash", func() error {
			_, err := VerifySecretHash(ctx, hash, "anything")
			return err
		}},
		// The tagged SHA-256 form takes no slot by design; a device paired
		// before that format existed still holds a scrypt hash, and that
		// branch must be admitted like any other derivation.
		{"VerifyDeviceSecret (legacy scrypt hash)", func() error {
			_, err := VerifyDeviceSecret(ctx, hash, "anything")
			return err
		}},
		{"Store.Create", func() error {
			_, err := store.Create(ctx, "brand-new-user", "a-sufficiently-long-password", RoleUser)
			return err
		}},
		{"Store.SetPassword", func() error {
			_, err := store.SetPassword(ctx, bootstrap.ID, "another-long-enough-password", false)
			return err
		}},
		{"Store.SetDerivedAuth", func() error {
			_, err := store.SetDerivedAuth(ctx, bootstrap.ID, strings.Repeat("ab", 32), "c2FsdA==", MinLoginIterations, false)
			return err
		}},
		{"Store.ConsumeRecoveryCode", func() error {
			_, _, err := store.ConsumeRecoveryCode(ctx, bootstrap.ID, "correct-horse-battery-staple")
			return err
		}},
		{"Store.RehashPassword", func() error {
			return store.RehashPassword(ctx, bootstrap.ID, "correct-horse-battery-staple")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, ErrKDFBusy) {
				t.Fatalf("derived a key with every slot held: got err %v, want ErrKDFBusy", err)
			}
		})
	}
}

// TestWithKDFSlotShedsRatherThanQueueingForever covers the shed path.
//
// An unbounded blocking send capped scrypt's memory but replaced it with an
// unbounded backlog: goroutines parked forever, each holding a parsed request,
// draining MaxConcurrentKDF derivations at a time. Neither ReadTimeout nor the
// client hanging up unblocks a channel send, so the work ran anyway, minutes
// later, for callers long gone.
func TestWithKDFSlotShedsRatherThanQueueingForever(t *testing.T) {
	withShortKDFQueueWait(t, 50*time.Millisecond)
	release := withSaturatedKDF(t)
	defer release()

	ran := false
	start := time.Now()
	err := withKDFSlot(context.Background(), func() { ran = true })
	elapsed := time.Since(start)

	if !errors.Is(err, ErrKDFBusy) {
		t.Fatalf("got err %v, want ErrKDFBusy", err)
	}
	if ran {
		t.Error("fn ran despite no slot being available; the shed must not perform the derivation")
	}
	if elapsed > time.Second {
		t.Errorf("waited %v before shedding; the bounded wait is not in effect", elapsed)
	}
}

// TestWithKDFSlotAbandonsOnCancelledContext: a client that has already
// disconnected must not be handed a slot ahead of one still waiting, and must
// not cost a derivation.
func TestWithKDFSlotAbandonsOnCancelledContext(t *testing.T) {
	withShortKDFQueueWait(t, 5*time.Second)
	release := withSaturatedKDF(t)
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- withKDFSlot(ctx, func() { t.Error("fn ran for a cancelled caller") }) }()

	// Give the goroutine time to park on the semaphore, then hang up.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got err %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("withKDFSlot did not return after its caller's context was cancelled")
	}
}

// TestWithKDFSlotAdmitsWhenCapacityFrees proves the shed is a bound and not a
// blanket refusal: once a slot frees, the next caller runs normally.
func TestWithKDFSlotAdmitsWhenCapacityFrees(t *testing.T) {
	withShortKDFQueueWait(t, 2*time.Second)
	release := withSaturatedKDF(t)

	var wg sync.WaitGroup
	wg.Add(1)
	ran := false
	var err error
	go func() {
		defer wg.Done()
		err = withKDFSlot(context.Background(), func() { ran = true })
	}()

	time.Sleep(20 * time.Millisecond)
	release()
	wg.Wait()

	if err != nil {
		t.Fatalf("unexpected error once capacity freed: %v", err)
	}
	if !ran {
		t.Error("fn did not run after a slot became available")
	}
}

// TestConcurrentDerivationsAreBounded drives real HashPassword calls rather
// than the semaphore directly, so it measures what actually reaches scrypt.
func TestConcurrentDerivationsAreBounded(t *testing.T) {
	withShortKDFQueueWait(t, 10*time.Second)

	var mu sync.Mutex
	inFlight, peak := 0, 0
	var wg sync.WaitGroup
	for i := 0; i < MaxConcurrentKDF*4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = withKDFSlot(context.Background(), func() {
				mu.Lock()
				inFlight++
				if inFlight > peak {
					peak = inFlight
				}
				mu.Unlock()
				time.Sleep(5 * time.Millisecond)
				mu.Lock()
				inFlight--
				mu.Unlock()
			})
		}()
	}
	wg.Wait()

	if peak > MaxConcurrentKDF {
		t.Fatalf("observed %d concurrent derivations, cap is %d", peak, MaxConcurrentKDF)
	}
}

// TestWithKDFSlotIsReentrant covers the property that lets a caller hold a slot
// across a region without deadlocking against its own derivations.
//
// package api's login path wraps the credential check so its stopwatch starts
// after the queue rather than before it. If the derivation inside then queued
// for a slot of its own, MaxConcurrentKDF concurrent logins would each hold one
// slot and wait for another — every slot held by something waiting for a slot,
// resolved only by the queue timeout shedding all of them.
func TestWithKDFSlotIsReentrant(t *testing.T) {
	withShortKDFQueueWait(t, 200*time.Millisecond)

	// One slot, so a second acquisition could not possibly succeed. Anything
	// that completes below did so by reusing the caller's.
	for i := 0; i < MaxConcurrentKDF-1; i++ {
		kdfSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < MaxConcurrentKDF-1; i++ {
			<-kdfSlots
		}
	})

	var derivations atomic.Int64
	err := WithKDFSlot(context.Background(), func(ctx context.Context) {
		// Two in a row, both inside the one slot.
		for i := 0; i < 2; i++ {
			if _, err := HashPassword(ctx, "nested"); err != nil {
				t.Errorf("nested derivation %d was refused a slot the caller already holds: %v", i, err)
				return
			}
			derivations.Add(1)
		}
	})
	if err != nil {
		t.Fatalf("WithKDFSlot: %v", err)
	}
	if got := derivations.Load(); got != 2 {
		t.Fatalf("completed %d nested derivations, want 2", got)
	}
}
