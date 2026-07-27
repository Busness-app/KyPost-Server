package mfa

import (
	"errors"
	"testing"
)

// run-4 M14: the push-MFA challenge carried nothing but its own id, so the
// human approving "the single highest-value action in this app" (the Android
// client's own words) was told nothing about what they were approving. The
// shipped client parses ipAddress, approxLocation, userAgent, issuedAt,
// matchDigits and decoyDigits, and its MfaNumberMatch.optionsFor returns null
// when matchDigits is not exactly two digits — which, per its comment,
// "silently drops the screen back to a bare Approve button. Number matching is
// the whole anti-fatigue control."
//
// The approval was always cryptographically sound (device credentials, user
// binding, a live PushMFAEnabled re-check). What was missing is that the
// decision was made blind, which is exactly the gap an MFA-fatigue attack walks
// through: the attacker triggers the login, the victim's phone buzzes, and
// nothing on the screen distinguishes it from their own sign-in.
//
// Number matching closes that by making approval require reading something off
// the browser that started the login. The server generates the digits and,
// critically, VERIFIES them — a client-side-only comparison would be theatre.

func TestCreateGeneratesTwoMatchDigits(t *testing.T) {
	store := NewStore()

	ch, err := store.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(ch.MatchDigits) != 2 {
		t.Fatalf("MatchDigits = %q, want exactly 2 characters", ch.MatchDigits)
	}
	for _, r := range ch.MatchDigits {
		if r < '0' || r > '9' {
			t.Fatalf("MatchDigits = %q, want digits only", ch.MatchDigits)
		}
	}
}

// Predictable digits would let an attacker who triggers the login tell the
// victim which number to tap — over the phone, in a chat, in the phishing page
// itself. Not proof of a CSPRNG, but it catches a constant or a counter.
func TestCreateVariesMatchDigits(t *testing.T) {
	store := NewStore()
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		ch, err := store.Create("user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		seen[ch.MatchDigits] = true
	}
	if len(seen) < 10 {
		t.Fatalf("only %d distinct match values in 200 challenges; digits look predictable", len(seen))
	}
}

func TestResolvePushWithMatchAcceptsTheCorrectDigits(t *testing.T) {
	store := NewStore()
	ch, err := store.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	status, err := store.ResolvePushWithMatch(ch.ID, "device-1", true, ch.MatchDigits)
	if err != nil {
		t.Fatalf("ResolvePushWithMatch: %v", err)
	}
	if status != "approved" {
		t.Fatalf("status = %q, want approved", status)
	}
}

// The whole point: approving with the wrong number must fail, server-side.
func TestResolvePushWithMatchRejectsWrongDigits(t *testing.T) {
	store := NewStore()
	ch, err := store.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	wrong := "00"
	if ch.MatchDigits == wrong {
		wrong = "11"
	}

	if _, err := store.ResolvePushWithMatch(ch.ID, "device-1", true, wrong); !errors.Is(err, ErrMatchDigitsMismatch) {
		t.Fatalf("err = %v, want ErrMatchDigitsMismatch", err)
	}

	// And the challenge must still be pending, not burned — the legitimate user
	// tapping the wrong tile should be able to try again within the window.
	got, ok := store.Get(ch.ID)
	if !ok {
		t.Fatal("challenge disappeared after a wrong-digit approval")
	}
	if got.PushStatus == "approved" {
		t.Fatal("a wrong-digit approval was recorded as approved")
	}
}

// A DENY needs no number. The safe answer must always be available: someone
// who is being MFA-fatigued should be able to shut it down without first
// solving a puzzle they have no way to solve.
func TestResolvePushWithMatchAllowsDenyWithoutDigits(t *testing.T) {
	store := NewStore()
	ch, err := store.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	status, err := store.ResolvePushWithMatch(ch.ID, "device-1", false, "")
	if err != nil {
		t.Fatalf("ResolvePushWithMatch(deny): %v", err)
	}
	if status != "denied" {
		t.Fatalf("status = %q, want denied", status)
	}
}

// An older client that does not send digits must not be able to approve by
// omitting them — that would make the control opt-out for anyone who can reach
// the endpoint.
func TestResolvePushWithMatchRejectsMissingDigitsOnApprove(t *testing.T) {
	store := NewStore()
	ch, err := store.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := store.ResolvePushWithMatch(ch.ID, "device-1", true, ""); !errors.Is(err, ErrMatchDigitsMismatch) {
		t.Fatalf("err = %v, want ErrMatchDigitsMismatch", err)
	}
}

// Repeated wrong guesses must not turn into an oracle for a two-digit space.
func TestResolvePushWithMatchLocksOutAfterRepeatedWrongDigits(t *testing.T) {
	store := NewStore()
	ch, err := store.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	wrong := "00"
	if ch.MatchDigits == wrong {
		wrong = "11"
	}

	// Every wrong attempt but the last reports a plain mismatch, so a
	// legitimate mis-tap can be retried.
	for i := 0; i < maxMatchAttempts-1; i++ {
		if _, err := store.ResolvePushWithMatch(ch.ID, "device-1", true, wrong); !errors.Is(err, ErrMatchDigitsMismatch) {
			t.Fatalf("attempt %d: err = %v, want ErrMatchDigitsMismatch", i, err)
		}
	}
	// The one that spends the budget says so, rather than inviting another try.
	if _, err := store.ResolvePushWithMatch(ch.ID, "device-1", true, wrong); !errors.Is(err, ErrMatchAttemptsExhausted) {
		t.Fatalf("final attempt: err = %v, want ErrMatchAttemptsExhausted", err)
	}

	// Even the CORRECT answer is refused now: the challenge is spent.
	if _, err := store.ResolvePushWithMatch(ch.ID, "device-1", true, ch.MatchDigits); !errors.Is(err, ErrMatchAttemptsExhausted) {
		t.Fatalf("err = %v, want the challenge to stay spent", err)
	}
}

func TestDecoyDigitsAreDistinctAndIncludeNoMatch(t *testing.T) {
	store := NewStore()
	ch, err := store.Create("user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	decoys := ch.DecoyDigits
	if len(decoys) < 2 {
		t.Fatalf("decoys = %v, want at least 2 so the tap is a real choice", decoys)
	}
	seen := map[string]bool{}
	for _, d := range decoys {
		if d == ch.MatchDigits {
			t.Fatalf("a decoy equals the match value: %v vs %q", decoys, ch.MatchDigits)
		}
		if len(d) != 2 {
			t.Fatalf("decoy %q is not two digits", d)
		}
		if seen[d] {
			t.Fatalf("duplicate decoy %q in %v", d, decoys)
		}
		seen[d] = true
	}
}
