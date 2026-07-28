package captcha

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"
)

// solve brute-forces ch the way the browser does, and encodes the solution
// exactly as frontend/src/lib/pow.ts does: base64(JSON of the challenge plus
// "number"). Keeping this in test code (rather than shipping a Go solver)
// keeps the server free of the work it is charging the client for.
func solve(t *testing.T, ch Challenge) string {
	t.Helper()
	for n := 0; n <= ch.MaxNumber; n++ {
		sum := sha256.Sum256([]byte(ch.Salt + strconv.Itoa(n)))
		if hex.EncodeToString(sum[:]) == ch.Challenge {
			return encodeSolution(t, ch, n)
		}
	}
	t.Fatalf("challenge %+v has no solution in range", ch)
	return ""
}

func encodeSolution(t *testing.T, ch Challenge, number int) string {
	t.Helper()
	payload := map[string]any{
		"algorithm": ch.Algorithm,
		"salt":      ch.Salt,
		"challenge": ch.Challenge,
		"maxnumber": ch.MaxNumber,
		"expires":   ch.Expires,
		"signature": ch.Signature,
		"number":    number,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal solution: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// newTestPoW uses a deliberately tiny maxNumber so the brute-force in solve()
// is instant; the verification logic is identical at any difficulty.
func newTestPoW(t *testing.T) *PoWVerifier {
	t.Helper()
	v, err := NewPoWVerifier([]byte("test-hmac-key-32-bytes-long-xxxx"), 200)
	if err != nil {
		t.Fatalf("NewPoWVerifier: %v", err)
	}
	return v
}

func TestPoWAcceptsAValidSolution(t *testing.T) {
	v := newTestPoW(t)
	ch, err := v.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	ok, err := v.Verify(context.Background(), solve(t, ch), "1.2.3.4")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("a freshly solved challenge must verify")
	}
}

func TestPoWRejectsAReplayedSolution(t *testing.T) {
	v := newTestPoW(t)
	ch, err := v.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	token := solve(t, ch)
	if ok, _ := v.Verify(context.Background(), token, ""); !ok {
		t.Fatal("first use must verify")
	}
	// Without this, one solved challenge buys unlimited login attempts and
	// the whole proof-of-work is decorative.
	if ok, _ := v.Verify(context.Background(), token, ""); ok {
		t.Fatal("second use of the same salt must be refused")
	}
}

func TestPoWRejectsATamperedSignature(t *testing.T) {
	v := newTestPoW(t)
	ch, _ := v.Issue()
	token := solve(t, ch)

	forged := ch
	forged.MaxNumber = 1 // an attacker lowering the difficulty they were set
	if ok, _ := v.Verify(context.Background(), encodeSolution(t, forged, 0), ""); ok {
		t.Fatal("a challenge whose signed fields were edited must be refused")
	}
	// The untouched original must still be good, proving the rejection above
	// came from the tamper and not from something incidental.
	if ok, _ := v.Verify(context.Background(), token, ""); !ok {
		t.Fatal("the untampered solution should still verify")
	}
}

func TestPoWRejectsAWrongNumber(t *testing.T) {
	v := newTestPoW(t)
	ch, _ := v.Issue()
	// Find the real answer, then submit a different one under the same
	// (correctly signed) challenge.
	var answer int
	for n := 0; n <= ch.MaxNumber; n++ {
		sum := sha256.Sum256([]byte(ch.Salt + strconv.Itoa(n)))
		if hex.EncodeToString(sum[:]) == ch.Challenge {
			answer = n
			break
		}
	}
	wrong := (answer + 1) % (ch.MaxNumber + 1)
	if ok, _ := v.Verify(context.Background(), encodeSolution(t, ch, wrong), ""); ok {
		t.Fatal("a number that does not hash to the challenge must be refused")
	}
}

func TestPoWRejectsANumberOutOfRange(t *testing.T) {
	v := newTestPoW(t)
	ch, _ := v.Issue()
	if ok, _ := v.Verify(context.Background(), encodeSolution(t, ch, -1), ""); ok {
		t.Fatal("a negative number must be refused")
	}
	if ok, _ := v.Verify(context.Background(), encodeSolution(t, ch, ch.MaxNumber+1), ""); ok {
		t.Fatal("a number above maxnumber must be refused")
	}
}

func TestPoWReportsExpiryDistinctly(t *testing.T) {
	v := newTestPoW(t)
	ch, _ := v.Issue()
	token := solve(t, ch)

	// handleLogin refunds the lockout strike for an expired challenge and
	// spends it for a wrong one, so these two outcomes must be
	// distinguishable by the caller — not both a bare false.
	v.now = func() time.Time { return time.Now().Add(powChallengeTTL + time.Minute) }
	ok, err := v.Verify(context.Background(), token, "")
	if ok {
		t.Fatal("an expired challenge must not verify")
	}
	if err == nil || !errorIsChallengeExpired(err) {
		t.Fatalf("Verify() err = %v, want ErrChallengeExpired", err)
	}
}

func TestPoWRejectsMalformedTokens(t *testing.T) {
	v := newTestPoW(t)
	for name, token := range map[string]string{
		"empty":          "",
		"not base64":     "!!!!not base64!!!!",
		"not json":       base64.StdEncoding.EncodeToString([]byte("hello")),
		"wrong algo":     base64.StdEncoding.EncodeToString([]byte(`{"algorithm":"MD5","salt":"a","challenge":"b","maxnumber":1,"expires":9999999999,"signature":"c","number":0}`)),
		"empty json obj": base64.StdEncoding.EncodeToString([]byte(`{}`)),
	} {
		ok, err := v.Verify(context.Background(), token, "")
		if ok {
			t.Errorf("%s: must not verify", name)
		}
		// Malformed input is a failed attempt, not a server fault: it must
		// not surface as an error, or handleLogin answers 503 and refunds
		// the strike for what is really a bad solution.
		if err != nil {
			t.Errorf("%s: Verify() err = %v, want nil", name, err)
		}
	}
}

func TestPoWSweepExpiredDropsSpentSalts(t *testing.T) {
	v := newTestPoW(t)
	ch, _ := v.Issue()
	if ok, _ := v.Verify(context.Background(), solve(t, ch), ""); !ok {
		t.Fatal("setup: solution should verify")
	}
	if got := v.spentCount(); got != 1 {
		t.Fatalf("spentCount() = %d, want 1", got)
	}
	v.SweepExpired(time.Now().Add(powChallengeTTL + time.Minute))
	if got := v.spentCount(); got != 0 {
		t.Fatalf("spentCount() after sweep = %d, want 0", got)
	}
}

func TestNewPoWVerifierRequiresAKey(t *testing.T) {
	if _, err := NewPoWVerifier(nil, 100); err == nil {
		t.Fatal("an empty HMAC key must be refused: it would make every signature forgeable")
	}
}

func TestPoWIssuesDistinctSalts(t *testing.T) {
	v := newTestPoW(t)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		ch, err := v.Issue()
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if seen[ch.Salt] {
			t.Fatalf("salt %q issued twice; the spent-salt cache would reject legitimate logins", ch.Salt)
		}
		seen[ch.Salt] = true
	}
}

func errorIsChallengeExpired(err error) bool {
	return errors.Is(err, ErrChallengeExpired)
}
