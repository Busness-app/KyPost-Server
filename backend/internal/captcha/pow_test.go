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

// answerFor is solve() without the encoding, for tests that need to build a
// solution whose only defect is the one they are testing.
func answerFor(t *testing.T, ch Challenge) int {
	t.Helper()
	for n := 0; n <= ch.MaxNumber; n++ {
		sum := sha256.Sum256([]byte(ch.Salt + strconv.Itoa(n)))
		if hex.EncodeToString(sum[:]) == ch.Challenge {
			return n
		}
	}
	t.Fatalf("challenge %+v has no solution in range", ch)
	return 0
}

func encodeSolution(t *testing.T, ch Challenge, number int) string {
	t.Helper()
	payload := map[string]any{
		"algorithm": ch.Algorithm,
		"salt":      ch.Salt,
		"challenge": ch.Challenge,
		"maxnumber": ch.MaxNumber,
		"expires":   ch.Expires,
		"clientip":  ch.ClientIP,
		"signature": ch.Signature,
		"number":    number,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal solution: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// testClientIP is the address every challenge below is issued to and, unless
// a test is specifically about the binding, submitted from. Challenges are
// bound to the requesting address, so "" no longer works as a don't-care.
const testClientIP = "203.0.113.7"

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
	ch, err := v.IssueAt(testClientIP, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	ok, err := v.Verify(context.Background(), solve(t, ch), testClientIP)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("a freshly solved challenge must verify")
	}
}

func TestPoWRejectsAReplayedSolution(t *testing.T) {
	v := newTestPoW(t)
	ch, err := v.IssueAt(testClientIP, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	token := solve(t, ch)
	if ok, _ := v.Verify(context.Background(), token, testClientIP); !ok {
		t.Fatal("first use must verify")
	}
	// Without this, one solved challenge buys unlimited login attempts and
	// the whole proof-of-work is decorative.
	if ok, _ := v.Verify(context.Background(), token, testClientIP); ok {
		t.Fatal("second use of the same salt must be refused")
	}
}

func TestPoWRejectsATamperedSignature(t *testing.T) {
	v := newTestPoW(t)
	ch, _ := v.IssueAt(testClientIP, 0)
	token := solve(t, ch)

	forged := ch
	forged.MaxNumber = 1 // an attacker lowering the difficulty they were set
	if ok, _ := v.Verify(context.Background(), encodeSolution(t, forged, 0), testClientIP); ok {
		t.Fatal("a challenge whose signed fields were edited must be refused")
	}
	// The untouched original must still be good, proving the rejection above
	// came from the tamper and not from something incidental.
	if ok, _ := v.Verify(context.Background(), token, testClientIP); !ok {
		t.Fatal("the untampered solution should still verify")
	}
}

func TestPoWRejectsAWrongNumber(t *testing.T) {
	v := newTestPoW(t)
	ch, _ := v.IssueAt(testClientIP, 0)
	// Find the real answer, then submit a different one under the same
	// (correctly signed) challenge.
	wrong := (answerFor(t, ch) + 1) % (ch.MaxNumber + 1)
	if ok, _ := v.Verify(context.Background(), encodeSolution(t, ch, wrong), testClientIP); ok {
		t.Fatal("a number that does not hash to the challenge must be refused")
	}
}

func TestPoWRejectsANumberOutOfRange(t *testing.T) {
	v := newTestPoW(t)
	ch, _ := v.IssueAt(testClientIP, 0)
	if ok, _ := v.Verify(context.Background(), encodeSolution(t, ch, -1), testClientIP); ok {
		t.Fatal("a negative number must be refused")
	}
	if ok, _ := v.Verify(context.Background(), encodeSolution(t, ch, ch.MaxNumber+1), testClientIP); ok {
		t.Fatal("a number above maxnumber must be refused")
	}
}

func TestPoWReportsExpiryDistinctly(t *testing.T) {
	v := newTestPoW(t)
	ch, _ := v.IssueAt(testClientIP, 0)
	token := solve(t, ch)

	// handleLogin refunds the lockout strike for an expired challenge and
	// spends it for a wrong one, so these two outcomes must be
	// distinguishable by the caller — not both a bare false.
	v.now = func() time.Time { return time.Now().Add(powChallengeTTL + time.Minute) }
	ok, err := v.Verify(context.Background(), token, testClientIP)
	if ok {
		t.Fatal("an expired challenge must not verify")
	}
	if err == nil || !errorIsChallengeExpired(err) {
		t.Fatalf("Verify() err = %v, want ErrChallengeExpired", err)
	}
}

func TestPoWRefusesASolutionFromAnotherAddress(t *testing.T) {
	// The bypass this closes: api's per-IP escalation raises the difficulty
	// for an address with recent failed logins, so without this check an
	// attacker fetched cheap base-difficulty challenges from a clean address
	// and submitted them from their escalated one, paying the base price
	// forever. Escalation then priced only the honest user who mistyped.
	v := newTestPoW(t)
	ch, _ := v.IssueAt(testClientIP, 0)

	ok, err := v.Verify(context.Background(), solve(t, ch), "198.51.100.99")
	if ok {
		t.Fatal("a solution issued to one address must not verify from another")
	}
	// Distinct from both a forgery (plain false) and an expiry: handleLogin
	// refunds the lockout strike for this, because a phone changing networks
	// mid-solve is not a wrong credential.
	if !errors.Is(err, ErrChallengeWrongClient) {
		t.Fatalf("Verify() err = %v, want ErrChallengeWrongClient", err)
	}
}

func TestPoWDoesNotSpendTheSaltOnAWrongAddress(t *testing.T) {
	// Why the address check must sit above consume: a user whose address
	// changed mid-solve retries from the address the challenge was issued to,
	// and must not then be told their challenge was already spent. One
	// network hiccup, one failure.
	v := newTestPoW(t)
	ch, _ := v.IssueAt(testClientIP, 0)
	token := solve(t, ch)

	if ok, _ := v.Verify(context.Background(), token, "198.51.100.99"); ok {
		t.Fatal("setup: the foreign submission must be refused")
	}
	if got := v.spentCount(); got != 0 {
		t.Fatalf("spentCount() after a refused foreign solution = %d, want 0", got)
	}
	ok, err := v.Verify(context.Background(), token, testClientIP)
	if err != nil {
		t.Fatalf("Verify from the issuing address: %v", err)
	}
	if !ok {
		t.Fatal("the same solution must still verify from the address it was issued to")
	}
}

func TestPoWRejectsATamperedClientIP(t *testing.T) {
	// The client must not be able to move a challenge to another address by
	// rewriting the field it is handed. It is inside the signed preimage, so
	// this fails as a forgery — a plain false, no strike refund.
	v := newTestPoW(t)
	ch, _ := v.IssueAt(testClientIP, 0)
	token := solve(t, ch)

	// The correct answer, so the signature is the *only* thing that can
	// reject this. Submitting a deliberately wrong number here would let the
	// test pass even with clientip left out of the signed preimage — the hash
	// check would do the rejecting and prove nothing.
	moved := ch
	moved.ClientIP = "198.51.100.99"
	ok, err := v.Verify(context.Background(), encodeSolution(t, moved, answerFor(t, ch)), moved.ClientIP)
	if ok {
		t.Fatal("a challenge whose clientip was edited must be refused")
	}
	if err != nil {
		t.Fatalf("a rewritten clientip is a forgery, not a distinct outcome: err = %v, want nil", err)
	}
	// The untouched original still verifies, proving the rejection above came
	// from the tamper and not from something incidental.
	if ok, _ := v.Verify(context.Background(), token, testClientIP); !ok {
		t.Fatal("the untampered solution should still verify")
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
		ok, err := v.Verify(context.Background(), token, testClientIP)
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
	ch, _ := v.IssueAt(testClientIP, 0)
	if ok, _ := v.Verify(context.Background(), solve(t, ch), testClientIP); !ok {
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
		ch, err := v.IssueAt(testClientIP, 0)
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

func TestNewVerifierBuildsPoWProvider(t *testing.T) {
	v, err := NewVerifier(Config{Provider: ProviderPoW, HMACKey: []byte("k"), MaxNumber: 100})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, isPoW := v.(*PoWVerifier); !isPoW {
		t.Fatalf("NewVerifier(pow) = %T, want *PoWVerifier", v)
	}
}

func TestNewVerifierPoWDoesNotWantASiteverifySecret(t *testing.T) {
	// The pow provider has no upstream to authenticate to, so SecretKey is
	// meaningless for it — requiring one would make operators invent a
	// value that is never used.
	if _, err := NewVerifier(Config{Provider: ProviderPoW, HMACKey: []byte("k")}); err != nil {
		t.Fatalf("pow must not require SecretKey: %v", err)
	}
}

func TestNewVerifierPoWRequiresAnHMACKey(t *testing.T) {
	if _, err := NewVerifier(Config{Provider: ProviderPoW}); err == nil {
		t.Fatal("pow with no HMAC key must fail closed")
	}
}
