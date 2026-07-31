package api

import (
	"os"
	"testing"
	"time"

	"kypost-server/backend/internal/users"
)

// This package's tests are dominated by scrypt. At the production cost
// (N=1<<17, 128 MiB and ~200 ms a derivation) they took over four minutes, and
// again in CI under -race. Nothing here asserts how expensive a hash is, only
// what the handlers do with one.
//
// The cost is lowered here, in TestMain, and nowhere else. hashCostN is a plain
// package variable in internal/users, so writing it once before any test starts
// is safe and writing it from inside a test is a data race.
//
// Production strength is pinned elsewhere: users' TestHashPasswordUsesCurrentCost
// asserts the scryptN constant and the written hash prefix directly, in a package
// that does not apply this override.
// Lowering that cost is also what makes the instance-wide login budget
// meaningless here, so the two overrides belong together. The budget meters
// SECONDS OF DERIVATION, and a second measured in this binary is a cheap hash
// times whatever -race costs on this machine — a ratio that varies by machine
// and turned "fifteen sign-ins" into three on a CI runner. The stopwatch is
// stubbed to bill one loginKDFReserveSeconds flat, which restores the burst to
// exactly loginRateBurst sign-ins everywhere. See loginKDFBilledSeconds; the
// bucket itself stays entirely real, so a test that drains it still gets a 429.
func TestMain(m *testing.M) {
	restore := users.SetHashCostForTest(users.MinVerifiableScryptN)
	loginKDFBilledSeconds = func(time.Duration) float64 { return loginKDFReserveSeconds }
	code := m.Run()
	restore()
	os.Exit(code)
}

// withProductionHashCost restores the real scrypt cost for one test. Use it for
// the tests whose subject is the cost itself.
//
// It is NOT how a budget-sensitive test buys headroom any more. That was the old
// reason to reach for it — the budget billed measured time, so a cheap hash
// admitted far more attempts than the burst nominally held — and it never
// actually worked, because -race pushed the measurement the other way by a
// machine-dependent factor. The stopwatch is stubbed instead, in TestMain.
//
// Registers its own t.Cleanup rather than returning a restore func: a caller who
// forgot to invoke the restore would leak the production cost into every test
// that ran afterwards, with nothing failing to say so.
//
// users.ProductionScryptN rather than a literal 1<<17, so raising the real cost
// cannot leave this helper restoring the old one.
//
// Safe only because no test in this package calls t.Parallel(), so nothing else
// reads hashCostN while this writes it. TestNoTestInThisPackageCallsParallel
// enforces that.
func withProductionHashCost(t *testing.T) {
	t.Helper()
	t.Cleanup(users.SetHashCostForTest(users.ProductionScryptN))
}

// TestProductionBillsTheMeasuredTime pins the cost oracle this binary does NOT
// run. TestMain replaces loginKDFBilledSeconds with a flat charge, so nothing
// else in the package exercises the shipped one — and a budget that bills a
// constant in production is not a budget at all: it degrades to counting
// requests, which is the exact failure loginKDFReserve's comment exists to
// prevent. Asserting billMeasuredTime directly is what keeps the substitution
// confined to the stopwatch.
func TestProductionBillsTheMeasuredTime(t *testing.T) {
	if got := billMeasuredTime(250 * time.Millisecond); got != 0.25 {
		t.Errorf("billMeasuredTime(250ms) = %v, want 0.25: production must bill what the "+
			"derivation actually cost, not a fixed figure", got)
	}
	if got := billMeasuredTime(2 * time.Second); got != 2.0 {
		t.Errorf("billMeasuredTime(2s) = %v, want 2.0: a derivation that costs ten times the "+
			"reserve must drain ten times the budget, or a slow machine admits the same "+
			"number of attempts while burning ten times the CPU", got)
	}
}

// TestTestBinaryBillsExactlyOneReserve pins the other half: the stub's value is
// not arbitrary. At exactly loginKDFReserveSeconds the burst holds exactly
// loginRateBurst sign-ins, which is the arithmetic every login-heavy test in
// this package now relies on. A stub of, say, half the reserve would silently
// double every test's headroom.
func TestTestBinaryBillsExactlyOneReserve(t *testing.T) {
	if got := loginKDFBilledSeconds(37 * time.Millisecond); got != loginKDFReserveSeconds {
		t.Fatalf("the test binary billed %v for a derivation, want a flat %v; "+
			"TestMain's stub is missing or wrong and every budget-sensitive test in this "+
			"package is back to depending on how fast this machine runs scrypt",
			got, loginKDFReserveSeconds)
	}
}
