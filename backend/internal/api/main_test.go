package api

import (
	"os"
	"testing"

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
func TestMain(m *testing.M) {
	restore := users.SetHashCostForTest(users.MinVerifiableScryptN)
	code := m.Run()
	restore()
	os.Exit(code)
}

// withProductionHashCost restores the real scrypt cost for one test. Use it for
// the tests whose subject is the cost — the instance-wide login budget is
// denominated in seconds of derivation work, so under a cheap hash it admits far
// more attempts and a test that counts requests measures nothing.
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
