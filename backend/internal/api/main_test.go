package api

import (
	"os"
	"testing"

	"kypost-server/backend/internal/users"
)

// This package's tests are dominated by scrypt. At the production cost
// (N=1<<17, 128 MiB and ~200 ms a derivation) they took over four minutes, and
// CI pays it again under -race. A suite that slow stops being run locally,
// which costs more than the fidelity it buys: nothing here asserts how
// expensive a hash is, only what the handlers do with one.
//
// The cost is lowered here, in TestMain, and nowhere else. hashCostN is a plain
// package variable in internal/users, so writing it once before any test starts
// is safe and writing it from inside a test is a data race.
//
// Production strength is pinned where it belongs — users'
// TestHashPasswordUsesCurrentCost asserts the scryptN constant and the written
// hash prefix directly, in a package that does not apply this override.
func TestMain(m *testing.M) {
	restore := users.SetHashCostForTest(users.MinVerifiableScryptN)
	code := m.Run()
	restore()
	os.Exit(code)
}

// withProductionHashCost restores the real scrypt cost for one test. Use it for
// the few tests whose subject IS the cost — the instance-wide login budget is
// denominated in seconds of derivation work, so under a cheap hash it correctly
// admits far more attempts and a test that counts requests measures nothing.
//
// Registers its own t.Cleanup rather than returning a restore func. The old
// signature depended on every caller writing `defer withProductionHashCost(t)()`
// and one that forgot would leak the production cost into every test that ran
// afterwards — silently restoring the four-minute suite with nothing failing to
// say so.
//
// users.ProductionScryptN rather than a literal 1<<17, so raising the real cost
// cannot leave this helper quietly restoring the old one.
//
// Safe only because no test in this package calls t.Parallel(), so tests run one
// at a time and nothing else is reading hashCostN while this writes it. That is
// not left to trust: TestNoTestInThisPackageCallsParallel enforces it.
func withProductionHashCost(t *testing.T) {
	t.Helper()
	t.Cleanup(users.SetHashCostForTest(users.ProductionScryptN))
}
