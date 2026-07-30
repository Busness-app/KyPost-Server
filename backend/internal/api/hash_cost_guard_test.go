package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kypost-server/backend/internal/users"
)

// TestNoTestInThisPackageCallsParallel enforces the invariant main_test.go's
// TestMain and withProductionHashCost both depend on.
//
// users.hashCostN is an unsynchronized package variable. TestMain lowers it once
// before anything runs, which is safe, and withProductionHashCost raises it back
// for individual tests, which is safe ONLY while tests run one at a time. A
// single t.Parallel() anywhere in this package makes that a data race — and one
// that -race will report against users.HashPassword, a file nobody would think
// to look in for the cause.
//
// This was a comment asking future authors not to do it. Comments do not fail
// builds.
func TestNoTestInThisPackageCallsParallel(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Parallel" {
				return true
			}
			// t.Parallel() / b.Parallel(). Any receiver is a problem here; the
			// point is that two tests in this package must never overlap.
			t.Errorf("%s:%d calls %s.Parallel().\n"+
				"internal/api lowers users.hashCostN in TestMain and raises it per-test in "+
				"withProductionHashCost, both writing an unsynchronized package variable. That "+
				"is safe only while tests run sequentially. If you need parallelism here, move "+
				"the cost override behind a mutex in internal/users first.",
				name, fset.Position(sel.Pos()).Line, exprString(sel.X))
			return true
		})
	}

	// A rename or a build-tag change that stops this from seeing the test files
	// would otherwise leave it passing forever while checking nothing.
	if scanned < 20 {
		t.Fatalf("scanned only %d _test.go files in this package; the guard is no longer looking at the suite", scanned)
	}
}

func exprString(e ast.Expr) string {
	if ident, ok := e.(*ast.Ident); ok {
		return ident.Name
	}
	return "?"
}

// TestSetHashCostForTestRefusesBelowVerifiableFloor pins the panic that stops a
// test cost from minting hashes verifyScryptHash will never accept.
func TestSetHashCostForTestRefusesBelowVerifiableFloor(t *testing.T) {
	for _, n := range []int{1 << 13, 1000, 0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("SetHashCostForTest(%d) did not panic; it would mint unverifiable hashes", n)
				}
			}()
			users.SetHashCostForTest(n)
		}()
	}
}

// TestProductionHashCostHelperRestoresTheTestCost proves withProductionHashCost
// cleans up after itself without the caller writing a defer. The old signature
// returned a restore func, and a caller that forgot to invoke it leaked the
// 128 MiB cost into every subsequent test in the package with nothing failing.
func TestProductionHashCostHelperRestoresTheTestCost(t *testing.T) {
	lowered := users.HashCostN()
	if lowered != users.MinVerifiableScryptN {
		t.Fatalf("TestMain should have lowered the cost to %d, got %d", users.MinVerifiableScryptN, lowered)
	}

	t.Run("raised inside", func(t *testing.T) {
		withProductionHashCost(t)
		if got := users.HashCostN(); got != users.ProductionScryptN {
			t.Fatalf("inside the helper's scope: got cost %d, want %d", got, users.ProductionScryptN)
		}
	})

	if got := users.HashCostN(); got != lowered {
		t.Fatalf("after the subtest returned: got cost %d, want the lowered %d — the helper leaked", got, lowered)
	}
}

// TestMainTestAppliesTheLoweredCost guards the other direction: that TestMain is
// actually in effect. Without it the suite still passes, just twenty times
// slower, which is the failure mode that gets a suite abandoned rather than
// fixed.
func TestMainTestAppliesTheLoweredCost(t *testing.T) {
	if users.HashCostN() >= users.ProductionScryptN {
		t.Fatalf("hash cost is %d: TestMain's override is not in effect and this suite will take minutes",
			users.HashCostN())
	}
	if _, err := os.Stat(filepath.Join(".", "main_test.go")); err != nil {
		t.Fatalf("main_test.go is missing; the cost override lives there: %v", err)
	}
}
