package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// lockRank is the declared acquisition order of Server's mutexes. A lock may
// only be taken while holding locks of STRICTLY LOWER rank.
//
// The order itself is the one Server's doc comment has always stated. What did
// not exist was anything that checked it: the comment said "Nothing currently
// takes more than one, which is the only reason there is no deadlock to find
// today", which is an admission that the invariant was held by nobody. The
// failure it describes — one handler reading s.cfg inside a userMu critical
// section while another does the reverse — is an ABBA deadlock that appears only
// under concurrent load, in production, and no unit test would provoke it.
//
// Adding a mutex to Server means adding it here. A lock absent from this map is
// invisible to the check.
var lockRank = map[string]int{
	"cfgMu":    1,
	"sessMu":   2,
	"userMu":   3,
	"ollamaMu": 4,
	"serverMu": 5,
}

// TestLockOrderIsRespected enforces lockRank across the package, including
// across function calls.
//
// It is a static check rather than a runtime one because the bug is a schedule
// that has to be hit, not a state that can be asserted: a runtime detector would
// need per-goroutine lock tracking and would still only fire on the interleaving
// that already deadlocked. The nesting, on the other hand, is right there in the
// source.
//
// Two things are checked:
//
//  1. Direct nesting — a function that takes B while holding A, where A outranks
//     B.
//  2. Nesting through a call — a function that holds A and calls something which
//     (transitively, within this package) takes B. This is the realistic shape:
//     nobody writes two Lock() calls next to each other, they call a helper that
//     happens to lock.
//
// Deliberate conservatism: a lock is treated as held from its Lock() to its
// matching Unlock() in the same function, or to the end of the function when
// there is none — which is what `defer mu.Unlock()`, the dominant pattern here,
// actually means. Over-approximating "held" produces false positives, not false
// negatives, and a false positive is a comment away from being resolved.
func TestLockOrderIsRespected(t *testing.T) {
	files := parsePackage(t)

	// Direct acquisitions per function, then propagated through the call graph.
	direct := map[string]map[string]bool{}
	calls := map[string]map[string]bool{}
	for _, file := range files {
		for _, fn := range funcDecls(file.ast) {
			name := funcKey(fn)
			direct[name] = locksAcquiredDirectly(fn)
			calls[name] = callsMade(fn)
		}
	}
	transitive := propagateLocks(direct, calls)

	checked := 0
	for _, file := range files {
		fset := file.fset
		for _, fn := range funcDecls(file.ast) {
			events := lockEvents(fn)
			if len(events) == 0 && len(callsMade(fn)) == 0 {
				continue
			}
			checked++
			var held []string // innermost last

			for _, ev := range events {
				switch ev.kind {
				case eventUnlock:
					for i := len(held) - 1; i >= 0; i-- {
						if held[i] == ev.lock {
							held = append(held[:i], held[i+1:]...)
							break
						}
					}
				case eventLock:
					if bad := violates(held, ev.lock); bad != "" {
						t.Errorf("%s: takes %s while holding %s.\n"+
							"LOCK ORDER is %s. Taking them in the other order somewhere else is an "+
							"ABBA deadlock that only appears under concurrent load.",
							fset.Position(ev.pos), ev.lock, bad, declaredOrder())
					}
					held = append(held, ev.lock)
				case eventCall:
					if len(held) == 0 {
						continue
					}
					for lock := range transitive[ev.callee] {
						if bad := violates(held, lock); bad != "" {
							t.Errorf("%s: calls %s while holding %s, and %s (transitively) takes %s.\n"+
								"LOCK ORDER is %s. Either move the call out of the critical section, "+
								"or take the locks in rank order.",
								fset.Position(ev.pos), ev.callee, bad, ev.callee, lock, declaredOrder())
						}
					}
				}
			}
		}
	}

	// Guards against the check silently passing because it stopped finding
	// anything — a rename of the mutex fields, or the package being split up.
	if checked < 50 {
		t.Fatalf("only %d functions inspected; this test is no longer reading the package", checked)
	}
	for name := range lockRank {
		if !anyFunctionTakes(direct, name) {
			t.Errorf("no function in this package takes %s; it was renamed or removed, and "+
				"lockRank is now describing something that does not exist", name)
		}
	}
}

func violates(held []string, taking string) string {
	rank, known := lockRank[taking]
	if !known {
		return ""
	}
	for _, h := range held {
		if h == taking {
			continue // re-entrance is a different bug; sync catches it by hanging
		}
		if lockRank[h] >= rank {
			return h
		}
	}
	return ""
}

func declaredOrder() string {
	names := make([]string, 0, len(lockRank))
	for n := range lockRank {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return lockRank[names[i]] < lockRank[names[j]] })
	return strings.Join(names, " before ")
}

func anyFunctionTakes(direct map[string]map[string]bool, lock string) bool {
	for _, locks := range direct {
		if locks[lock] {
			return true
		}
	}
	return false
}

const (
	eventLock = iota
	eventUnlock
	eventCall
)

type lockEvent struct {
	kind   int
	lock   string // for eventLock/eventUnlock
	callee string // for eventCall
	pos    token.Pos
}

// lockEvents returns fn's lock/unlock/call events in source order.
//
// A DEFERRED Unlock is not an unlock event. `defer mu.Unlock()` is written
// immediately after the Lock, so at its source position it would release a lock
// that is in fact held for the rest of the function — which silently defeats the
// whole check, since every critical section in this package is written that way.
// Dropping the event leaves the lock held to the end of the function, which is
// what defer means.
func lockEvents(fn *ast.FuncDecl) []lockEvent {
	deferred := deferredCalls(fn)

	var out []lockEvent
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if lock, method, ok := mutexCall(call); ok {
			if strings.HasSuffix(method, "Unlock") {
				if deferred[call.Pos()] {
					return true
				}
				out = append(out, lockEvent{kind: eventUnlock, lock: lock, pos: call.Pos()})
				return true
			}
			out = append(out, lockEvent{kind: eventLock, lock: lock, pos: call.Pos()})
			return true
		}
		if callee := calleeName(call); callee != "" {
			out = append(out, lockEvent{kind: eventCall, callee: callee, pos: call.Pos()})
		}
		return true
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].pos < out[j].pos })
	return out
}

// deferredCalls is the set of call expressions that are the subject of a defer.
// A deferred call runs at function exit, not where it is written.
func deferredCalls(fn *ast.FuncDecl) map[token.Pos]bool {
	out := map[token.Pos]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if d, ok := n.(*ast.DeferStmt); ok && d.Call != nil {
			out[d.Call.Pos()] = true
			// A deferred closure body runs at exit too; anything it unlocks is
			// held until then.
			if lit, ok := d.Call.Fun.(*ast.FuncLit); ok && lit.Body != nil {
				ast.Inspect(lit.Body, func(inner ast.Node) bool {
					if c, ok := inner.(*ast.CallExpr); ok {
						out[c.Pos()] = true
					}
					return true
				})
			}
		}
		return true
	})
	return out
}

// mutexCall recognises s.<mu>.Lock/RLock/Unlock/RUnlock and reports the mutex
// field name.
func mutexCall(call *ast.CallExpr) (lock, method string, ok bool) {
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel {
		return "", "", false
	}
	switch sel.Sel.Name {
	case "Lock", "RLock", "Unlock", "RUnlock":
	default:
		return "", "", false
	}
	inner, isSel := sel.X.(*ast.SelectorExpr)
	if !isSel {
		return "", "", false
	}
	if _, known := lockRank[inner.Sel.Name]; !known {
		return "", "", false
	}
	return inner.Sel.Name, sel.Sel.Name, true
}

// calleeName reports the name of a call to a function or method in this
// package. Selector calls on anything other than a receiver-shaped ident are
// ignored — they are stdlib or another package, neither of which can touch these
// mutexes.
func calleeName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if x, ok := fun.X.(*ast.Ident); ok && (x.Name == "s" || x.Name == "srv") {
			return fun.Sel.Name
		}
	}
	return ""
}

func locksAcquiredDirectly(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if lock, method, ok := mutexCall(call); ok && !strings.HasSuffix(method, "Unlock") {
				out[lock] = true
			}
		}
		return true
	})
	return out
}

func callsMade(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if name := calleeName(call); name != "" {
				out[name] = true
			}
		}
		return true
	})
	return out
}

// propagateLocks closes the direct-acquisition sets over the call graph, so
// "this helper eventually locks userMu" is answerable.
func propagateLocks(direct, calls map[string]map[string]bool) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for fn, locks := range direct {
		out[fn] = map[string]bool{}
		for l := range locks {
			out[fn][l] = true
		}
	}
	// Fixed point. The graph is small (a few hundred functions) and shallow, so
	// iterating to stability costs nothing and handles recursion for free.
	for changed := true; changed; {
		changed = false
		for fn, callees := range calls {
			for callee := range callees {
				for lock := range out[callee] {
					if !out[fn][lock] {
						out[fn][lock] = true
						changed = true
					}
				}
			}
		}
	}
	return out
}

type parsedFile struct {
	ast  *ast.File
	fset *token.FileSet
}

func parsePackage(t *testing.T) []parsedFile {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []parsedFile
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		out = append(out, parsedFile{ast: file, fset: fset})
	}
	if len(out) == 0 {
		t.Fatal("no source files found")
	}
	return out
}

func funcDecls(file *ast.File) []*ast.FuncDecl {
	var out []*ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			out = append(out, fn)
		}
	}
	return out
}

func funcKey(fn *ast.FuncDecl) string { return fn.Name.Name }
