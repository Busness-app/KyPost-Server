package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoMessageContentInInstanceWideLog is the api-package half of the same
// invariant processor/log_privacy_test.go enforces: s.logger writes to the
// instance-wide app.log, and this package's own GET /api/logs hands that file
// to any admin account. Message content and correspondence metadata belong in
// the caller's per-user store, never here.
//
// Kept as a second copy rather than a shared helper because a test that has to
// be imported is a test a new package forgets to import. Both packages log to
// the same file; both need the guard standing on its own.
func TestNoMessageContentInInstanceWideLog(t *testing.T) {
	forbidden := map[string]string{
		"sender":  "the sending address is correspondence metadata",
		"subject": "a subject line is message content",
		"body":    "a body is message content",
		"snippet": "a snippet is message content",
		// Deliberately NOT "to": in this package it names an API request
		// target often enough that the field is ambiguous rather than wrong.
		"password":      "never log a credential",
		"secret":        "never log a credential",
		"device_secret": "never log a credential",
		"csrf_token":    "never log a credential",
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Info" && sel.Sel.Name != "Error") {
				return true
			}
			inner, ok := sel.X.(*ast.SelectorExpr)
			if !ok || inner.Sel.Name != "logger" {
				return true
			}
			for i := 1; i < len(call.Args); i += 2 {
				lit, ok := call.Args[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				key, err := strconv.Unquote(lit.Value)
				if err != nil {
					continue
				}
				if why, bad := forbidden[strings.ToLower(key)]; bad {
					t.Errorf("%s: log field %q must not reach app.log — %s. "+
						"GET /api/logs serves that file to any admin.",
						fset.Position(lit.Pos()), key, why)
				}
			}
			return true
		})
	}
}
