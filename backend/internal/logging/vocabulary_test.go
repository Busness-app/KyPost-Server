package logging

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Harvest real call sites so adding a new field without a declaration fails CI.
func TestCallSiteFieldsSurviveFiltering(t *testing.T) {
	t.Setenv("KY_LOG_LEVEL", "info")
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "../.."))
	keys := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "http" {
				return true
			}
			switch sel.Sel.Name {
			case "Info", "Error", "Warn", "Debug":
			default:
				return true
			}
			for i := 1; i+1 < len(call.Args); i += 2 {
				lit, ok := call.Args[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				key, err := strconv.Unquote(lit.Value)
				if err == nil {
					keys[key] = path
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatalf("harvest unexpectedly found only %d fields", len(keys))
	}
	for key, path := range keys {
		var out bytes.Buffer
		l, err := NewWithOutput(&out)
		if err != nil {
			t.Fatal(err)
		}
		l.Info("vocabulary check", key, "example")
		var record map[string]any
		if err := json.Unmarshal(out.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		if record[key] == nil || record["dropped_fields"] != nil {
			t.Errorf("undeclared field %q at %s", key, path)
		}
	}
}
