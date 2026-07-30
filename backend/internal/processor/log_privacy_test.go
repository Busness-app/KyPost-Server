package processor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbiddenLogKeys are structured-log field names that must never appear in a
// p.log call in this package.
//
// The poller's logger writes to the instance-wide app.log, and
// GET /api/logs serves that file to ANY admin account. Putting a sender or a
// subject there hands every user's correspondence metadata to an account that
// is not theirs, on a server whose premise is that only the recipient can read
// their mail. Both fields are already recorded on the per-user state.Decision
// row, which lives in that user's own state.db.
//
// This is enforced by scanning the source rather than by capturing log output
// because the field has to be absent from EVERY log call, including ones on
// error paths no test happens to drive. A behavioural test proves one line is
// clean; this proves the package is.
var forbiddenLogKeys = map[string]string{
	"sender":  "the sending address is correspondence metadata",
	"subject": "a subject line is message content",
	"body":    "a body is message content",
	"to":      "recipient addresses are correspondence metadata",
	"snippet": "a snippet is message content",
}

func TestNoMessageContentInInstanceWideLog(t *testing.T) {
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
			// p.log.Info(...) / p.log.Error(...) — the logging.Logger API is
			// (msg string, kv ...string), so keys sit at odd indexes after the
			// message.
			inner, ok := sel.X.(*ast.SelectorExpr)
			if !ok || inner.Sel.Name != "log" {
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
				if why, bad := forbiddenLogKeys[strings.ToLower(key)]; bad {
					t.Errorf("%s: log field %q must not reach app.log — %s. "+
						"GET /api/logs serves that file to any admin; record it on the "+
						"per-user state.Decision row instead.",
						fset.Position(lit.Pos()), key, why)
				}
			}
			return true
		})
	}
}

func TestClipForLogBoundsAndFlattensModelOutput(t *testing.T) {
	// A model that echoes its input back is the case that matters: the echoed
	// text is attacker-controlled email content, and newlines in it would forge
	// whole records for anything parsing app.log line by line.
	long := strings.Repeat("A", maxLoggedLabelBytes*3)
	got := clipForLog("  line one\nline two\r\n" + long + "  ")

	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("clipForLog left newlines in %q — a subject can forge a log record", got)
	}
	if len(got) > maxLoggedLabelBytes+len("...(truncated)") {
		t.Errorf("clipForLog returned %d bytes, want at most %d", len(got), maxLoggedLabelBytes+len("...(truncated)"))
	}
	if !strings.HasSuffix(got, "...(truncated)") {
		t.Errorf("clipForLog(%d bytes) = %q, want a truncation marker", len(long), got)
	}

	// Short, well-behaved output passes through unchanged apart from trimming.
	if got := clipForLog("  Important  "); got != "Important" {
		t.Errorf("clipForLog trimmed-only case = %q, want %q", got, "Important")
	}
}
