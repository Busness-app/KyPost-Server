package imap

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"testing"

	goimap "github.com/BrianLeishman/go-imap"

	"github.com/Busness-app/kypost-server/backend/internal/mailmsg"
)

// TestFetchAttachmentsOversizedSearchCriteria pins the exact SEARCH
// fetchAttachments composes: the single-UID counterpart to
// GetMessageBodies's "UID <set> LARGER <cap>". IMAP ANDs search keys, so this
// asks the server one question about one message — "is the message at this UID
// bigger than we will hold in memory?" — and gets it answered from the
// server's own RFC822.SIZE, without a byte of the body crossing the wire.
func TestFetchAttachmentsOversizedSearchCriteria(t *testing.T) {
	withLoweredMaxInboundMessageBytes(t, 100)
	sb := goimap.Search().UID(strconv.Itoa(7)).Larger(int(mailmsg.MaxInboundMessageBytes))
	if got, want := sb.Build(), "UID 7 LARGER 100"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestFetchAttachmentsSearchesBeforeItFetches is the ordering assertion that
// IS the fix.
//
// fetchAttachments used to call GetEmails first and check emailContentSize
// afterwards, on the stated reasoning that "the one-message blast radius here
// is the same whether the size check runs before or after the fetch". It is
// not: go-imap's GetEmails requests, buffers, MIME-parses and base64-decodes
// the whole message before returning, so a check that runs afterwards can
// only describe the allocation. The recipient opening a message with
// attachments is enough to spend it — ReadPage loads the attachment list
// automatically — and how big that message is belongs to whoever sent it.
//
// A static check because this package cannot drive a *goimap.Dialer without a
// live or fake server (see TestPartitionUIDsBySize's note), and because the
// property is an ordering in the source rather than a state to assert:
// SearchUIDs after GetEmails would pass any behavioural test that only looked
// at the returned error.
func TestFetchAttachmentsSearchesBeforeItFetches(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "client_attachments.go", nil, 0)
	if err != nil {
		t.Fatalf("parse client_attachments.go: %v", err)
	}

	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "fetchAttachments" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("fetchAttachments not found in client_attachments.go; if it moved, move this test with it")
	}

	type call struct {
		name string
		pos  token.Pos
	}
	var calls []call
	ast.Inspect(body, func(n ast.Node) bool {
		expr, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := expr.Fun.(*ast.SelectorExpr); ok {
			calls = append(calls, call{name: sel.Sel.Name, pos: expr.Pos()})
		}
		return true
	})
	sort.Slice(calls, func(i, j int) bool { return calls[i].pos < calls[j].pos })

	indexOf := func(name string) int {
		for i, c := range calls {
			if c.name == name {
				return i
			}
		}
		return -1
	}

	search := indexOf("SearchUIDs")
	fetch := indexOf("GetEmails")

	if fetch < 0 {
		t.Fatal("fetchAttachments no longer calls GetEmails; this test names the fetch it guards")
	}
	if search < 0 {
		t.Fatal("fetchAttachments has no pre-fetch LARGER SEARCH: an oversized message is buffered in full before any size check runs")
	}
	if search > fetch {
		t.Error("fetchAttachments searches for oversized messages AFTER fetching one; the whole message is already in memory by then")
	}
}
