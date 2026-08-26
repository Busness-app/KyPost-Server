package imap

// Unit tests for the pure half of folder resolution. Every branch that routes a
// message trusts this parser's output, so it is worth exercising directly
// rather than only through a live conversation.

import (
	"reflect"
	"testing"
)

func TestParseListLine(t *testing.T) {
	for _, tc := range []struct {
		name      string
		line      string
		wantAttrs []string
		wantDelim string
		wantName  string
		wantOK    bool
	}{
		{
			name:      "special-use attribute with a dot delimiter",
			line:      `* LIST (\HasNoChildren \Trash) "." "INBOX.Trash"`,
			wantAttrs: []string{`\HasNoChildren`, `\Trash`},
			wantDelim: ".", wantName: "INBOX.Trash", wantOK: true,
		},
		{
			name:      "unquoted mailbox name",
			line:      `* LIST (\HasNoChildren) "/" INBOX`,
			wantAttrs: []string{`\HasNoChildren`},
			wantDelim: "/", wantName: "INBOX", wantOK: true,
		},
		{
			// The reason the name is read as a token rather than split on space.
			name:      "quoted name containing a space",
			line:      `* LIST (\HasNoChildren \Junk) "/" "Junk E-mail"`,
			wantAttrs: []string{`\HasNoChildren`, `\Junk`},
			wantDelim: "/", wantName: "Junk E-mail", wantOK: true,
		},
		{
			name:      "no attributes",
			line:      `* LIST () "/" "Trash"`,
			wantAttrs: []string{},
			wantDelim: "/", wantName: "Trash", wantOK: true,
		},
		{
			// Servers with a flat namespace report NIL, which is not a delimiter.
			name:      "NIL delimiter",
			line:      `* LIST (\NoInferiors) NIL "INBOX"`,
			wantAttrs: []string{`\NoInferiors`},
			wantDelim: "", wantName: "INBOX", wantOK: true,
		},
		{
			name:      "escaped quote inside the name",
			line:      `* LIST () "/" "od\"d"`,
			wantAttrs: []string{},
			wantDelim: "/", wantName: `od"d`, wantOK: true,
		},
		{
			name:      "XLIST, as older Gmail speaks it",
			line:      `* XLIST (\HasNoChildren \Trash) "/" "[Gmail]/Trash"`,
			wantAttrs: []string{`\HasNoChildren`, `\Trash`},
			wantDelim: "/", wantName: "[Gmail]/Trash", wantOK: true,
		},
		{name: "a tagged completion line is not a LIST line", line: `A1 OK LIST completed`},
		{name: "some other untagged response", line: `* 5 EXISTS`},
		{name: "truncated", line: `* LIST (\HasNoChildren`},
		{name: "empty", line: ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs, delim, name, ok := parseListLine(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if !reflect.DeepEqual(attrs, tc.wantAttrs) {
				t.Errorf("attrs = %q, want %q", attrs, tc.wantAttrs)
			}
			if delim != tc.wantDelim {
				t.Errorf("delimiter = %q, want %q", delim, tc.wantDelim)
			}
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
		})
	}
}

func TestFolderIndexResolve(t *testing.T) {
	t.Run("prefers the special-use attribute over a matching name", func(t *testing.T) {
		// Both exist. The server says the localized one is the trash, and a
		// leftover folder that merely happens to be spelled "Trash" must not win.
		index := &folderIndex{
			delimiter: "/",
			names:     []string{"INBOX", "Trash", "Papierkorb"},
			special:   map[string]string{useTrash: "Papierkorb"},
		}
		if got, ok := index.resolve(useTrash); !ok || got != "Papierkorb" {
			t.Fatalf("resolve = %q %v, want Papierkorb", got, ok)
		}
	})

	t.Run("falls back to alias order", func(t *testing.T) {
		index := &folderIndex{
			delimiter: "/",
			names:     []string{"INBOX", "Junk E-mail", "Spam"},
			special:   map[string]string{},
		}
		// "Spam" outranks "Junk E-mail" in folderNameAliases.
		if got, ok := index.resolve(useJunk); !ok || got != "Spam" {
			t.Fatalf("resolve = %q %v, want Spam", got, ok)
		}
	})

	t.Run("matches an INBOX child", func(t *testing.T) {
		index := &folderIndex{
			delimiter: ".",
			names:     []string{"INBOX", "INBOX.Trash"},
			special:   map[string]string{},
		}
		if got, ok := index.resolve(useTrash); !ok || got != "INBOX.Trash" {
			t.Fatalf("resolve = %q %v, want INBOX.Trash", got, ok)
		}
	})

	// A folder buried in the user's own tree is not the account's archive, and
	// filing mail into it would be its own quiet data loss.
	t.Run("ignores a same-named folder deeper in the tree", func(t *testing.T) {
		index := &folderIndex{
			delimiter: "/",
			names:     []string{"INBOX", "Work/2019/Archive"},
			special:   map[string]string{},
		}
		if got, ok := index.resolve(useArchive); ok {
			t.Fatalf("resolve = %q, want no match for a nested folder", got)
		}
	})

	t.Run("reports no match when nothing fits", func(t *testing.T) {
		index := &folderIndex{delimiter: "/", names: []string{"INBOX"}, special: map[string]string{}}
		if got, ok := index.resolve(useTrash); ok {
			t.Fatalf("resolve = %q, want no match", got)
		}
	})
}

func TestDefaultNameForEverySpecialUse(t *testing.T) {
	// specialFolderLocked creates defaultNameFor(use) when the account has none,
	// so an entry missing here would panic on an empty slice at exactly the
	// wrong moment.
	for _, use := range []string{useTrash, useJunk, useArchive, useSent, useDrafts} {
		if name := defaultNameFor(use); name == "" {
			t.Errorf("no default folder name for %q", use)
		}
	}
}
