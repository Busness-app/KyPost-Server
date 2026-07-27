package imap

import (
	"errors"
	"strings"
	"testing"
)

// The injection these validators exist to stop. go-imap interpolates keywords
// raw into `UID STORE <uid> +FLAGS (%s)` and mailbox names into a quoted
// argument escaped only for `"`, so a bare CR/LF ends the current command and
// starts a second one on the same authenticated connection.
func TestValidateKeywordRejectsCommandInjection(t *testing.T) {
	hostile := []string{
		"X)\r\nA1 DELETE \"INBOX\"",
		"X)\nA1 LOGOUT",
		"a\rb",
		"(",
		")",
		`quote"mark`,
		`back\slash`,
		"star*",
		"percent%",
		"bracket]",
		"brace{",
	}
	for _, label := range hostile {
		if err := ValidateKeyword(label); err == nil {
			t.Errorf("ValidateKeyword(%q) = nil, want an error — this reaches the IMAP wire unescaped", label)
		} else if !errors.Is(err, ErrUnsafeKeyword) {
			t.Errorf("ValidateKeyword(%q) error = %v, want it to wrap ErrUnsafeKeyword", label, err)
		}
	}
}

// The everyday half of the same bug: a keyword with a space was silently split
// into two flags by `strings.Join(addFlags, " ")`, so "Follow Up" set the flags
// "Follow" and "Up" and the unlabel path could then never remove either.
func TestValidateKeywordRejectsSpaceSoOneKeywordStaysOneFlag(t *testing.T) {
	if err := ValidateKeyword("Follow Up"); err == nil {
		t.Fatal(`ValidateKeyword("Follow Up") = nil, want an error: a space makes UID STORE emit two separate flags`)
	}
}

func TestValidateKeywordAcceptsRealKeywords(t *testing.T) {
	// $Phishing is the one this codebase sets itself (processor.phishKeyword);
	// the rest are ordinary RFC 3501 atoms a user or another MUA would produce.
	for _, label := range []string{"$Phishing", "$Junk", "NonJunk", "Work", "to-do", "label_1", "  padded  "} {
		if err := ValidateKeyword(label); err != nil {
			t.Errorf("ValidateKeyword(%q) = %v, want nil", label, err)
		}
	}
}

func TestValidateMailboxNameRejectsCommandInjection(t *testing.T) {
	hostile := []string{
		"abc\r\nA1 DELETE \"INBOX\"",
		"abc\nA1 LOGOUT",
		"abc\x00def",
		// A trailing backslash escapes the *closing* quote rather than being
		// escaped by AddSlashes: CREATE "abc\" swallows the rest of the line.
		`abc\`,
		`a\"b`,
		`say "hi"`,
	}
	for _, name := range hostile {
		if err := ValidateMailboxName(name); err == nil {
			t.Errorf("ValidateMailboxName(%q) = nil, want an error — this reaches the IMAP wire unescaped", name)
		} else if !errors.Is(err, ErrUnsafeMailbox) {
			t.Errorf("ValidateMailboxName(%q) error = %v, want it to wrap ErrUnsafeMailbox", name, err)
		}
	}
}

// Mailbox names are quoted on the wire, so the validator must stay narrow
// enough not to break folders people actually have.
func TestValidateMailboxNameAcceptsRealFolders(t *testing.T) {
	for _, name := range []string{"INBOX", "Archive/2026", "Archive.2026", "Sent Items", "Rechnungen", "日本語", "[Gmail]/All Mail"} {
		if err := ValidateMailboxName(name); err != nil {
			t.Errorf("ValidateMailboxName(%q) = %v, want nil", name, err)
		}
	}
}

// The adapter methods, not just the validators, must refuse. These return
// before ensureConnectedLocked, so they need no live IMAP server.
func TestLabelMethodsRefuseUnsafeKeywordBeforeConnecting(t *testing.T) {
	c := &APIClient{}
	const hostile = "X)\r\nA1 DELETE \"INBOX\""

	if err := c.ApplyLabel(t.Context(), "1", hostile); !errors.Is(err, ErrUnsafeKeyword) {
		t.Errorf("ApplyLabel error = %v, want ErrUnsafeKeyword", err)
	}
	if err := c.RemoveLabel(t.Context(), "1", hostile); !errors.Is(err, ErrUnsafeKeyword) {
		t.Errorf("RemoveLabel error = %v, want ErrUnsafeKeyword", err)
	}
	if err := c.EnsureLabel(t.Context(), hostile); !errors.Is(err, ErrUnsafeKeyword) {
		t.Errorf("EnsureLabel error = %v, want ErrUnsafeKeyword", err)
	}
}

func TestFolderMethodsRefuseUnsafeNameBeforeConnecting(t *testing.T) {
	c := &APIClient{}
	const hostile = "evil\r\nA1 LOGOUT"

	if _, err := c.CreateFolder(t.Context(), "", hostile); !errors.Is(err, ErrUnsafeMailbox) {
		t.Errorf("CreateFolder(name) error = %v, want ErrUnsafeMailbox", err)
	}
	if _, err := c.CreateFolder(t.Context(), hostile, "ok"); !errors.Is(err, ErrUnsafeMailbox) {
		t.Errorf("CreateFolder(parent) error = %v, want ErrUnsafeMailbox", err)
	}
	if err := c.DeleteFolder(t.Context(), hostile); !errors.Is(err, ErrUnsafeMailbox) {
		t.Errorf("DeleteFolder error = %v, want ErrUnsafeMailbox", err)
	}
	if _, err := c.RenameFolder(t.Context(), hostile, "ok"); !errors.Is(err, ErrUnsafeMailbox) {
		t.Errorf("RenameFolder(folder) error = %v, want ErrUnsafeMailbox", err)
	}
	if _, err := c.RenameFolder(t.Context(), "Parent/Child", hostile); !errors.Is(err, ErrUnsafeMailbox) {
		t.Errorf("RenameFolder(name) error = %v, want ErrUnsafeMailbox", err)
	}
}

// selectMailboxLocked is the single guard the six read paths share; a nil
// dialer proves it refuses before it would ever dereference one.
func TestSelectMailboxLockedRefusesBeforeDialing(t *testing.T) {
	c := &APIClient{}
	if err := c.selectMailboxLocked(nil, "evil\r\nA1 LOGOUT"); !errors.Is(err, ErrUnsafeMailbox) {
		t.Fatalf("selectMailboxLocked error = %v, want ErrUnsafeMailbox", err)
	}
	// Empty means "keep the current selection" and must stay a no-op, not an
	// error — several callers rely on that.
	if err := c.selectMailboxLocked(nil, "  "); err != nil {
		t.Fatalf("selectMailboxLocked(empty) = %v, want nil", err)
	}
}

// Guards against a well-meaning "let's allow unicode keywords" edit: an IMAP
// atom is ASCII, and a server echoing back a re-encoded form would break
// hasPhishKeyword's matching.
func TestValidateKeywordRejectsNonASCII(t *testing.T) {
	if err := ValidateKeyword("wichtig-über"); err == nil {
		t.Fatal("ValidateKeyword(non-ASCII) = nil, want an error")
	}
	if !strings.Contains(atomSpecials, "(") {
		t.Fatal("atomSpecials no longer lists '(' — the RFC 3501 atom-specials set was edited")
	}
}
