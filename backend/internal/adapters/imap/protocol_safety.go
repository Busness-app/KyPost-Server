package imap

import (
	"errors"
	"fmt"
	"strings"

	goimap "github.com/BrianLeishman/go-imap"
)

// Input validation for the two kinds of string this package hands to the IMAP
// protocol writer: keywords (flags) and mailbox names.
//
// This exists because go-imap does not escape enough to make either safe.
// Keywords are interpolated raw:
//
//	query += fmt.Sprintf(` +FLAGS (%s)`, strings.Join(addFlags, " "))
//
// and mailbox names go into a quoted string escaped by `AddSlashes`, which is
// `strings.NewReplacer("\"", "\\\"")` — it escapes the double-quote and
// nothing else. Neither handles CR/LF, so a value carrying a bare newline
// ends the current command and starts a second, caller-chosen one on the same
// authenticated connection. Neither handles a backslash either, so a name
// ending in one escapes the closing quote instead of being escaped by it.
//
// The guards live here, on the shared adapter methods, rather than in each
// HTTP handler: the poller applies keywords too (see processor.applyPhishKeyword),
// and a guard per caller is both a bigger diff and one caller away from being
// forgotten. Handlers may call these first to answer 400 instead of 502, but
// the adapter is the boundary that must hold.

// ErrUnsafeKeyword / ErrUnsafeMailbox are returned by the validators below.
// Handlers match on them to distinguish "you sent something invalid" (400)
// from "the IMAP server refused" (502).
var (
	ErrUnsafeKeyword = errors.New("invalid IMAP keyword")
	ErrUnsafeMailbox = errors.New("invalid mailbox name")
)

// atomSpecials are the characters RFC 3501's `atom` production excludes.
// A flag-keyword is an atom, so a keyword containing any of these cannot be
// sent as one — SP in particular is why "Follow Up" silently became the two
// separate flags "Follow" and "Up" before this check existed, leaving a flag
// the unlabel path could never remove.
const atomSpecials = `(){ %*"\]`

// ValidateKeyword reports whether label is a legal RFC 3501 flag-keyword:
// non-empty, printable ASCII only, and free of atom-specials. Non-ASCII is
// refused rather than encoded — an atom is ASCII by definition, and a server
// that accepted a UTF-8 keyword would hand it back in a form this client
// could not match.
func ValidateKeyword(label string) error {
	label = strings.TrimSpace(label)
	if label == "" {
		return fmt.Errorf("%w: keyword is required", ErrUnsafeKeyword)
	}
	for _, r := range label {
		if r < 0x21 || r > 0x7E {
			return fmt.Errorf("%w: %q must contain only printable ASCII with no spaces", ErrUnsafeKeyword, label)
		}
		if strings.ContainsRune(atomSpecials, r) {
			return fmt.Errorf("%w: %q must not contain any of %s", ErrUnsafeKeyword, label, atomSpecials)
		}
	}
	return nil
}

// ValidateMailboxName reports whether name is safe to interpolate into a
// quoted mailbox argument (CREATE/RENAME/DELETE/SELECT/EXAMINE/UID MOVE).
//
// Deliberately narrower than "what IMAP permits" only where it has to be:
// control characters end the command, and `\` and `"` defeat AddSlashes as
// described above. Everything else a mail server would accept in a mailbox
// name — spaces, unicode, punctuation — still passes, because rejecting it
// would break real mailboxes for no security gain.
func ValidateMailboxName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: mailbox name is required", ErrUnsafeMailbox)
	}
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7F:
			return fmt.Errorf("%w: %q must not contain control characters", ErrUnsafeMailbox, name)
		case r == '\\' || r == '"':
			return fmt.Errorf("%w: %q must not contain a backslash or double-quote", ErrUnsafeMailbox, name)
		}
	}
	return nil
}

// validateOptionalMailboxName applies ValidateMailboxName only when name is
// non-empty. Several call sites treat "" as "not specified" (an empty parent
// means top level, an empty mailbox means the current selection), and those
// must keep meaning that rather than becoming an error.
func validateOptionalMailboxName(name string) error {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	return ValidateMailboxName(name)
}

// selectMailboxLocked switches the dialer to mailbox, validating it first.
//
// Six read paths (ListUnreadMessages, ListOverviews, SearchMessages,
// GetMessageBodies, ApplyInboxAction, fetchAttachments) had this same
// four-line "select it unless it's empty or already current" block copied out.
// Collapsing them into one method is what makes the ValidateMailboxName call
// a single guard rather than six that a seventh caller could forget to add.
//
// Callers must already hold c.opMu — every one of them does, via the
// ensureConnectedLocked contract.
func (c *APIClient) selectMailboxLocked(d *goimap.Dialer, mailbox string) error {
	mailbox = strings.TrimSpace(mailbox)
	if mailbox == "" || strings.EqualFold(mailbox, c.mailbox) {
		return nil
	}
	if err := ValidateMailboxName(mailbox); err != nil {
		return err
	}
	if err := d.SelectFolder(mailbox); err != nil {
		return fmt.Errorf("imap select folder %q: %w", mailbox, err)
	}
	return nil
}
