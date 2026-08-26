// Resolving which mailbox a message action means: the account's real trash,
// junk, archive, sent and drafts folders, as the server names them.
//
// The rule this file exists to enforce is "look before you create". Guessing a
// name and creating one when the guess misses does not fail loudly — it
// succeeds into a folder nobody else uses, and the mail is gone as far as the
// user's other clients and the server's own retention and spam training are
// concerned.
package imap

import (
	"fmt"
	"strings"

	goimap "github.com/BrianLeishman/go-imap"
)

// RFC 6154 special-use attributes. The server tells us what a folder is FOR,
// which is the only thing that survives a localized folder name.
const (
	useTrash   = `\trash`
	useJunk    = `\junk`
	useArchive = `\archive`
	useSent    = `\sent`
	useDrafts  = `\drafts`
)

// folderNameAliases are the conventional spellings to fall back on when the
// server publishes no special-use attribute, matched against a folder's leaf
// name. Order is preference order, and the first entry doubles as the name to
// create when the account genuinely has no such folder.
var folderNameAliases = map[string][]string{
	useTrash:   {"Trash", "Deleted Items", "Deleted Messages", "Bin"},
	useJunk:    {"Junk", "Spam", "Junk E-mail", "Junk Email", "Bulk Mail"},
	useArchive: {"Archive", "Archives"},
	useSent:    {"Sent", "Sent Items", "Sent Messages", "Sent Mail"},
	useDrafts:  {"Drafts", "Draft"},
}

// folderIndex is one snapshot of the server's mailbox list: what exists, how
// the hierarchy is spelled, and what each folder is for.
type folderIndex struct {
	// delimiter is the server's hierarchy separator, "/" or "." in practice.
	// Read from LIST rather than guessed, which is what the old
	// "Archive/2026" then "Archive.2026" candidate pairs were groping for.
	delimiter string
	names     []string
	// special maps a lowercased special-use attribute to the folder carrying it.
	special map[string]string
}

// parseListLine pulls the attributes, hierarchy delimiter and mailbox name out
// of one untagged LIST response, of the form:
//
//	STAR LIST (\HasNoChildren \Trash) "." "INBOX.Trash"
//
// (written with STAR because a literal asterisk here reads as a list bullet.)
//
// A pure function so the parsing is testable without a server, which matters
// because every branch below trusts its output to route mail.
//
// Mailbox names arrive in modified UTF-7 (RFC 3501 §5.1.3) and are NOT decoded:
// they are echoed straight back to the server in the next command, so the
// encoded form is the correct one to carry. It does mean a non-ASCII name will
// not match a folderNameAliases entry — which is exactly the case special-use
// attributes exist to cover.
func parseListLine(line string) (attrs []string, delimiter, name string, ok bool) {
	rest := strings.TrimSpace(line)
	if !strings.HasPrefix(rest, "*") {
		return nil, "", "", false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "*"))
	for _, verb := range []string{"LIST", "LSUB", "XLIST"} {
		if len(rest) >= len(verb) && strings.EqualFold(rest[:len(verb)], verb) {
			rest = strings.TrimSpace(rest[len(verb):])
			goto parsed
		}
	}
	return nil, "", "", false

parsed:
	if !strings.HasPrefix(rest, "(") {
		return nil, "", "", false
	}
	end := strings.Index(rest, ")")
	if end < 0 {
		return nil, "", "", false
	}
	attrs = strings.Fields(rest[1:end])
	rest = strings.TrimSpace(rest[end+1:])

	delimiter, rest, ok = readAtomOrQuoted(rest)
	if !ok {
		return nil, "", "", false
	}
	if strings.EqualFold(delimiter, "NIL") {
		delimiter = ""
	}

	name, _, ok = readAtomOrQuoted(strings.TrimSpace(rest))
	if !ok || name == "" {
		return nil, "", "", false
	}
	return attrs, delimiter, name, true
}

// readAtomOrQuoted reads one IMAP token — a quoted string, which may contain
// spaces ("Junk E-mail", "Sent Items"), or a bare atom — and returns it along
// with whatever follows.
func readAtomOrQuoted(s string) (token, rest string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	if s[0] != '"' {
		token, rest, _ = strings.Cut(s, " ")
		return token, rest, true
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			}
		case '"':
			return b.String(), s[i+1:], true
		default:
			b.WriteByte(s[i])
		}
	}
	return "", "", false
}

// listFolders runs one LIST and builds an index from it. selectionOption is the
// bare `LIST "" "*"` when empty, or the RFC 6154 selection form when set to
// `(SPECIAL-USE)`.
func listFolders(d *goimap.Dialer, selectionOption string) (*folderIndex, error) {
	command := `LIST "" "*"`
	if selectionOption != "" {
		command = `LIST ` + selectionOption + ` "" "*"`
	}

	index := &folderIndex{special: map[string]string{}}
	// retryCount 0: a server that does not know the selection option answers
	// BAD, and go-imap cannot tell a rejected command from a dropped socket —
	// it would close the connection and log in again for each retry. One
	// attempt, and the caller reconnects.
	_, err := d.Exec(command, false, 0, func(line []byte) error {
		attrs, delimiter, name, ok := parseListLine(string(line))
		if !ok {
			return nil
		}
		if delimiter != "" {
			index.delimiter = delimiter
		}
		index.names = append(index.names, name)
		for _, attr := range attrs {
			lowered := strings.ToLower(attr)
			if _, wanted := folderNameAliases[lowered]; wanted {
				if _, taken := index.special[lowered]; !taken {
					index.special[lowered] = name
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return index, nil
}

// folderIndexLocked returns the cached mailbox list, building it on first use.
// Caller must hold opMu.
func (c *APIClient) folderIndexLocked(d *goimap.Dialer) (*folderIndex, error) {
	if c.folders != nil {
		return c.folders, nil
	}

	index, err := listFolders(d, "")
	if err != nil {
		// A failed Exec leaves the connection closed even at retryCount 0 (the
		// retry helper's failure hook closes before it checks whether any
		// retries remain), so the connection has to be rebuilt before anything
		// else can run on it.
		if rerr := d.Reconnect(); rerr != nil {
			return nil, fmt.Errorf("imap list folders: %w", err)
		}
		return nil, fmt.Errorf("imap list folders: %w", err)
	}

	// Most servers volunteer special-use attributes in a plain LIST. RFC 6154
	// only obliges them to under the selection option, so ask explicitly when
	// none came back and the server says it supports them — that combination is
	// the only way a localized folder name is ever resolvable.
	if len(index.special) == 0 && capabilitySupportsSpecialUse(d) {
		if special, err := listFolders(d, "(SPECIAL-USE)"); err == nil {
			for attr, name := range special.special {
				index.special[attr] = name
			}
		} else if rerr := d.Reconnect(); rerr != nil {
			return nil, fmt.Errorf("imap list special-use folders: %w", err)
		}
	}

	if index.delimiter == "" {
		index.delimiter = "/"
	}
	c.folders = index
	return index, nil
}

// capabilitySupportsSpecialUse asks the server what it can do. CAPABILITY is
// mandatory in IMAP4rev1, so unlike the selection option it cannot come back
// BAD and cost a reconnect.
func capabilitySupportsSpecialUse(d *goimap.Dialer) bool {
	supported := false
	_, err := d.Exec("CAPABILITY", false, 0, func(line []byte) error {
		if strings.Contains(strings.ToUpper(string(line)), "SPECIAL-USE") {
			supported = true
		}
		return nil
	})
	if err != nil {
		_ = d.Reconnect()
		return false
	}
	return supported
}

// leafOf returns the last path segment of a mailbox name under delimiter.
func leafOf(name, delimiter string) string {
	if delimiter == "" {
		return name
	}
	if idx := strings.LastIndex(name, delimiter); idx >= 0 {
		return name[idx+len(delimiter):]
	}
	return name
}

// isTopLevelOrInboxChild keeps alias matching to the folders that could
// plausibly BE the account's trash, rather than any folder in the tree that
// happens to be called Archive — "Work/2019/Archive" is not the archive.
func (f *folderIndex) isTopLevelOrInboxChild(name string) bool {
	if f.delimiter == "" || !strings.Contains(name, f.delimiter) {
		return true
	}
	parent := name[:strings.LastIndex(name, f.delimiter)]
	return strings.EqualFold(parent, "INBOX")
}

// resolve returns the folder serving the given special use, and whether one was
// found. Special-use attribute first, conventional name second.
func (f *folderIndex) resolve(use string) (string, bool) {
	if name, ok := f.special[use]; ok {
		return name, true
	}
	for _, alias := range folderNameAliases[use] {
		for _, name := range f.names {
			if !f.isTopLevelOrInboxChild(name) {
				continue
			}
			if strings.EqualFold(leafOf(name, f.delimiter), alias) {
				return name, true
			}
		}
	}
	return "", false
}

// defaultNameFor is what to create when the account has no such folder at all.
func defaultNameFor(use string) string {
	return folderNameAliases[use][0]
}

// existingSpecialFolderLocked resolves the account's folder for a special use
// WITHOUT creating anything, for callers that are asking a question rather than
// routing a message. Caller must hold opMu.
func (c *APIClient) existingSpecialFolderLocked(d *goimap.Dialer, use string) (string, bool) {
	index, err := c.folderIndexLocked(d)
	if err != nil {
		return "", false
	}
	return index.resolve(use)
}

// specialFolderLocked resolves the account's folder for a special use, creating
// the conventional one only when the server genuinely has none. Caller must
// hold opMu.
func (c *APIClient) specialFolderLocked(d *goimap.Dialer, use string) (string, error) {
	index, err := c.folderIndexLocked(d)
	if err != nil {
		return "", err
	}
	if name, ok := index.resolve(use); ok {
		return name, nil
	}

	name := defaultNameFor(use)
	if err := d.CreateFolder(name); err != nil {
		return "", fmt.Errorf("imap create %s folder: %w", name, err)
	}
	c.invalidateFolderIndexLocked()
	return name, nil
}

// childOfSpecialFolderLocked resolves a special-use folder and returns a named
// child of it — the yearly archive — spelled with the server's own delimiter,
// creating whatever part of that path is missing. Caller must hold opMu.
func (c *APIClient) childOfSpecialFolderLocked(d *goimap.Dialer, use, child string) (string, error) {
	parent, err := c.specialFolderLocked(d, use)
	if err != nil {
		return "", err
	}
	index, err := c.folderIndexLocked(d)
	if err != nil {
		return "", err
	}

	full := parent + index.delimiter + child
	for _, existing := range index.names {
		if strings.EqualFold(existing, full) {
			return full, nil
		}
	}
	if err := d.CreateFolder(full); err != nil {
		return "", fmt.Errorf("imap create %s folder: %w", full, err)
	}
	c.invalidateFolderIndexLocked()
	return full, nil
}

// invalidateFolderIndexLocked drops the cached mailbox list after this client
// changes it. Caller must hold opMu.
func (c *APIClient) invalidateFolderIndexLocked() {
	c.folders = nil
}
