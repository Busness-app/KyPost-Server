// IMAP mailbox and keyword operations: listing labels and subfolders,
// create/delete/rename, and applying or removing a keyword on a message.
package imap

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	goimap "github.com/BrianLeishman/go-imap"
)

func (c *APIClient) ListLabels(ctx context.Context) ([]string, error) {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return nil, err
	}

	lastUIDs, err := d.GetLastNUIDs(200)
	if err != nil {
		return nil, fmt.Errorf("imap get recent uids: %w", err)
	}
	if len(lastUIDs) == 0 {
		return []string{}, nil
	}

	ov, err := d.GetOverviews(lastUIDs...)
	if err != nil {
		return nil, fmt.Errorf("imap get overviews: %w", err)
	}

	seen := map[string]bool{}
	labels := make([]string, 0, 16)
	for _, uid := range lastUIDs {
		o := ov[uid]
		if o == nil {
			continue
		}
		for _, flag := range o.Flags {
			flag = strings.TrimSpace(flag)
			if flag == "" || strings.HasPrefix(flag, "\\") {
				continue
			}
			if seen[flag] {
				continue
			}
			seen[flag] = true
			labels = append(labels, flag)
		}
	}
	sort.Strings(labels)
	return labels, nil
}

func (c *APIClient) ListSubfolders(ctx context.Context, parent string) ([]string, error) {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parent = strings.TrimSpace(parent)

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return nil, err
	}

	folders, err := d.GetFolders()
	if err != nil {
		return nil, fmt.Errorf("imap list folders: %w", err)
	}

	if parent == "" {
		children := []string{}
		seen := map[string]bool{}
		for _, folder := range folders {
			clean := strings.TrimSpace(folder)
			if clean == "" || strings.EqualFold(clean, "INBOX") {
				continue
			}

			topLevel := clean
			if strings.HasPrefix(strings.ToUpper(clean), "INBOX/") || strings.HasPrefix(strings.ToUpper(clean), "INBOX.") {
				rest := clean[len("INBOX/"):]
				if strings.HasPrefix(strings.ToUpper(clean), "INBOX.") {
					rest = clean[len("INBOX."):]
				}
				if idx := strings.IndexAny(rest, "/."); idx >= 0 {
					rest = rest[:idx]
				}
				sep := "/"
				if strings.HasPrefix(strings.ToUpper(clean), "INBOX.") {
					sep = "."
				}
				topLevel = "INBOX" + sep + strings.TrimSpace(rest)
			} else if idx := strings.IndexAny(clean, "/."); idx >= 0 {
				topLevel = clean[:idx]
			}

			label := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(topLevel, "INBOX/"), "INBOX."))
			if label == "" || strings.EqualFold(label, "Archive") {
				continue
			}
			key := strings.ToLower(topLevel)
			if seen[key] {
				continue
			}
			seen[key] = true
			children = append(children, topLevel)
		}

		sort.Strings(children)
		return children, nil
	}

	parentLower := strings.ToLower(parent)
	children := []string{}
	seen := map[string]bool{}
	for _, folder := range folders {
		clean := strings.TrimSpace(folder)
		if clean == "" {
			continue
		}
		child := ""
		for _, prefix := range []string{parent + "/", parent + ".", "INBOX/" + parent + "/", "INBOX." + parent + "."} {
			if strings.HasPrefix(strings.ToLower(clean), strings.ToLower(prefix)) {
				rest := clean[len(prefix):]
				if rest == "" {
					break
				}
				child = clean
				if idx := strings.IndexAny(rest, "/."); idx >= 0 {
					child = prefix + rest[:idx]
				}
				break
			}
		}
		if child == "" {
			continue
		}
		label := strings.TrimSpace(child)
		if strings.HasPrefix(strings.ToLower(label), strings.ToLower("INBOX/"+parent+"/")) {
			label = label[len("INBOX/"+parent+"/"):]
		} else if strings.HasPrefix(strings.ToLower(label), strings.ToLower("INBOX."+parent+".")) {
			label = label[len("INBOX."+parent+"."):]
		} else if strings.HasPrefix(strings.ToLower(label), strings.ToLower(parent+"/")) {
			label = label[len(parent+"/"):]
		} else if strings.HasPrefix(strings.ToLower(label), strings.ToLower(parent+".")) {
			label = label[len(parent+"."):]
		}
		label = strings.TrimSpace(label)
		if label == "" {
			continue
		}
		key := strings.ToLower(child)
		if key == parentLower || seen[key] {
			continue
		}
		seen[key] = true
		children = append(children, child)
	}

	sort.Strings(children)
	return children, nil
}

func containsMailboxPath(folders []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, folder := range folders {
		if strings.EqualFold(strings.TrimSpace(folder), target) {
			return true
		}
	}
	return false
}

func preferredMailboxDelimiters(parent string, folders []string) []string {
	clean := strings.TrimSpace(parent)
	if strings.Contains(clean, "/") {
		return []string{"/", "."}
	}
	if strings.Contains(clean, ".") {
		return []string{".", "/"}
	}
	for _, folder := range folders {
		trimmed := strings.TrimSpace(folder)
		if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(clean+"/")) {
			return []string{"/", "."}
		}
		if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(clean+".")) {
			return []string{".", "/"}
		}
	}
	if strings.EqualFold(clean, "INBOX") {
		return []string{"/", "."}
	}
	return []string{"/", "."}
}

func mailboxParent(path string) string {
	clean := strings.TrimSpace(path)
	idx := strings.LastIndexAny(clean, "/.")
	if idx <= 0 {
		return ""
	}
	return clean[:idx]
}

func (c *APIClient) CreateFolder(ctx context.Context, parent, name string) (string, error) {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return "", err
	}

	parent = strings.TrimSpace(parent)
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("folder name is required")
	}
	if strings.ContainsAny(name, "/.") {
		return "", errors.New(`folder name must be a single level, containing no "/" or "."`)
	}
	if err := ValidateMailboxName(name); err != nil {
		return "", err
	}
	// The parent is concatenated onto name below and the result goes to
	// CREATE, so it is just as much a protocol sink as the leaf is.
	if err := validateOptionalMailboxName(parent); err != nil {
		return "", err
	}

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return "", err
	}

	folders, err := d.GetFolders()
	if err != nil {
		return "", fmt.Errorf("imap list folders: %w", err)
	}

	if parent == "" {
		if containsMailboxPath(folders, name) {
			return name, nil
		}
		if err := d.CreateFolder(name); err != nil {
			return "", fmt.Errorf("imap create folder %q: %w", name, err)
		}
		return name, nil
	}

	var lastErr error
	for _, delimiter := range preferredMailboxDelimiters(parent, folders) {
		candidate := parent + delimiter + name
		if containsMailboxPath(folders, candidate) {
			return candidate, nil
		}
		if err := d.CreateFolder(candidate); err == nil {
			return candidate, nil
		} else {
			lastErr = err
		}
	}

	if lastErr != nil {
		return "", fmt.Errorf("imap create folder %q under %q: %w", name, parent, lastErr)
	}
	return "", fmt.Errorf("imap create folder %q under %q failed", name, parent)
}

func (c *APIClient) DeleteFolder(ctx context.Context, folder string) error {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	folder = strings.TrimSpace(folder)
	if folder == "" {
		return errors.New("folder is required")
	}
	// folder reaches SELECT, UID MOVE, and DELETE below.
	if err := ValidateMailboxName(folder); err != nil {
		return err
	}
	parent := mailboxParent(folder)
	if parent == "" {
		return errors.New("folder must have a parent mailbox")
	}

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return err
	}

	folders, err := d.GetFolders()
	if err != nil {
		return fmt.Errorf("imap list folders: %w", err)
	}
	for _, existing := range folders {
		clean := strings.TrimSpace(existing)
		if strings.EqualFold(clean, folder) {
			continue
		}
		if strings.HasPrefix(strings.ToLower(clean), strings.ToLower(folder+"/")) || strings.HasPrefix(strings.ToLower(clean), strings.ToLower(folder+".")) {
			return errors.New("folder has subfolders and cannot be deleted yet")
		}
	}

	if err := d.SelectFolder(folder); err != nil {
		return fmt.Errorf("imap select folder %q: %w", folder, err)
	}
	uids, err := d.GetUIDs("ALL")
	if err != nil {
		return fmt.Errorf("imap list folder messages %q: %w", folder, err)
	}
	for _, uid := range uids {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := d.MoveEmail(uid, parent); err != nil {
			return fmt.Errorf("imap move uid %d from %q to %q: %w", uid, folder, parent, err)
		}
	}
	if err := d.SelectFolder(parent); err != nil {
		return fmt.Errorf("imap select parent folder %q: %w", parent, err)
	}
	if err := d.DeleteFolder(folder); err != nil {
		return fmt.Errorf("imap delete folder %q: %w", folder, err)
	}
	return nil
}

func (c *APIClient) RenameFolder(ctx context.Context, folder, name string) (string, error) {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return "", err
	}
	folder = strings.TrimSpace(folder)
	name = strings.TrimSpace(name)
	if folder == "" {
		return "", errors.New("folder is required")
	}
	if name == "" {
		return "", errors.New("folder name is required")
	}
	if strings.ContainsAny(name, "/.") {
		return "", errors.New(`folder name must be a single level, containing no "/" or "."`)
	}
	// Both halves reach RENAME: folder as the source, name as the leaf of the
	// destination path built below.
	if err := ValidateMailboxName(folder); err != nil {
		return "", err
	}
	if err := ValidateMailboxName(name); err != nil {
		return "", err
	}
	parent := mailboxParent(folder)
	if parent == "" {
		return "", errors.New("folder must have a parent mailbox")
	}

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return "", err
	}

	folders, err := d.GetFolders()
	if err != nil {
		return "", fmt.Errorf("imap list folders: %w", err)
	}
	delimiter := "/"
	if strings.Contains(folder, ".") {
		delimiter = "."
	}
	if !strings.Contains(folder, "/") && !strings.Contains(folder, ".") {
		for _, candidate := range preferredMailboxDelimiters(parent, folders) {
			delimiter = candidate
			break
		}
	}
	newPath := parent + delimiter + name
	if strings.EqualFold(folder, newPath) {
		return folder, nil
	}
	if containsMailboxPath(folders, newPath) {
		return "", fmt.Errorf("folder %q already exists", newPath)
	}
	if err := d.RenameFolder(folder, newPath); err != nil {
		return "", fmt.Errorf("imap rename folder %q to %q: %w", folder, newPath, err)
	}
	return newPath, nil
}

func (c *APIClient) EnsureLabel(ctx context.Context, label string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateKeyword(label); err != nil {
		return err
	}
	// IMAP keywords are typically created implicitly when first applied.
	return nil
}

func (c *APIClient) ApplyLabel(ctx context.Context, messageID, label string) error {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	uid, err := strconv.Atoi(strings.TrimSpace(messageID))
	if err != nil || uid <= 0 {
		return fmt.Errorf("invalid message id %q", messageID)
	}
	label = strings.TrimSpace(label)
	if err := ValidateKeyword(label); err != nil {
		return err
	}

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return err
	}

	flags := goimap.Flags{Keywords: map[string]bool{label: true}}
	if err := d.SetFlags(uid, flags); err != nil {
		return fmt.Errorf("imap set keyword %q on uid %d: %w", label, uid, err)
	}
	return nil
}

// RemoveLabel clears one IMAP keyword flag from a message — the mirror of
// ApplyLabel, using Keywords[label]=false so SetFlags emits -FLAGS (label)
// in the same UID STORE shape ApplyLabel uses for +FLAGS.
func (c *APIClient) RemoveLabel(ctx context.Context, messageID, label string) error {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	uid, err := strconv.Atoi(strings.TrimSpace(messageID))
	if err != nil || uid <= 0 {
		return fmt.Errorf("invalid message id %q", messageID)
	}
	label = strings.TrimSpace(label)
	if err := ValidateKeyword(label); err != nil {
		return err
	}

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return err
	}

	flags := goimap.Flags{Keywords: map[string]bool{label: false}}
	if err := d.SetFlags(uid, flags); err != nil {
		return fmt.Errorf("imap clear keyword %q on uid %d: %w", label, uid, err)
	}
	return nil
}
