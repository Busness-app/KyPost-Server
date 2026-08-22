package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/fsutil"
)

const maxContactPhotoBytes = 5 << 20 // 5MB

// maxContactPhotoBytesPerUser caps the total size of one account's photo
// directory.
//
// The per-photo limit above bounded a single upload but nothing bounded the
// total: uploading 5 MiB, clearing the contact's ref and repeating grew the
// shared state volume without limit, and none of it was reachable afterwards
// to even show the user what they were using. 200 MiB is roughly forty
// full-size photos, far past a realistic address book, while still being a
// number the volume can absorb from every account at once.
const maxContactPhotoBytesPerUser = 200 << 20 // 200MB

// contentTypeExt is the set of image types a contact photo may be.
//
// Every entry must have a decoder registered by the blank imports above:
// storeContactPhoto gates on image.DecodeConfig, so an entry without one is
// advertised as supported and then rejected 100% of the time with "file is not
// a decodable image". "image/webp" was exactly that — Go's standard library
// has no webp decoder (as of 1.26), so every webp upload, direct or via an
// inbound CardDAV vCard PHOTO, failed while loadContactPhoto below happily
// claimed to serve the type back.
//
// Restoring webp means a decoder, not a map entry: golang.org/x/image/webp
// would be a new dependency for a format this map only ever claimed by
// accident, so it stays out until someone actually asks for it.
var contentTypeExt = map[string]string{
	"image/jpeg": "jpg",
	"image/png":  "png",
	"image/gif":  "gif",
}

// handleContactPhoto uploads (POST), serves (GET), or clears (DELETE) a
// single contact's photo. Upload/delete are web-UI-only workflows and stay
// session-only; GET also accepts the sub+hash pairing auth mobile uses
// elsewhere (see withMailAuth on its route registration).
func (s *Server) handleContactPhoto(w http.ResponseWriter, r *http.Request) {
	store, err := s.contactsFor(r)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	uid := strings.TrimSpace(r.PathValue("id"))
	c, found, err := store.Get(uid)
	if err != nil {
		http.Error(w, "failed to read contacts", http.StatusInternalServerError)
		return
	}
	if !found || c.Deleted {
		http.Error(w, "contact not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodPost:
		s.handleContactPhotoUpload(w, r, store, ac.UserID, c)
	case http.MethodGet:
		s.handleContactPhotoGet(w, r, ac.UserID, c)
	case http.MethodDelete:
		// SetPhotoRef, not Upsert: the store carries PhotoRef forward on an
		// ordinary write so no contact update can change it, and this handler
		// is one of the two legitimate writers.
		if _, _, err := store.SetPhotoRef(c.UID, ""); err != nil {
			http.Error(w, "failed to update contact", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleContactPhotoUpload(w http.ResponseWriter, r *http.Request, store *contacts.Store, userID string, c contacts.Contact) {
	r.Body = http.MaxBytesReader(w, r.Body, maxContactPhotoBytes)
	if err := r.ParseMultipartForm(maxContactPhotoBytes); err != nil {
		http.Error(w, "photo too large or invalid form", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("photo")
	if err != nil {
		http.Error(w, "photo file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	body, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "failed to read photo", http.StatusBadRequest)
		return
	}

	ref, err := s.storeContactPhoto(userID, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	updated, ok, err := store.SetPhotoRef(c.UID, ref)
	if err != nil {
		http.Error(w, "failed to update contact", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "contact not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"photoRef": updated.PhotoRef, "photoUrl": "/api/contacts/" + updated.UID + "/photo"})
}

// storeContactPhoto validates that body is a supported, decodable image,
// writes it to disk under a content-hashed filename, and returns the
// resulting PhotoRef. Shared by the JSON upload endpoint and the CardDAV
// PUT path (an inbound vCard PHOTO property).
func (s *Server) storeContactPhoto(userID string, body []byte) (string, error) {
	contentType := http.DetectContentType(body)
	ext, ok := contentTypeExt[contentType]
	if !ok {
		return "", fmt.Errorf("unsupported image type: %s", contentType)
	}
	if _, _, err := image.DecodeConfig(bytes.NewReader(body)); err != nil {
		return "", errors.New("file is not a decodable image")
	}

	sum := sha256.Sum256(body)
	ref := hex.EncodeToString(sum[:]) + "." + ext

	path := s.userContactPhotoPath(userID, ref)
	// Checked before writing, and skipped when the file is already there: the
	// name is a content hash, so re-storing a picture the user already has
	// overwrites it and adds nothing. Charging for it would refuse a no-op,
	// which is how a CardDAV client that re-PUTs unchanged cards would hit the
	// cap without ever growing anything.
	// The per-photo cap is enforced HERE, not only at the HTTP entrances. The
	// two upload handlers bound their bodies at maxContactPhotoBytes, but the
	// vCard import and CardDAV client-sync paths reach this function under
	// their own, larger limits, so an inline data: URI PHOTO could store a file
	// well past the per-photo ceiling.
	if len(body) > maxContactPhotoBytes {
		return "", errors.New("contact photo is too large")
	}

	// Measure and write under one lock. Without it the ReadDir total and the
	// write were a check-then-act: concurrent uploads all observed the same
	// pre-write usage, all passed, and the per-account cap was exceeded by
	// roughly (concurrency x photo size).
	if err := fsutil.WithFileLock(s.userContactPhotosDir(userID), func() error {
		if _, statErr := os.Stat(path); errors.Is(statErr, os.ErrNotExist) {
			used, uerr := s.contactPhotoBytesUsed(userID)
			// Refuse when the quota cannot be measured. Skipping the check on a
			// read error meant any transient ReadDir failure — EMFILE under the
			// very burst this bounds, EACCES, a flaky volume — silently
			// disabled the cap.
			if uerr != nil {
				return fmt.Errorf("cannot verify photo quota: %w", uerr)
			}
			if used+int64(len(body)) > maxContactPhotoBytesPerUser {
				return errors.New("contact photo storage is full for this account; remove some photos and try again")
			}
		}
		return fsutil.AtomicWriteFile(path, body, 0o600)
	}); err != nil {
		return "", err
	}
	return ref, nil
}

// contactPhotoBytesUsed totals the bytes in a user's photo directory. A missing
// directory is zero, not an error.
func (s *Server) contactPhotoBytesUsed(userID string) (int64, error) {
	entries, err := os.ReadDir(s.userContactPhotosDir(userID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, ierr := entry.Info()
		if ierr != nil {
			continue
		}
		total += info.Size()
	}
	return total, nil
}

// sweepContactPhotos deletes photo files no live contact references.
//
// Reclamation is reference-based rather than delete-on-unlink because photo
// filenames are content hashes: two contacts with the same picture share one
// file, so unlinking on behalf of one would blank the other. Nothing removed
// orphans at all before this, so DELETE .../photo cleared the ref and left the
// bytes on disk forever.
//
// A contact tombstone (Deleted) holds no reference — its photo is exactly the
// kind that should come back. Subdirectories are left alone, and one
// unremovable file does not abort the rest of the sweep.
func (s *Server) sweepContactPhotos(userID string) error {
	store, err := s.userContactsStore(userID)
	if err != nil {
		return err
	}
	// The sweep deletes every photo file this set does not name, so a failed
	// read must abort it: an empty set means "nothing is referenced", and the
	// sweep would delete every photo the user has.
	all, err := store.List()
	if err != nil {
		return err
	}
	referenced := map[string]bool{}
	for _, c := range all {
		if c.Deleted || c.PhotoRef == "" {
			continue
		}
		referenced[filepath.Base(c.PhotoRef)] = true
	}

	dir := s.userContactPhotosDir(userID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || referenced[entry.Name()] {
			continue
		}
		if rerr := os.Remove(filepath.Join(dir, entry.Name())); rerr != nil {
			s.logger.Error("failed to remove orphaned contact photo",
				"user_id", userID, "file", entry.Name(), "error", rerr.Error())
		}
	}
	return nil
}

// loadContactPhoto reads a previously stored photo back into memory (for
// inlining as a CardDAV vCard PHOTO data: URI), returning its bytes and MIME
// content type. Returns ok=false if ref is empty or the file is missing.
func (s *Server) loadContactPhoto(userID, ref string) (data []byte, contentType string, ok bool) {
	if ref == "" {
		return nil, "", false
	}
	body, err := os.ReadFile(s.userContactPhotoPath(userID, ref))
	if err != nil {
		return nil, "", false
	}
	ext := ref
	if i := strings.LastIndex(ref, "."); i >= 0 {
		ext = ref[i+1:]
	}
	for ct, e := range contentTypeExt {
		if e == ext {
			return body, ct, true
		}
	}
	return body, "application/octet-stream", true
}

func (s *Server) handleContactPhotoGet(w http.ResponseWriter, r *http.Request, userID string, c contacts.Contact) {
	if c.PhotoRef == "" {
		http.Error(w, "no photo", http.StatusNotFound)
		return
	}
	path := s.userContactPhotoPath(userID, c.PhotoRef)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "no photo", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to read photo", http.StatusInternalServerError)
		return
	}
	// Safe to cache aggressively: the filename is content-hashed, so any
	// change in bytes produces a different PhotoRef/URL.
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	http.ServeFile(w, r, path)
}
