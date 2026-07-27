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
	"strings"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/fsutil"
)

const maxContactPhotoBytes = 5 << 20 // 5MB

var contentTypeExt = map[string]string{
	"image/jpeg": "jpg",
	"image/png":  "png",
	"image/webp": "webp",
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
	c, found := store.Get(uid)
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

	if err := fsutil.AtomicWriteFile(s.userContactPhotoPath(userID, ref), body, 0o600); err != nil {
		return "", fmt.Errorf("failed to store photo: %w", err)
	}
	return ref, nil
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
