package api

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/contacts"
)

// run-4 LOW-10: contact photos had no quota and no reclamation. DELETE
// .../photo cleared the contact's PhotoRef but left the file on disk forever,
// and nothing anywhere ever removed an orphaned photo — so an authenticated
// user could upload 5 MiB at a time, delete, and repeat, growing the shared
// state volume without bound and without any of it being reachable or
// accounted for.
//
// Deleting the file at unlink time is the wrong fix: photo filenames are
// content hashes, so two contacts with the same picture share one file and
// unlinking one would blank the other. Reclamation has to be
// reference-based — hence a sweep.

// testPNG returns a small valid PNG, distinct per seed so each has its own
// content hash.
func testPNG(t *testing.T, seed uint8) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: seed, G: seed, B: seed, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	return buf.Bytes()
}

func photoFileCount(t *testing.T, srv *Server, userID string) int {
	t.Helper()
	entries, err := os.ReadDir(srv.userContactPhotosDir(userID))
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("ReadDir: %v", err)
	}
	return len(entries)
}

func TestSweepContactPhotosRemovesUnreferencedFiles(t *testing.T) {
	srv := newTestServer(t)
	const userID = "user-1"

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	kept, err := store.Upsert(contacts.Contact{FormattedName: "Kept"})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	keptRef, err := srv.storeContactPhoto(userID, testPNG(t, 1))
	if err != nil {
		t.Fatalf("storeContactPhoto: %v", err)
	}
	if _, _, err := store.SetPhotoRef(kept.UID, keptRef); err != nil {
		t.Fatalf("SetPhotoRef: %v", err)
	}
	// An orphan: uploaded, then the contact's ref was cleared (or the contact
	// was deleted) and the bytes were left behind.
	orphanRef, err := srv.storeContactPhoto(userID, testPNG(t, 2))
	if err != nil {
		t.Fatalf("storeContactPhoto: %v", err)
	}

	if got := photoFileCount(t, srv, userID); got != 2 {
		t.Fatalf("photo files before sweep = %d, want 2", got)
	}

	if err := srv.sweepContactPhotos(userID); err != nil {
		t.Fatalf("sweepContactPhotos: %v", err)
	}

	if _, err := os.Stat(srv.userContactPhotoPath(userID, orphanRef)); !os.IsNotExist(err) {
		t.Fatalf("orphaned photo survived the sweep (err=%v)", err)
	}
	if _, err := os.Stat(srv.userContactPhotoPath(userID, keptRef)); err != nil {
		t.Fatalf("referenced photo was deleted: %v", err)
	}
}

// Two contacts sharing one picture share one file, because the name is a
// content hash. Clearing one contact's ref must not take the other's picture
// with it — the exact bug that made delete-at-unlink the wrong design.
func TestSweepContactPhotosKeepsFileSharedByTwoContacts(t *testing.T) {
	srv := newTestServer(t)
	const userID = "user-1"

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	ref, err := srv.storeContactPhoto(userID, testPNG(t, 3))
	if err != nil {
		t.Fatalf("storeContactPhoto: %v", err)
	}

	var uids []string
	for _, name := range []string{"A", "B"} {
		c, uerr := store.Upsert(contacts.Contact{FormattedName: name})
		if uerr != nil {
			t.Fatalf("Upsert: %v", uerr)
		}
		if _, _, serr := store.SetPhotoRef(c.UID, ref); serr != nil {
			t.Fatalf("SetPhotoRef: %v", serr)
		}
		uids = append(uids, c.UID)
	}

	// One of them drops the photo.
	if _, _, err := store.SetPhotoRef(uids[0], ""); err != nil {
		t.Fatalf("SetPhotoRef: %v", err)
	}
	if err := srv.sweepContactPhotos(userID); err != nil {
		t.Fatalf("sweepContactPhotos: %v", err)
	}

	if _, err := os.Stat(srv.userContactPhotoPath(userID, ref)); err != nil {
		t.Fatalf("a photo still referenced by another contact was deleted: %v", err)
	}
}

// A deleted contact is a tombstone with no photo of its own; its bytes must be
// reclaimed rather than pinned by the tombstone forever.
func TestSweepContactPhotosReclaimsDeletedContactsPhoto(t *testing.T) {
	srv := newTestServer(t)
	const userID = "user-1"

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	c, err := store.Upsert(contacts.Contact{FormattedName: "Gone"})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	ref, err := srv.storeContactPhoto(userID, testPNG(t, 4))
	if err != nil {
		t.Fatalf("storeContactPhoto: %v", err)
	}
	if _, _, err := store.SetPhotoRef(c.UID, ref); err != nil {
		t.Fatalf("SetPhotoRef: %v", err)
	}
	if _, err := store.Delete(c.UID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if err := srv.sweepContactPhotos(userID); err != nil {
		t.Fatalf("sweepContactPhotos: %v", err)
	}
	if _, err := os.Stat(srv.userContactPhotoPath(userID, ref)); !os.IsNotExist(err) {
		t.Fatalf("a deleted contact's photo survived (err=%v)", err)
	}
}

// The sweep must never wander outside the user's own photo directory, and must
// tolerate junk rather than aborting on it.
func TestSweepContactPhotosIgnoresSubdirectories(t *testing.T) {
	srv := newTestServer(t)
	const userID = "user-1"

	dir := srv.userContactPhotosDir(userID)
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := srv.sweepContactPhotos(userID); err != nil {
		t.Fatalf("sweepContactPhotos: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "nested")); err != nil {
		t.Fatalf("sweep removed a subdirectory: %v", err)
	}
}

func TestStoreContactPhotoRefusesPastTheUserQuota(t *testing.T) {
	srv := newTestServer(t)
	const userID = "user-1"

	// Fill the directory past the cap with pre-existing bytes, so the test does
	// not depend on how many uploads it takes to get there.
	dir := srv.userContactPhotosDir(userID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	filler := make([]byte, maxContactPhotoBytesPerUser)
	if err := os.WriteFile(filepath.Join(dir, "filler.png"), filler, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := srv.storeContactPhoto(userID, testPNG(t, 5)); err == nil {
		t.Fatal("storeContactPhoto succeeded past the per-user quota")
	}
}

func TestStoreContactPhotoAllowsUploadsUnderTheQuota(t *testing.T) {
	srv := newTestServer(t)

	if _, err := srv.storeContactPhoto("user-1", testPNG(t, 6)); err != nil {
		t.Fatalf("an ordinary upload was refused: %v", err)
	}
}

// Re-uploading a picture the user already has must not be charged twice — the
// filename is the content hash, so it overwrites rather than adding bytes.
func TestStoreContactPhotoAllowsReuploadingTheSameImageAtQuota(t *testing.T) {
	srv := newTestServer(t)
	const userID = "user-1"

	img := testPNG(t, 7)
	ref, err := srv.storeContactPhoto(userID, img)
	if err != nil {
		t.Fatalf("storeContactPhoto: %v", err)
	}

	// Pad the directory to the cap with a separate file.
	dir := srv.userContactPhotosDir(userID)
	filler := make([]byte, maxContactPhotoBytesPerUser)
	if err := os.WriteFile(filepath.Join(dir, "filler.png"), filler, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := srv.storeContactPhoto(userID, img); err != nil {
		t.Fatalf("re-uploading an image already on disk was refused: %v", err)
	}
	if _, err := os.Stat(srv.userContactPhotoPath(userID, ref)); err != nil {
		t.Fatalf("the existing photo went missing: %v", err)
	}
}

// The pickup quota is a condition the caller can clear themselves, so it must
// not surface as a server fault — the compose UI can only say something useful
// if the status distinguishes it.
func TestSealedPickupCreateReportsQuotaAsTooManyRequests(t *testing.T) {
	srv := newTestServer(t)
	u := clientProtectedUser(t, srv)

	for i := 0; i < 100; i++ {
		if _, err := srv.pickupStore.CreateClientSealed(u.ID, "r@example.com", sealedBlob, time.Hour); err != nil {
			t.Fatalf("CreateClientSealed %d: %v", i, err)
		}
	}

	body, _ := json.Marshal(map[string]any{"recipient": "nokey@example.com", "sealed": sealedBlob})
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/pickup", bytes.NewReader(body))
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePickupCreate)(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
	}
	if strings.Contains(strings.ToLower(rec.Body.String()), "failed to create") {
		t.Fatalf("quota refusal was reported as a server fault: %s", rec.Body.String())
	}
}
