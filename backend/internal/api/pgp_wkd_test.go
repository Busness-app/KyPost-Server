package api

import "testing"

func TestWKDHashLocalPart(t *testing.T) {
	// Canonical vector from the WKD spec (draft-koch-openpgp-webkey-service):
	// local-part "Joe.Doe" hashes to this z-base-32 string.
	got := wkdHashLocalPart("Joe.Doe")
	want := "iy9q119eutrkn8s1mk4r39qejnbu3n5q"
	if got != want {
		t.Fatalf("wkdHashLocalPart = %q, want %q", got, want)
	}
}
