package contacts

import (
	"encoding/json"
	"testing"
)

func TestContactProvenanceRoundTrips(t *testing.T) {
	c := Contact{
		FormattedName:     "Dana",
		PGPKey:            "ARMORED",
		PGPKeySource:      PGPSourceWKD,
		PGPKeyFingerprint: "ABC123",
		PGPKeyVerified:    false,
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Contact
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.PGPKeySource != PGPSourceWKD || back.PGPKeyFingerprint != "ABC123" {
		t.Fatalf("provenance not preserved: %+v", back)
	}
}

func TestLegacyContactMissingProvenanceIsTolerated(t *testing.T) {
	var c Contact
	if err := json.Unmarshal([]byte(`{"fn":"Old","pgpKey":"K"}`), &c); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if c.PGPKeySource != "" || c.PGPKeyVerified {
		t.Fatalf("legacy defaults wrong: %+v", c)
	}
}
