package users

import "testing"

func TestValidEnvelopeSlot(t *testing.T) {
	tests := []struct {
		slot string
		want bool
	}{
		{"recovery", true},
		{"device:abc123", true},
		{"password", false}, // written only via RewrapPGPPrivateKey
		{"device:", false},
		{"", false},
		{"nonsense", false},
		{"device:has space", false},
		{"device:has\nnewline", false},
	}
	for _, tc := range tests {
		if got := ValidEnvelopeSlot(tc.slot); got != tc.want {
			t.Errorf("ValidEnvelopeSlot(%q) = %v, want %v", tc.slot, got, tc.want)
		}
	}
}

// The legacy single-blob field must present as the password slot, so callers
// have one way to ask "every sealing of this key" and legacy accounts need no
// migration pass over users.json.
func TestWrappedEnvelopesSynthesisesLegacyPasswordSlot(t *testing.T) {
	u := User{PGPPrivateKeyWrapped: `{"v":2}`}
	got := u.WrappedEnvelopes()
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1: %+v", len(got), got)
	}
	if got[0].Slot != EnvelopeSlotPassword || got[0].Envelope != `{"v":2}` {
		t.Fatalf("unexpected entry: %+v", got[0])
	}
}

func TestWrappedEnvelopesCombinesLegacyAndList(t *testing.T) {
	u := User{
		PGPPrivateKeyWrapped: `{"v":2,"slot":"pw"}`,
		PGPWrappedEnvelopes: []WrappedEnvelope{
			{Slot: EnvelopeSlotRecovery, Envelope: `{"v":2,"slot":"rec"}`},
		},
	}
	got := u.WrappedEnvelopes()
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %+v", len(got), got)
	}
	if got[0].Slot != EnvelopeSlotPassword || got[1].Slot != EnvelopeSlotRecovery {
		t.Fatalf("unexpected order/slots: %+v", got)
	}
}

// A list entry claiming the password slot must not shadow the legacy field:
// one slot, one writer. Otherwise a caller that could write the list could
// replace the password envelope without going through RewrapPGPPrivateKey and
// its ErrNotClientProtected guard.
func TestWrappedEnvelopesIgnoresPasswordSlotInList(t *testing.T) {
	u := User{
		PGPPrivateKeyWrapped: "legit",
		PGPWrappedEnvelopes:  []WrappedEnvelope{{Slot: EnvelopeSlotPassword, Envelope: "impostor"}},
	}
	got := u.WrappedEnvelopes()
	if len(got) != 1 || got[0].Envelope != "legit" {
		t.Fatalf("list entry shadowed the legacy password envelope: %+v", got)
	}
}

func TestWrappedEnvelopesEmptyWhenNoIdentity(t *testing.T) {
	if got := (User{}).WrappedEnvelopes(); len(got) != 0 {
		t.Fatalf("len = %d, want 0", len(got))
	}
}
