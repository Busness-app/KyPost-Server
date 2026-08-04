package contacts

import (
	"reflect"
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	cases := map[string]string{
		"  Foo@Bar.COM ": "foo@bar.com",
		"a@b.com":        "a@b.com",
		"   ":            "",
		"":               "",
	}
	for in, want := range cases {
		if got := normalizeEmail(in); got != want {
			t.Errorf("normalizeEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizePhone(t *testing.T) {
	if a, b := normalizePhone("+1 (555) 123-4567"), normalizePhone("555-123-4567"); a != b {
		t.Errorf("expected +1 and bare form to match: %q vs %q", a, b)
	}
	cases := map[string]string{
		"+1 (555) 123-4567": "5551234567",
		"555.123.4567":      "5551234567",
		"12345":             "12345",
		"abc":               "",
		"":                  "",
	}
	for in, want := range cases {
		if got := normalizePhone(in); got != want {
			t.Errorf("normalizePhone(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFindDuplicateGroups_SharedEmail(t *testing.T) {
	cs := []Contact{
		{UID: "a", FormattedName: "A", Emails: []ContactValue{{Value: "X@y.com"}}},
		{UID: "b", FormattedName: "B", Emails: []ContactValue{{Value: "x@Y.com"}}},
		{UID: "c", FormattedName: "C", Emails: []ContactValue{{Value: "z@y.com"}}},
	}
	groups := findDuplicateGroups(cs)
	if !reflect.DeepEqual(groups, [][]int{{0, 1}}) {
		t.Fatalf("groups = %v, want [[0 1]]", groups)
	}
}

func TestFindDuplicateGroups_SharedPhone(t *testing.T) {
	cs := []Contact{
		{UID: "a", FormattedName: "A", Phones: []ContactValue{{Value: "+1 555 123 4567"}}},
		{UID: "b", FormattedName: "B", Phones: []ContactValue{{Value: "(555) 123-4567"}}},
	}
	groups := findDuplicateGroups(cs)
	if !reflect.DeepEqual(groups, [][]int{{0, 1}}) {
		t.Fatalf("groups = %v, want [[0 1]]", groups)
	}
}

func TestFindDuplicateGroups_NameOnlyMatchesWhenEmpty(t *testing.T) {
	cs := []Contact{
		{UID: "full", FormattedName: "John Smith", Emails: []ContactValue{{Value: "john@x.com"}}},
		{UID: "bare", FormattedName: "john smith"}, // no email/phone -> otherwise empty
	}
	groups := findDuplicateGroups(cs)
	if !reflect.DeepEqual(groups, [][]int{{0, 1}}) {
		t.Fatalf("groups = %v, want [[0 1]] (name-only contact should match)", groups)
	}
}

func TestFindDuplicateGroups_NameDoesNotMatchWhenBothHaveContactInfo(t *testing.T) {
	cs := []Contact{
		{UID: "a", FormattedName: "John Smith", Emails: []ContactValue{{Value: "a@x.com"}}},
		{UID: "b", FormattedName: "John Smith", Emails: []ContactValue{{Value: "b@x.com"}}},
	}
	if groups := findDuplicateGroups(cs); len(groups) != 0 {
		t.Fatalf("groups = %v, want none (same name but distinct emails, neither empty)", groups)
	}
}

func TestGroupShouldMerge(t *testing.T) {
	pair := []Contact{{FormattedName: "A"}, {FormattedName: "B"}}
	if !groupShouldMerge(pair) {
		t.Error("size-2 group should always merge")
	}
	sameName := []Contact{{FormattedName: "Jane Doe"}, {FormattedName: "jane doe"}, {FormattedName: "JANE DOE"}}
	if !groupShouldMerge(sameName) {
		t.Error("size-3 group with one shared name should merge")
	}
	family := []Contact{{FormattedName: "Mom"}, {FormattedName: "Dad"}, {FormattedName: "Kid"}}
	if groupShouldMerge(family) {
		t.Error("size-3 group with differing names should NOT merge")
	}
}

func TestMergeGroup(t *testing.T) {
	members := []Contact{
		{
			UID: "old", CreatedAt: "2020-01-01T00:00:00Z", UpdatedAt: "2020-01-01T00:00:00Z", Rev: 1,
			FormattedName: "J. Smith", Org: "OldCorp",
			Emails: []ContactValue{{Value: "j@old.com"}},
			Phones: []ContactValue{{Value: "555-111-2222"}},
		},
		{
			UID: "new", CreatedAt: "2021-06-01T00:00:00Z", UpdatedAt: "2021-06-01T00:00:00Z", Rev: 5,
			FormattedName: "John Smith", Title: "Engineer",
			Emails: []ContactValue{{Value: "J@OLD.com"}, {Value: "john@new.com"}},
		},
	}
	survivor, absorbed := mergeGroup(members)

	if survivor.UID != "old" {
		t.Errorf("survivor UID = %q, want oldest 'old'", survivor.UID)
	}
	if !reflect.DeepEqual(absorbed, []string{"new"}) {
		t.Errorf("absorbed = %v, want [new]", absorbed)
	}
	// Most-recent non-empty scalar wins.
	if survivor.FormattedName != "John Smith" {
		t.Errorf("FormattedName = %q, want newest 'John Smith'", survivor.FormattedName)
	}
	// Blank-on-newer filled from older; older-only fields kept.
	if survivor.Org != "OldCorp" {
		t.Errorf("Org = %q, want 'OldCorp'", survivor.Org)
	}
	if survivor.Title != "Engineer" {
		t.Errorf("Title = %q, want 'Engineer'", survivor.Title)
	}
	// Emails unioned + de-duped by normalized value (j@old.com appears once).
	if len(survivor.Emails) != 2 {
		t.Errorf("emails = %v, want 2 unique", survivor.Emails)
	}
	if len(survivor.Phones) != 1 {
		t.Errorf("phones = %v, want 1", survivor.Phones)
	}
	if !reflect.DeepEqual(survivor.MergedUIDs, []string{"new"}) {
		t.Errorf("MergedUIDs = %v, want [new]", survivor.MergedUIDs)
	}
}

func TestStoreDedupe(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Upsert(Contact{FormattedName: "Ann", Emails: []ContactValue{{Value: "ann@x.com"}}})
	_, _ = s.Upsert(Contact{FormattedName: "Ann B", Emails: []ContactValue{{Value: "ANN@x.com"}}, Phones: []ContactValue{{Value: "555-9999"}}})

	rep, err := s.Dedupe()
	if err != nil {
		t.Fatal(err)
	}
	if rep.MergedCount != 1 {
		t.Fatalf("MergedCount = %d, want 1", rep.MergedCount)
	}

	live := s.List()
	if len(live) != 1 {
		t.Fatalf("live contacts = %d, want 1", len(live))
	}
	survivor := live[0]
	if survivor.UID != a.UID {
		t.Errorf("survivor = %q, want oldest %q", survivor.UID, a.UID)
	}
	if len(survivor.Phones) != 1 {
		t.Errorf("survivor should have absorbed the phone: %v", survivor.Phones)
	}
	if len(survivor.MergedUIDs) != 1 {
		t.Errorf("survivor MergedUIDs = %v, want 1", survivor.MergedUIDs)
	}

	// Loser is tombstoned and points back at the survivor.
	loserUID := survivor.MergedUIDs[0]
	loser, ok := s.Get(loserUID)
	if !ok || !loser.Deleted {
		t.Fatalf("loser %q should be a tombstone", loserUID)
	}
	if loser.MergedInto != survivor.UID {
		t.Errorf("loser.MergedInto = %q, want %q", loser.MergedInto, survivor.UID)
	}

	// Idempotent: a second pass finds nothing.
	rep2, err := s.Dedupe()
	if err != nil {
		t.Fatal(err)
	}
	if rep2.MergedCount != 0 {
		t.Errorf("second Dedupe MergedCount = %d, want 0", rep2.MergedCount)
	}
}

// TestMergeDoesNotAttachStaleProvenanceToAnotherKey is run-7 finding F9.
//
// mergeGroup took PGPKey from the newest duplicate but left the survivor's
// fingerprint/source/verified in place, producing a contact whose pin named a
// key it no longer held — "manual/verified" stamped onto whatever a later
// duplicate carried. Anything that can create a duplicate can reach it,
// including a hostile upstream CardDAV server, which cannot overwrite a local
// contact by UID but can certainly add one.
func TestMergeDoesNotAttachStaleProvenanceToAnotherKey(t *testing.T) {
	verified := Contact{
		UID: "victim", CreatedAt: "2026-01-01T00:00:00Z", Rev: 1,
		FormattedName: "Bob",
		Emails:        []ContactValue{{Value: "bob@example.com"}},
		PGPKey:        "VICTIM-KEY", PGPKeyFingerprint: "VICTIMFPR",
		PGPKeySource: "manual", PGPKeyVerified: true,
	}
	planted := Contact{
		UID: "attacker", CreatedAt: "2026-06-01T00:00:00Z", Rev: 2,
		FormattedName: "Bob",
		Emails:        []ContactValue{{Value: "bob@example.com"}},
		PGPKey:        "ATTACKER-KEY",
	}

	survivor, _ := mergeGroup([]Contact{verified, planted})

	if survivor.PGPKey != "VICTIM-KEY" {
		t.Errorf("a planted duplicate replaced a key the survivor already held: PGPKey = %q", survivor.PGPKey)
	}
	if survivor.PGPKeyFingerprint != "VICTIMFPR" || survivor.PGPKeySource != "manual" || !survivor.PGPKeyVerified {
		t.Errorf("the survivor's own provenance was disturbed: fpr=%q source=%q verified=%v",
			survivor.PGPKeyFingerprint, survivor.PGPKeySource, survivor.PGPKeyVerified)
	}
}

// A survivor with no key of its own still adopts one — together with the
// provenance that describes it, never the survivor's own.
func TestMergeAdoptsKeyAndItsProvenanceTogether(t *testing.T) {
	bare := Contact{
		UID: "bare", CreatedAt: "2026-01-01T00:00:00Z", Rev: 1,
		FormattedName: "Bob",
		Emails:        []ContactValue{{Value: "bob@example.com"}},
	}
	withKey := Contact{
		UID: "withkey", CreatedAt: "2026-06-01T00:00:00Z", Rev: 2,
		FormattedName: "Bob",
		Emails:        []ContactValue{{Value: "bob@example.com"}},
		PGPKey:        "SOME-KEY", PGPKeyFingerprint: "SOMEFPR", PGPKeySource: "wkd",
	}

	survivor, _ := mergeGroup([]Contact{bare, withKey})

	if survivor.PGPKey != "SOME-KEY" || survivor.PGPKeyFingerprint != "SOMEFPR" || survivor.PGPKeySource != "wkd" {
		t.Fatalf("key and provenance must move together: key=%q fpr=%q source=%q",
			survivor.PGPKey, survivor.PGPKeyFingerprint, survivor.PGPKeySource)
	}
}
