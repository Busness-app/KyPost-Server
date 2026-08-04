package contacts

import (
	"sort"
	"strings"
)

// normalizeEmail lowercases and trims an email so "Foo@Bar.COM" and
// " foo@bar.com " compare equal.
func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// normalizePhone reduces a phone number to comparable digits. It keeps only
// digits and, when there are at least ten, compares on the last ten so
// "+1 (555) 123-4567" matches "555-123-4567".
//
// ponytail: naive heuristic, no libphonenumber. Ceiling: numbers that differ
// only outside the last ten digits collide, and extensions are ignored.
func normalizePhone(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteByte(byte(r))
		}
	}
	d := b.String()
	if len(d) >= 10 {
		return d[len(d)-10:]
	}
	return d
}

func normalizeName(c Contact) string {
	return strings.ToLower(strings.Join(strings.Fields(c.FormattedName), " "))
}

// otherwiseEmpty reports whether a contact carries no email or phone, so its
// name is the only thing left to match on.
func otherwiseEmpty(c Contact) bool {
	return len(c.Emails) == 0 && len(c.Phones) == 0
}

// matchKeys returns the normalized email/phone values a contact can be matched
// by (blank values excluded).
func matchKeys(c Contact) []string {
	keys := make([]string, 0, len(c.Emails)+len(c.Phones))
	for _, e := range c.Emails {
		if v := normalizeEmail(e.Value); v != "" {
			keys = append(keys, "e:"+v)
		}
	}
	for _, p := range c.Phones {
		if v := normalizePhone(p.Value); v != "" {
			keys = append(keys, "p:"+v)
		}
	}
	return keys
}

// findDuplicateGroups returns the connected components (size >= 2) of the graph
// where two contacts are joined if they share a normalized email or phone, or
// share a normalized name when at least one of them is otherwiseEmpty. Each
// returned group is a sorted list of indices into cs; groups are ordered by
// their first index. The name-guard for larger components is applied separately
// by groupShouldMerge.
func findDuplicateGroups(cs []Contact) [][]int {
	uf := newUnionFind(len(cs))

	// Union everything sharing an email or phone key.
	byKey := map[string]int{}
	for i, c := range cs {
		for _, k := range matchKeys(c) {
			if j, ok := byKey[k]; ok {
				uf.union(i, j)
			} else {
				byKey[k] = i
			}
		}
	}

	// Union on name only when at least one side is otherwiseEmpty.
	byName := map[string][]int{}
	for i, c := range cs {
		if n := normalizeName(c); n != "" {
			byName[n] = append(byName[n], i)
		}
	}
	for _, idxs := range byName {
		for a := 0; a < len(idxs); a++ {
			for b := a + 1; b < len(idxs); b++ {
				if otherwiseEmpty(cs[idxs[a]]) || otherwiseEmpty(cs[idxs[b]]) {
					uf.union(idxs[a], idxs[b])
				}
			}
		}
	}

	comps := map[int][]int{}
	for i := range cs {
		r := uf.find(i)
		comps[r] = append(comps[r], i)
	}
	groups := make([][]int, 0)
	for _, members := range comps {
		if len(members) < 2 {
			continue
		}
		sort.Ints(members)
		groups = append(groups, members)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i][0] < groups[j][0] })
	return groups
}

// groupShouldMerge decides whether a connected component should be merged. A
// direct pair (size 2) always merges. A larger, chained/bridged component only
// merges when every member shares one non-empty normalized name, guarding
// against over-merging distinct people who happen to share a value.
func groupShouldMerge(members []Contact) bool {
	if len(members) < 2 {
		return false
	}
	if len(members) == 2 {
		return true
	}
	name := normalizeName(members[0])
	if name == "" {
		return false
	}
	for _, m := range members[1:] {
		if normalizeName(m) != name {
			return false
		}
	}
	return true
}

// mergeGroup folds a group into one survivor. The survivor is the oldest member
// (earliest CreatedAt, tie-broken by lowest Rev then UID); it keeps its own UID
// and CreatedAt. Multi-value fields are unioned and de-duped; scalar fields take
// the most-recently-updated non-empty value. absorbed is the sorted list of the
// other members' UIDs. Rev/UpdatedAt are left for the store to stamp.
func mergeGroup(members []Contact) (survivor Contact, absorbed []string) {
	ordered := append([]Contact(nil), members...)
	sort.Slice(ordered, func(i, j int) bool { return olderThan(ordered[i], ordered[j]) })
	survivor = ordered[0]

	for _, m := range ordered[1:] {
		absorbed = append(absorbed, m.UID)
	}
	sort.Strings(absorbed)

	// Newest-first ordering drives scalar precedence.
	byNewest := append([]Contact(nil), members...)
	sort.Slice(byNewest, func(i, j int) bool { return newerThan(byNewest[i], byNewest[j]) })

	survivor.FormattedName = firstNonEmpty(byNewest, func(c Contact) string { return c.FormattedName })
	survivor.GivenName = firstNonEmpty(byNewest, func(c Contact) string { return c.GivenName })
	survivor.FamilyName = firstNonEmpty(byNewest, func(c Contact) string { return c.FamilyName })
	survivor.MiddleName = firstNonEmpty(byNewest, func(c Contact) string { return c.MiddleName })
	survivor.Prefix = firstNonEmpty(byNewest, func(c Contact) string { return c.Prefix })
	survivor.Suffix = firstNonEmpty(byNewest, func(c Contact) string { return c.Suffix })
	survivor.Nickname = firstNonEmpty(byNewest, func(c Contact) string { return c.Nickname })
	survivor.Org = firstNonEmpty(byNewest, func(c Contact) string { return c.Org })
	survivor.Title = firstNonEmpty(byNewest, func(c Contact) string { return c.Title })
	survivor.Notes = firstNonEmpty(byNewest, func(c Contact) string { return c.Notes })
	survivor.Birthday = firstNonEmpty(byNewest, func(c Contact) string { return c.Birthday })
	survivor.PhotoRef = firstNonEmpty(byNewest, func(c Contact) string { return c.PhotoRef })
	// The key and its provenance move together, or not at all.
	//
	// Taking PGPKey from the newest member while leaving the survivor's
	// fingerprint, source and verified flag in place left a contact whose pin
	// named a key it no longer held: "manual/verified" attached to whichever key
	// the newest duplicate happened to carry. That is the exact state
	// carryPGPProvenance calls "worse than dropping it" — tierKeyChanged then
	// compares against a fingerprint no key has — and it is reachable by anything
	// that can create a duplicate, including a hostile upstream CardDAV server,
	// which cannot overwrite a local contact by UID but can certainly add one.
	survivor.PGPKey, survivor.PGPKeyFingerprint, survivor.PGPKeySource, survivor.PGPKeyVerified =
		mergePGPProvenance(survivor, byNewest)
	survivor.PhoneticGivenName = firstNonEmpty(byNewest, func(c Contact) string { return c.PhoneticGivenName })
	survivor.PhoneticFamilyName = firstNonEmpty(byNewest, func(c Contact) string { return c.PhoneticFamilyName })
	survivor.Department = firstNonEmpty(byNewest, func(c Contact) string { return c.Department })
	survivor.Pronouns = firstNonEmpty(byNewest, func(c Contact) string { return c.Pronouns })

	survivor.Emails = unionValues(members, func(c Contact) []ContactValue { return c.Emails }, normalizeEmail)
	survivor.Phones = unionValues(members, func(c Contact) []ContactValue { return c.Phones }, normalizePhone)
	survivor.Addresses = unionAddresses(members)
	survivor.GroupIDs = unionStrings(members, func(c Contact) []string { return c.GroupIDs })
	survivor.IMs = unionComparable(members, func(c Contact) []ContactIM { return c.IMs })
	survivor.Websites = unionComparable(members, func(c Contact) []ContactURL { return c.Websites })
	survivor.Relations = unionComparable(members, func(c Contact) []ContactRelation { return c.Relations })
	survivor.Events = unionComparable(members, func(c Contact) []ContactEvent { return c.Events })
	survivor.CustomFields = unionComparable(members, func(c Contact) []ContactCustomField { return c.CustomFields })

	survivor.MergedUIDs = mergedUIDs(survivor, members, absorbed)
	survivor.MergedInto = ""
	return survivor, absorbed
}

func firstNonEmpty(cs []Contact, get func(Contact) string) string {
	for _, c := range cs {
		if v := get(c); v != "" {
			return v
		}
	}
	return ""
}

func unionValues(members []Contact, get func(Contact) []ContactValue, norm func(string) string) []ContactValue {
	seen := map[string]bool{}
	var out []ContactValue
	for _, c := range members {
		for _, v := range get(c) {
			key := norm(v.Value)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, v)
		}
	}
	return out
}

func unionStrings(members []Contact, get func(Contact) []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range members {
		for _, v := range get(c) {
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// unionComparable de-dupes and unions any slice-of-comparable-struct field
// (ContactIM, ContactURL, ContactRelation, ContactEvent, ContactCustomField
// all have only string fields, so equality is a plain value comparison).
func unionComparable[T comparable](members []Contact, get func(Contact) []T) []T {
	seen := map[T]bool{}
	var out []T
	for _, c := range members {
		for _, v := range get(c) {
			if seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func unionAddresses(members []Contact) []ContactAddress {
	seen := map[ContactAddress]bool{}
	var out []ContactAddress
	for _, c := range members {
		for _, a := range c.Addresses {
			if seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// mergedUIDs unions any pre-existing provenance with the absorbed UIDs, dropping
// the survivor's own UID, and returns a sorted, de-duped list.
func mergedUIDs(survivor Contact, members []Contact, absorbed []string) []string {
	set := map[string]bool{}
	add := func(u string) {
		if u != "" && u != survivor.UID {
			set[u] = true
		}
	}
	for _, u := range absorbed {
		add(u)
	}
	for _, m := range members {
		for _, u := range m.MergedUIDs {
			add(u)
		}
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// olderThan orders by earliest CreatedAt, tie-broken by lowest Rev then UID, to
// pick the most stable (most-referenced) survivor identity.
func olderThan(a, b Contact) bool {
	if a.CreatedAt != b.CreatedAt {
		return a.CreatedAt < b.CreatedAt
	}
	if a.Rev != b.Rev {
		return a.Rev < b.Rev
	}
	return a.UID < b.UID
}

// newerThan orders newest-first by UpdatedAt, tie-broken by higher Rev, for
// scalar-field precedence.
func newerThan(a, b Contact) bool {
	if a.UpdatedAt != b.UpdatedAt {
		return a.UpdatedAt > b.UpdatedAt
	}
	return a.Rev > b.Rev
}

type unionFind struct{ parent []int }

func newUnionFind(n int) *unionFind {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	return &unionFind{parent: p}
}

func (u *unionFind) find(x int) int {
	for u.parent[x] != x {
		u.parent[x] = u.parent[u.parent[x]]
		x = u.parent[x]
	}
	return x
}

func (u *unionFind) union(a, b int) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u.parent[rb] = ra
	}
}

// mergePGPProvenance picks the key a merged contact keeps, together with the
// provenance that describes THAT key.
//
// The survivor keeps its own key when it has one: a contact that was already
// carrying key material — very often one the user verified by hand — must not
// have it replaced by a duplicate that arrived later from a sync. Only when the
// survivor has no key at all does the newest member's key move across, and then
// its provenance moves with it.
func mergePGPProvenance(survivor Contact, byNewest []Contact) (key, fingerprint, source string, verified bool) {
	if survivor.PGPKey != "" {
		return survivor.PGPKey, survivor.PGPKeyFingerprint, survivor.PGPKeySource, survivor.PGPKeyVerified
	}
	for _, c := range byNewest {
		if c.PGPKey != "" {
			return c.PGPKey, c.PGPKeyFingerprint, c.PGPKeySource, c.PGPKeyVerified
		}
	}
	return "", "", "", false
}
