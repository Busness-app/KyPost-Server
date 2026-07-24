package api

import (
	"context"
	"strings"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpdiscovery"
	"kypost-server/backend/internal/pgpmail"
)

// resolveTier identifies which rung of the discovery ladder produced a
// resolvedKey, so callers (send-time encryption, UI) can decide whether to
// use the key silently, prompt for confirmation, or send unencrypted.
type resolveTier string

const (
	// tierContactVerified is a usable key already pinned to a local contact
	// — used silently, no discovery performed.
	tierContactVerified resolveTier = "verified"
	// tierWKD is a key freshly discovered via Web Key Directory — auto-
	// trusted (the sender's own domain vouches for it) and pinned when
	// settings.StoreDiscoveredKeys is set.
	tierWKD resolveTier = "wkd"
	// tierKeyserverConfirm is a key found on a public keyserver — these are
	// unauthenticated by anyone the sender already trusts, so the caller
	// must get explicit user confirmation before it is pinned or used.
	tierKeyserverConfirm resolveTier = "keyserver_confirm"
	// tierKeyChanged means discovery found a key for this address whose
	// fingerprint differs from the one already pinned to the contact — a
	// TOFU (trust-on-first-use) violation. The resolver refuses to switch;
	// the caller must not encrypt to the newly discovered key.
	tierKeyChanged resolveTier = "key_changed"
	// tierNone means no usable key could be resolved by any means.
	tierNone resolveTier = "none"
)

// resolvedKey is the outcome of running the discovery ladder for one
// recipient address.
type resolvedKey struct {
	Armored     string
	Fingerprint string
	Tier        resolveTier
	Usable      bool
}

// keyResolver runs the PGP key discovery ladder — pinned contact key → WKD
// → keyserver — for one user's outgoing mail, honoring that user's
// pgpdiscovery.Settings and TOFU pinning against their contacts store.
type keyResolver struct {
	store    *contacts.Store
	settings pgpdiscovery.Settings
	// discover gates whether WKD/keyserver lookups run at all; false means
	// only the already-pinned contact key is considered (e.g. discovery
	// disabled by policy, or a caller that only wants the local view).
	discover bool
	// suppressed is the set of normalized addresses the user has opted out of
	// discovery. A suppressed address does no WKD/keyserver lookup, pin, or
	// auto-create — it falls through to the pickup path. A key the user
	// already holds (resolve step 1) is unaffected.
	suppressed map[string]bool
}

// findContact returns the first contact whose email matches, case-
// insensitively. Unlike findContactPGPKey (server.go), this returns the
// whole Contact so callers can inspect/update provenance fields beyond
// PGPKey.
func findContact(store *contacts.Store, email string) (contacts.Contact, bool) {
	target := strings.ToLower(strings.TrimSpace(email))
	for _, c := range store.List() {
		for _, e := range c.Emails {
			if strings.ToLower(strings.TrimSpace(e.Value)) == target {
				return c, true
			}
		}
	}
	return contacts.Contact{}, false
}

// pin writes a discovered key + provenance to the matching contact,
// creating a minimal contact if none exists yet. Upsert assigns a UID when
// c.UID is empty. Marks the key unverified — WKD/keyserver discovery is
// TOFU, not eyeball verification — unless the discovered fingerprint matches
// the fingerprint already pinned to the contact, in which case this is just
// a refresh of the same key and any existing source/verified provenance
// (e.g. a manual, eyeball-verified pin) is preserved rather than downgraded.
func (kr *keyResolver) pin(email, armored, fingerprint, source string) {
	c, ok := findContact(kr.store, email)
	if !ok {
		c = contacts.Contact{
			FormattedName:    email,
			Emails:           []contacts.ContactValue{{Value: email}},
			DiscoveryCreated: true,
		}
	}
	sameKey := ok && c.PGPKeyFingerprint != "" && strings.EqualFold(c.PGPKeyFingerprint, fingerprint)
	c.PGPKey = armored
	c.PGPKeyFingerprint = fingerprint
	if !sameKey {
		c.PGPKeySource = source
		c.PGPKeyVerified = false
	}
	// best-effort pin; a valid key still encrypts this send even if
	// persistence fails
	_, _ = kr.store.Upsert(c)
}

// resolve runs the discovery ladder for one recipient:
//
//  1. A usable key already pinned to a contact wins immediately, silently
//     (tierContactVerified) — no network calls.
//  2. Otherwise, if discover is enabled, try WKD. A validated hit is
//     auto-trusted (tierWKD) and pinned when settings.StoreDiscoveredKeys.
//  3. Otherwise, if discover is enabled, try a public keyserver. A usable
//     hit needs explicit user confirmation before use (tierKeyserverConfirm)
//     — it is not pinned by this call.
//  4. In steps 2/3, if the contact already had a pinned fingerprint that
//     differs from the newly discovered one, the resolver refuses to
//     switch: tierKeyChanged, Usable:false. This only triggers once the
//     previously pinned key has stopped being usable (revoked/expired) and
//     something else now serves a different key for the same address — a
//     still-usable pinned key is trusted as-is in step 1 and discovery
//     never runs.
//  5. Otherwise, tierNone.
func (kr *keyResolver) resolve(ctx context.Context, email string) resolvedKey {
	c, hasContact := findContact(kr.store, email)
	pinnedFP := ""
	if hasContact && c.PGPKey != "" {
		if st, err := pgpmail.CheckKeyStatus(c.PGPKey); err == nil && st.Usable() {
			return resolvedKey{Armored: c.PGPKey, Fingerprint: c.PGPKeyFingerprint, Tier: tierContactVerified, Usable: true}
		}
		pinnedFP = c.PGPKeyFingerprint
	}
	if !kr.discover {
		return resolvedKey{Tier: tierNone}
	}

	if kr.suppressed[strings.ToLower(strings.TrimSpace(email))] {
		return resolvedKey{Tier: tierNone}
	}

	if armored, fp, err := fetchWKDKey(ctx, email); err == nil {
		if pinnedFP != "" && !strings.EqualFold(pinnedFP, fp) {
			return resolvedKey{Tier: tierKeyChanged}
		}
		if kr.settings.StoreDiscoveredKeys {
			kr.pin(email, armored, fp, contacts.PGPSourceWKD)
		}
		return resolvedKey{Armored: armored, Fingerprint: fp, Tier: tierWKD, Usable: true}
	}

	if _, fp, st, err := keyserverLookup(ctx, email); err == nil && st.Usable() {
		if pinnedFP != "" && !strings.EqualFold(pinnedFP, fp) {
			return resolvedKey{Tier: tierKeyChanged}
		}
		return resolvedKey{Fingerprint: fp, Tier: tierKeyserverConfirm}
	}

	return resolvedKey{Tier: tierNone}
}
