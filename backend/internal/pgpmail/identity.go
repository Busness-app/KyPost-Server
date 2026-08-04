// Package pgpmail implements OpenPGP encryption, signing, and key-identity
// management for the mail send/receive paths. All private key material is
// held in memory only for the duration of a request; callers persist it via
// SealPrivateKey (an AES-GCM envelope, the same pattern as
// mfa.SealTOTPSecret) and never write unsealed key material to disk.
package pgpmail

import (
	"errors"
	"fmt"
	"strings"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/gopenpgp/v3/crypto"

	"kypost-server/backend/internal/cryptutil"
)

// Identity holds one OpenPGP keypair loaded in memory: a user's own private
// identity, used for decrypting and signing. Recipients' public keys are
// passed around as plain armored strings (Contact.PGPKey) since they never
// need decrypt/sign and so never need this type.
type Identity struct {
	Fingerprint      string
	KeyID            string
	ArmoredPublicKey string

	key *crypto.Key
}

// normalizeAddress lowercases and trims an email address for User ID
// comparison, matching how the address-binding checks elsewhere (WKD's
// validateDiscoveredKey, Autocrypt's buildAutocryptHeader) normalize before
// matching a key's User IDs against a mail address.
func normalizeAddress(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// hasUserIDEmail reports whether entity already carries target (already
// normalized) as the email of one of its User IDs.
func hasUserIDEmail(entity *openpgp.Entity, target string) bool {
	for _, uid := range entity.Identities {
		if normalizeAddress(uid.UserId.Email) == target {
			return true
		}
	}
	return false
}

// ArmoredKeyCertifiesAddress reports whether the armored public key carries
// address as the PARSED email of one of its User IDs.
//
// The parsed email, never a substring of the raw User-ID text. A User ID is
// free-form and self-certified, so "the sender's address appears somewhere in
// it" proves nothing: a UID of
//
//	Mallory <mallory@evil.example> aka Bob <bob@example.com>
//
// contains bob@example.com but parses — here and in every other binding check in
// this codebase — as mallory@evil.example. Matching on the parsed field is what
// makes this agree with the checks that decide which contact a key is pinned to.
//
// An unparseable or absent key returns false: it certifies nothing.
func ArmoredKeyCertifiesAddress(armoredPublicKey, address string) bool {
	target := normalizeAddress(address)
	if target == "" || strings.TrimSpace(armoredPublicKey) == "" {
		return false
	}
	key, err := crypto.NewKeyFromArmored(armoredPublicKey)
	if err != nil {
		return false
	}
	entity := key.GetEntity()
	if entity == nil {
		return false
	}
	return hasUserIDEmail(entity, target)
}

// GenerateIdentity creates a new OpenPGP keypair for name/email using
// gopenpgp's default profile (EdDSA/Curve25519 + SHA256, RFC4880-compatible
// and interoperable with the openpgp.js keys already used client-side for
// contacts).
//
// email becomes the primary User ID; each of additionalEmails becomes a
// further User ID on the same key, so one key can be published and
// advertised for every address its owner actually sends and receives as
// (WKD serving and Autocrypt both require the key to carry the address in
// question as a User ID). Blank entries and addresses already covered —
// case-insensitively, including email itself — are skipped rather than
// producing duplicate or empty User IDs.
func GenerateIdentity(name, email string, additionalEmails ...string) (*Identity, error) {
	gen := crypto.PGP().KeyGeneration().AddUserId(name, email)
	seen := map[string]bool{normalizeAddress(email): true}
	for _, extra := range additionalEmails {
		addr := normalizeAddress(extra)
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		gen = gen.AddUserId(name, addr)
	}
	key, err := gen.New().GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("pgpmail: generate key: %w", err)
	}
	return identityFromKey(key)
}

// UserIDEmails returns the normalized email of every User ID carried by an
// armored public (or private) key. It reads only public material, which is
// what makes it usable as a cheap gate: callers can decide whether a key
// already covers a set of addresses before paying to unseal and parse the
// private key.
func UserIDEmails(armoredKey string) ([]string, error) {
	key, err := crypto.NewKeyFromArmored(armoredKey)
	if err != nil {
		return nil, fmt.Errorf("pgpmail: parse key: %w", err)
	}
	entity := key.GetEntity()
	if entity == nil {
		return nil, errors.New("pgpmail: key has no entity")
	}
	out := make([]string, 0, len(entity.Identities))
	for _, uid := range entity.Identities {
		out = append(out, normalizeAddress(uid.UserId.Email))
	}
	return out, nil
}

// AddUserID self-signs an additional User ID for email onto an existing
// key, keeping the same primary key and therefore the same fingerprint —
// this is what lets a send-as alias verified *after* key generation still be
// published over WKD and advertised via Autocrypt, both of which refuse a
// key that does not carry the address as a User ID.
//
// It returns added=false with a nil error when the key already carries the
// address, so callers can skip the re-seal/persist. Callers MUST persist the
// updated ArmoredPublicKey and a freshly sealed private key afterwards; this
// only mutates the in-memory identity.
func (id *Identity) AddUserID(name, email string) (bool, error) {
	target := normalizeAddress(email)
	if target == "" {
		return false, errors.New("pgpmail: cannot add an empty user id email")
	}
	entity := id.key.GetEntity()
	if entity == nil {
		return false, errors.New("pgpmail: key has no entity")
	}
	if hasUserIDEmail(entity, target) {
		return false, nil
	}
	if err := entity.AddUserId(name, "", target, nil); err != nil {
		return false, fmt.Errorf("pgpmail: add user id: %w", err)
	}
	armoredPub, err := id.key.GetArmoredPublicKey()
	if err != nil {
		return false, fmt.Errorf("pgpmail: armor public key: %w", err)
	}
	id.ArmoredPublicKey = armoredPub
	return true, nil
}

// ImportIdentity parses an armored private key, unlocking it with passphrase
// if it is passphrase-protected (pass "" for an unprotected key).
func ImportIdentity(armoredPrivateKey, passphrase string) (*Identity, error) {
	key, err := crypto.NewPrivateKeyFromArmored(armoredPrivateKey, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("pgpmail: unlock private key: %w", err)
	}
	if !key.IsPrivate() {
		return nil, errors.New("pgpmail: armored key does not contain private key material")
	}
	return identityFromKey(key)
}

func identityFromKey(key *crypto.Key) (*Identity, error) {
	armoredPub, err := key.GetArmoredPublicKey()
	if err != nil {
		return nil, fmt.Errorf("pgpmail: armor public key: %w", err)
	}
	return &Identity{
		Fingerprint:      key.GetFingerprint(),
		KeyID:            key.GetHexKeyID(),
		ArmoredPublicKey: armoredPub,
		key:              key,
	}, nil
}

// SealPrivateKey AES-GCM seals the identity's private key with the master
// key at keyPath (creating the key on first use) and returns the JSON
// envelope as a string, ready to store on User.PGPPrivateKeyEnc. The armored
// form stored inside the envelope is unprotected (no passphrase) — the
// envelope's AES-GCM key is the sole protection, matching how
// mfa.SealTOTPSecret protects TOTP secrets.
func (id *Identity) SealPrivateKey(keyPath string) (string, error) {
	armored, err := id.key.Armor()
	if err != nil {
		return "", fmt.Errorf("pgpmail: armor private key: %w", err)
	}
	return cryptutil.SealString(armored, keyPath)
}

// OpenPrivateKey reverses SealPrivateKey, returning a usable Identity.
// Mirrors mfa.OpenTOTPSecret.
func OpenPrivateKey(enc, keyPath string) (*Identity, error) {
	armored, err := cryptutil.OpenString(enc, keyPath, errors.New("pgpmail: private key is not a valid envelope"))
	if err != nil {
		return nil, err
	}
	unlockedKey, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		return nil, fmt.Errorf("pgpmail: parse stored private key: %w", err)
	}
	return identityFromKey(unlockedKey)
}

// PublicKeyInfo describes an armored public key well enough to store it as
// a user's identity, without ever seeing the matching private key.
type PublicKeyInfo struct {
	Fingerprint string
	KeyID       string
	// ArmoredPublicKey is the re-armored key, not the caller's input: the
	// stored form is whatever this library produces from the parsed key, so
	// a client cannot smuggle trailing data past the parser by wrapping it
	// in an armor block the parser tolerates.
	ArmoredPublicKey string
}

// InspectPublicKey parses an armored public key and reports its identifying
// fields.
//
// This exists for the client-protected key flow: the browser generates the
// keypair, wraps the private half itself, and uploads only the public half
// plus an opaque wrapped blob. The server must therefore derive the
// fingerprint and key ID from the key it was actually given rather than
// believing whatever the client claimed them to be — a client that could
// assert an arbitrary fingerprint could get its own key published under
// another key's identity via WKD or Autocrypt.
func InspectPublicKey(armoredPublicKey string) (PublicKeyInfo, error) {
	key, err := crypto.NewKeyFromArmored(strings.TrimSpace(armoredPublicKey))
	if err != nil {
		return PublicKeyInfo{}, fmt.Errorf("pgpmail: parse public key: %w", err)
	}
	if key.IsPrivate() {
		// A private key here means the client uploaded the wrong half. Refuse
		// rather than quietly storing a private key in a public field.
		return PublicKeyInfo{}, errors.New("pgpmail: expected a public key, got a private key")
	}
	armored, err := key.GetArmoredPublicKey()
	if err != nil {
		return PublicKeyInfo{}, fmt.Errorf("pgpmail: armor public key: %w", err)
	}
	return PublicKeyInfo{
		Fingerprint:      key.GetFingerprint(),
		KeyID:            key.GetHexKeyID(),
		ArmoredPublicKey: armored,
	}, nil
}

// ExportArmoredPrivateKey returns the identity's armored private key.
//
// The only caller is the one-time migration that hands a legacy
// server-sealed key back to its owner's browser so the browser can rewrap it
// under a key the server does not have. It is deliberately a distinct,
// awkwardly-named method rather than a field: exporting a private key is
// not something any other code path should reach for by accident.
func (id *Identity) ExportArmoredPrivateKey() (string, error) {
	armored, err := id.key.Armor()
	if err != nil {
		return "", fmt.Errorf("pgpmail: armor private key: %w", err)
	}
	return armored, nil
}
