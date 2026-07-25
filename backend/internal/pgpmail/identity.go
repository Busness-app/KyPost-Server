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
