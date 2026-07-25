// Package cryptutil provides the shared AES-GCM "envelope" encrypt/decrypt
// primitives used to protect credentials and other sensitive payloads at
// rest (IMAP credentials, notification keys, etc). It is a leaf package with
// no dependencies on the rest of this codebase besides fsutil.
package cryptutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"kypost-server/backend/internal/fsutil"
)

// EncryptedPayload is the on-disk envelope format for an AES-GCM sealed
// payload.
type EncryptedPayload struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// ParseEnvelope parses raw as an EncryptedPayload. ok is false when raw does
// not unmarshal as a well-formed version-1 envelope (missing nonce/
// ciphertext, or an unrecognized version) — callers use this to fall back to
// treating raw as plaintext for backward compatibility with data written
// before encryption-at-rest was introduced.
func ParseEnvelope(raw []byte) (EncryptedPayload, bool) {
	var env EncryptedPayload
	if err := json.Unmarshal(raw, &env); err != nil || env.Version != 1 || strings.TrimSpace(env.Nonce) == "" || strings.TrimSpace(env.Ciphertext) == "" {
		return EncryptedPayload{}, false
	}
	return env, true
}

// keyGenMu serializes the create-on-first-use path in LoadOrCreateKey below.
// Without it, two concurrent callers racing the same not-yet-created key
// path (e.g. two different users both configuring IMAP moments after a fresh
// deploy) could each read os.ErrNotExist before either has written, each
// generate a different random key, and each seal their own data under a key
// that never gets persisted — silently and permanently orphaning whichever
// caller's write loses the race. One process-wide mutex is enough: key
// creation happens at most once per path ever, so contention is negligible.
var keyGenMu sync.Mutex

// LoadOrCreateKey reads the 32-byte base64-encoded master key at path,
// generating and persisting a new random one via fsutil.AtomicWriteFile if
// the file does not yet exist. Only callers that are allowed to originate
// the master key (the api process) should use this; other processes must
// use LoadKey so they never race-create a key the owning process didn't
// expect.
func LoadOrCreateKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		return decodeKey(b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	keyGenMu.Lock()
	defer keyGenMu.Unlock()

	// Re-check now that we hold the lock: another goroutine may have created
	// the file while we were waiting.
	if b, err := os.ReadFile(path); err == nil {
		return decodeKey(b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(key))
	if err := fsutil.AtomicWriteFile(path, encoded, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// LoadKey reads the 32-byte base64-encoded master key at path. Unlike
// LoadOrCreateKey, it never creates the file — it errors if the key is
// missing.
func LoadKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeKey(b)
}

func decodeKey(raw []byte) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	if len(decoded) != 32 {
		return nil, errors.New("invalid encryption master key length")
	}
	return decoded, nil
}

// Seal AES-GCM encrypts payload with key, returning the envelope ready to be
// marshaled to disk.
func Seal(payload, key []byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedPayload{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}

	sealed := gcm.Seal(nil, nonce, payload, nil)
	return EncryptedPayload{
		Version:    1,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(sealed),
	}, nil
}

// SealString AES-GCM seals plaintext with the master key at keyPath
// (creating the key on first use) and returns the JSON envelope as a
// string, ready to persist. Shared by every caller that seals a single
// secret string as an encrypted-at-rest envelope (PGP private keys, TOTP
// secrets).
func SealString(plaintext, keyPath string) (string, error) {
	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		return "", err
	}
	env, err := Seal([]byte(plaintext), key)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// OpenString reverses SealString, returning the plaintext. errNotEnvelope is
// returned verbatim when enc isn't a well-formed envelope, so callers can
// supply their own contextual message.
// It uses LoadKey, never LoadOrCreateKey: creating a master key on a
// decrypt path is how a missing/unmounted SECRET_DIR turns a loud "the key
// is gone" into a silent catastrophe. LoadOrCreateKey would mint a fresh
// random key, fail GCM authentication on every existing secret, and then
// leave the next SealString writing real data under the new key — half the
// volume encrypted under one key and half under another, with no way to
// tell which is which and no way back. LoadOrCreateKey's own doc comment
// restricts it to callers allowed to originate the key; this is not one.
func OpenString(enc, keyPath string, errNotEnvelope error) (string, error) {
	env, ok := ParseEnvelope([]byte(enc))
	if !ok {
		return "", errNotEnvelope
	}
	key, err := LoadKey(keyPath)
	if err != nil {
		return "", fmt.Errorf("load master key %s: %w", keyPath, err)
	}
	plain, err := Open(env, key)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ErrNotEncrypted reports that a stored payload is not a well-formed
// encryption envelope — it was written before encryption-at-rest existed,
// or it is corrupt.
var ErrNotEncrypted = errors.New("stored payload is not encrypted")

// OpenBytes decrypts a stored payload written as a marshaled
// EncryptedPayload, returning ErrNotEncrypted if raw is not one.
//
// It deliberately does NOT fall back to returning raw as plaintext. That
// fallback previously existed here (twice, copy-pasted) under a
// "backward-compatibility with plaintext credentials" comment, and a comment
// that exists to justify code is a sign the code is wrong: it made
// encryption-at-rest permanently optional and unenforced. Nothing ever
// re-encrypted the legacy file, nothing logged, and nothing could tell a
// legacy plaintext config apart from a corrupt one — so an IMAP password
// could sit in cleartext on disk forever while every call site reported
// success. Failing here is loud, loses nothing (the file is untouched), and
// has an obvious remedy: re-save the credentials once.
func OpenBytes(raw []byte, keyPath string) ([]byte, error) {
	env, ok := ParseEnvelope(raw)
	if !ok {
		return nil, ErrNotEncrypted
	}
	key, err := LoadKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load master key %s: %w", keyPath, err)
	}
	return Open(env, key)
}

// Open AES-GCM decrypts env with key.
func Open(env EncryptedPayload, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
