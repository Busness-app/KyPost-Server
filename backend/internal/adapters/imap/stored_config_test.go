package imap

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"kypost-server/backend/internal/cryptutil"
)

// The daemon reads the same IMAP config file the API writes, and used to accept
// it unencrypted. These tests pin the refusal: a plaintext or corrupt file is an
// error, an encrypted one round-trips.

func TestDecryptStoredPayloadRefusesPlaintext(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "imap-config.key")

	raw := []byte(`{"host":"imap.example.com","username":"u","password":"p"}`)
	if _, err := decryptStoredPayload(raw, keyPath); !errors.Is(err, cryptutil.ErrNotEncrypted) {
		t.Fatalf("expected ErrNotEncrypted for a plaintext config, got %v", err)
	}
}

func TestDecryptStoredPayloadRefusesCorruptEnvelope(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "imap-config.key")

	if _, err := decryptStoredPayload([]byte("not json at all"), keyPath); !errors.Is(err, cryptutil.ErrNotEncrypted) {
		t.Fatalf("expected ErrNotEncrypted for a corrupt config, got %v", err)
	}
}

func TestDecryptStoredPayloadReadsEncrypted(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "imap-config.key")

	want := `{"host":"imap.example.com","username":"u","password":"p"}`
	sealed, err := cryptutil.SealString(want, keyPath)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	got, err := decryptStoredPayload([]byte(sealed), keyPath)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("payload mismatch:\n got %s\nwant %s", got, want)
	}
}

// A plaintext config must fail the credential load loudly rather than
// authenticating from it, which is what the old fallback did.
func TestEnsureCredentialsRefusesPlaintextConfigFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "imap-config.json")
	keyPath := filepath.Join(dir, "imap-config.key")

	raw, err := json.Marshal(storedIMAPConfig{
		Host: "imap.example.com", Port: 993, Username: "u", Password: "p", Mailbox: "INBOX",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	c := &APIClient{configPath: configPath, configKeyPath: keyPath}
	err = c.ensureCredentialsFromStoredConfigLocked()
	if !errors.Is(err, cryptutil.ErrNotEncrypted) {
		t.Fatalf("expected ErrNotEncrypted, got %v", err)
	}
	if c.password != "" {
		t.Fatal("credentials were loaded from a plaintext config")
	}
}
