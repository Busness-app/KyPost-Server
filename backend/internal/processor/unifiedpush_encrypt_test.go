package processor

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"kypost-server/backend/internal/state"
)

// --- receiver side of RFC 8291 / RFC 8188 ---------------------------------
//
// The Android UnifiedPush connector drops any message it cannot decrypt
// (message.decrypted == false), which is precisely the failure this change
// exists to fix. Asserting a Content-Encoding header would not catch a wrong
// HKDF info string or a swapped key order — the request would still look
// right and the client would still discard it. So the test decrypts, the way
// the connector does, and compares plaintext.

// decryptAES128GCM reverses RFC 8188 aes128gcm for a single-record body, using
// the RFC 8291 key derivation. Returns the plaintext with padding removed.
func decryptAES128GCM(t *testing.T, body []byte, uaPrivate *ecdh.PrivateKey, authSecret []byte) []byte {
	t.Helper()
	// Header: salt(16) || rs(4) || idlen(1) || keyid(idlen)
	if len(body) < 21 {
		t.Fatalf("body too short for an aes128gcm header: %d bytes", len(body))
	}
	salt := body[:16]
	idLen := int(body[20])
	if len(body) < 21+idLen {
		t.Fatalf("body too short for keyid of %d bytes", idLen)
	}
	asPublicBytes := body[21 : 21+idLen]
	ciphertext := body[21+idLen:]

	asPublic, err := ecdh.P256().NewPublicKey(asPublicBytes)
	if err != nil {
		t.Fatalf("keyid is not a P-256 point: %v", err)
	}
	shared, err := uaPrivate.ECDH(asPublic)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}

	uaPublicBytes := uaPrivate.PublicKey().Bytes()

	// RFC 8291 §3.3: PRK_key = HMAC(auth_secret, ecdh_secret), then
	// IKM = HKDF-Expand(PRK_key, "WebPush: info" || 0x00 || ua_public || as_public, 32)
	prkKey := hmacSHA256(authSecret, shared)
	keyInfo := append([]byte("WebPush: info\x00"), uaPublicBytes...)
	keyInfo = append(keyInfo, asPublicBytes...)
	ikm := hkdfExpand(prkKey, keyInfo, 32)

	// RFC 8188 §2.2: PRK = HMAC(salt, IKM); CEK and NONCE expand from it.
	prk := hmacSHA256(salt, ikm)
	cek := hkdfExpand(prk, []byte("Content-Encoding: aes128gcm\x00"), 16)
	nonce := hkdfExpand(prk, []byte("Content-Encoding: nonce\x00"), 12)

	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	padded, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("GCM open failed — the client would have dropped this message: %v", err)
	}

	// Strip the RFC 8188 padding delimiter (0x02 on the last record) and any
	// trailing zero padding after it.
	for i := len(padded) - 1; i >= 0; i-- {
		if padded[i] == 0 {
			continue
		}
		if padded[i] != 1 && padded[i] != 2 {
			t.Fatalf("unexpected padding delimiter 0x%02x", padded[i])
		}
		return padded[:i]
	}
	t.Fatal("no padding delimiter found")
	return nil
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// hkdfExpand is HKDF-Expand with SHA-256 for outputs of at most one block,
// which is all RFC 8188 and RFC 8291 ever ask for.
func hkdfExpand(prk, info []byte, length int) []byte {
	if length > sha256.Size {
		panic("hkdfExpand: length exceeds one block")
	}
	return hmacSHA256(prk, append(append([]byte{}, info...), 0x01))[:length]
}

// --- test fixtures --------------------------------------------------------

// writeVAPIDKeyFile generates a VAPID keypair, writes the private half as the
// SEC1 PEM that config.LoadVAPIDPrivateKey expects, and returns the file path
// alongside the base64url public key.
func writeVAPIDKeyFile(t *testing.T) (privateKeyPath, publicKey string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "vapid.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	pub := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y) //nolint:staticcheck // matches config.ensureNotificationKeyMaterial
	return path, base64.RawURLEncoding.EncodeToString(pub)
}

// --- the tests ------------------------------------------------------------

// A device that supplied WebPush keys must receive ciphertext the connector
// can actually open, not plaintext JSON on a public broker.
func TestUnifiedPushSenderEncryptsWhenDeviceHasKeys(t *testing.T) {
	uaPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	authSecret := make([]byte, 16)
	if _, err := rand.Read(authSecret); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	var seenBody []byte
	var seenEncoding string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenEncoding = r.Header.Get("Content-Encoding")
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	keyPath, publicKey := writeVAPIDKeyFile(t)
	sender := NewUnifiedPushSender(nil, publicKey, keyPath)
	sender.client = ts.Client()

	device := state.NativeDevice{
		PushToken: ts.URL + "/topic",
		Transport: "unifiedpush",
		P256DH:    base64.RawURLEncoding.EncodeToString(uaPrivate.PublicKey().Bytes()),
		Auth:      base64.RawURLEncoding.EncodeToString(authSecret),
	}
	message := NativePushMessage{Title: "Title", Body: "Body", Data: map[string]string{"type": "mail"}}

	if err := sender.Send(context.Background(), device, message); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if seenEncoding != "aes128gcm" {
		t.Fatalf("Content-Encoding = %q, want aes128gcm", seenEncoding)
	}
	if json.Valid(seenBody) {
		t.Fatal("body parsed as JSON — the payload went out in the clear")
	}

	plaintext := decryptAES128GCM(t, seenBody, uaPrivate, authSecret)
	var got map[string]any
	if err := json.Unmarshal(plaintext, &got); err != nil {
		t.Fatalf("decrypted payload is not JSON: %v (%q)", err, plaintext)
	}
	if got["title"] != "Title" || got["body"] != "Body" {
		t.Fatalf("decrypted payload = %+v, want title/body preserved", got)
	}
	data, ok := got["data"].(map[string]any)
	if !ok || data["type"] != "mail" {
		t.Fatalf("decrypted data = %+v, want type=mail", got["data"])
	}
}

// A device registered by an older client, or through a distributor whose
// connector supplied no key material, keeps working exactly as it does today.
func TestUnifiedPushSenderFallsBackToPlaintextWithoutDeviceKeys(t *testing.T) {
	var seenBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &seenBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	keyPath, publicKey := writeVAPIDKeyFile(t)
	sender := NewUnifiedPushSender(nil, publicKey, keyPath)
	sender.client = ts.Client()

	err := sender.Send(context.Background(),
		state.NativeDevice{PushToken: ts.URL + "/topic", Transport: "unifiedpush"},
		NativePushMessage{Title: "Title", Body: "Body"})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if seenBody["title"] != "Title" {
		t.Fatalf("plaintext fallback body = %+v", seenBody)
	}
}

// A server whose VAPID private key cannot be read must still deliver. Losing
// encryption is bad; losing every notification is worse, and the operator sees
// the load failure in the log either way.
func TestUnifiedPushSenderFallsBackToPlaintextWithoutVAPIDKey(t *testing.T) {
	uaPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	authSecret := make([]byte, 16)
	if _, err := rand.Read(authSecret); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	var seenBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &seenBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sender := NewUnifiedPushSender(nil, "", filepath.Join(t.TempDir(), "does-not-exist.pem"))
	sender.client = ts.Client()

	err = sender.Send(context.Background(), state.NativeDevice{
		PushToken: ts.URL + "/topic",
		Transport: "unifiedpush",
		P256DH:    base64.RawURLEncoding.EncodeToString(uaPrivate.PublicKey().Bytes()),
		Auth:      base64.RawURLEncoding.EncodeToString(authSecret),
	}, NativePushMessage{Title: "Title", Body: "Body"})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if seenBody["title"] != "Title" {
		t.Fatalf("plaintext fallback body = %+v", seenBody)
	}
}

// 404/410 means the topic is gone. Stale detection must behave identically on
// the encrypted path, or a dead endpoint is retried forever.
func TestUnifiedPushSenderEncryptedPathReportsStale(t *testing.T) {
	uaPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	authSecret := make([]byte, 16)
	if _, err := rand.Read(authSecret); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	for _, status := range []int{http.StatusNotFound, http.StatusGone} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer ts.Close()

			keyPath, publicKey := writeVAPIDKeyFile(t)
			sender := NewUnifiedPushSender(nil, publicKey, keyPath)
			sender.client = ts.Client()

			err := sender.Send(context.Background(), state.NativeDevice{
				PushToken: ts.URL + "/topic",
				Transport: "unifiedpush",
				P256DH:    base64.RawURLEncoding.EncodeToString(uaPrivate.PublicKey().Bytes()),
				Auth:      base64.RawURLEncoding.EncodeToString(authSecret),
			}, NativePushMessage{Title: "Title"})
			if !errors.Is(err, ErrNativeDeviceStale) {
				t.Fatalf("Send() error = %v, want ErrNativeDeviceStale", err)
			}
		})
	}
}

// The encrypted path must keep the SSRF-hardened client, not webpush-go's
// default one — a redirect to a private address otherwise bypasses every
// check UnifiedPushSender exists to enforce.
func TestUnifiedPushSenderEncryptedPathRefusesNonHTTPS(t *testing.T) {
	keyPath, publicKey := writeVAPIDKeyFile(t)
	sender := NewUnifiedPushSender(nil, publicKey, keyPath)

	uaPrivate, _ := ecdh.P256().GenerateKey(rand.Reader)
	authSecret := make([]byte, 16)
	_, _ = rand.Read(authSecret)

	err := sender.Send(context.Background(), state.NativeDevice{
		PushToken: "http://example.com/topic",
		Transport: "unifiedpush",
		P256DH:    base64.RawURLEncoding.EncodeToString(uaPrivate.PublicKey().Bytes()),
		Auth:      base64.RawURLEncoding.EncodeToString(authSecret),
	}, NativePushMessage{Title: "Title"})
	if err == nil {
		t.Fatal("Send() to an http endpoint succeeded, want an error")
	}
}
