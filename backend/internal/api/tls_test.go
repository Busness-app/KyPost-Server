package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kypost-server/backend/internal/users"
)

// writeKeypair generates a self-signed certificate for cn and writes it to
// certPath/keyPath. Returns the certificate's serial so a test can tell one
// generation from the next.
func writeKeypair(t *testing.T, certPath, keyPath, cn string) *big.Int {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return serial
}

// TestTLSFilesFromEnvRequiresBoth is the fail-closed rule. An operator who set
// one of the two believes the port is encrypted; serving cleartext on it instead
// is the one outcome worse than refusing to start.
func TestTLSFilesFromEnvRequiresBoth(t *testing.T) {
	t.Run("neither is plain http", func(t *testing.T) {
		t.Setenv("TLS_CERT_FILE", "")
		t.Setenv("TLS_KEY_FILE", "")
		cert, key, err := tlsFilesFromEnv()
		if err != nil || cert != "" || key != "" {
			t.Errorf("got (%q, %q, %v), want empty with no error", cert, key, err)
		}
	})
	t.Run("cert without key is fatal", func(t *testing.T) {
		t.Setenv("TLS_CERT_FILE", "/tmp/c.pem")
		t.Setenv("TLS_KEY_FILE", "")
		if _, _, err := tlsFilesFromEnv(); err == nil {
			t.Error("no error for a cert with no key; this would serve cleartext on a TLS port")
		}
	})
	t.Run("key without cert is fatal", func(t *testing.T) {
		t.Setenv("TLS_CERT_FILE", "")
		t.Setenv("TLS_KEY_FILE", "/tmp/k.pem")
		if _, _, err := tlsFilesFromEnv(); err == nil {
			t.Error("no error for a key with no cert; this would serve cleartext on a TLS port")
		}
	})
	t.Run("whitespace counts as unset", func(t *testing.T) {
		t.Setenv("TLS_CERT_FILE", "   ")
		t.Setenv("TLS_KEY_FILE", "   ")
		if _, _, err := tlsFilesFromEnv(); err != nil {
			t.Errorf("whitespace-only paths should read as unset, got %v", err)
		}
	})
}

// TestNewTLSConfigFailsEarlyOnBadPaths: a bad path must be caught at startup,
// where an operator sees it, not at the first handshake days later.
func TestNewTLSConfigFailsEarlyOnBadPaths(t *testing.T) {
	dir := t.TempDir()
	if _, err := newTLSConfig(filepath.Join(dir, "missing.pem"), filepath.Join(dir, "missing.key")); err == nil {
		t.Error("newTLSConfig accepted nonexistent files")
	}

	// A cert that exists but is garbage must also fail at construction.
	certPath := filepath.Join(dir, "junk.pem")
	keyPath := filepath.Join(dir, "junk.key")
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newTLSConfig(certPath, keyPath); err == nil {
		t.Error("newTLSConfig accepted an unparseable keypair")
	}
}

func TestNewTLSConfigPinsMinimumVersion(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "c.key")
	writeKeypair(t, certPath, keyPath, "kypost.test")

	cfg, err := newTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatalf("newTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("newTLSConfig returned nil for a configured keypair")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2 (%#x): leaving it implicit lets a future "+
			"toolchain default decide whether this mail server negotiates a 2006 protocol",
			cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.GetCertificate == nil {
		t.Error("GetCertificate is nil; renewal reload depends on it")
	}
}

// TestCertificateReloadsOnRenewal is why GetCertificate exists rather than a
// static Certificates slice.
//
// Sessions here are in-memory by design, so a restart logs everyone out. ACME
// certificates rotate every 60-90 days. Without in-place reload, every renewal
// would mean a scheduled mandatory mass logout, forever.
func TestCertificateReloadsOnRenewal(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "c.key")
	firstSerial := writeKeypair(t, certPath, keyPath, "kypost.test")

	rc, err := newReloadingCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("newReloadingCertificate: %v", err)
	}

	got, err := rc.get(nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Leaf == nil {
		if got.Leaf, err = x509.ParseCertificate(got.Certificate[0]); err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
	}
	if got.Leaf.SerialNumber.Cmp(firstSerial) != 0 {
		t.Fatalf("serial = %v, want %v", got.Leaf.SerialNumber, firstSerial)
	}

	// Renew. Sleep past filesystem mtime granularity so the stamp genuinely
	// differs — the reload trigger is (modtime, size), and a fresh keypair can be
	// the same size as the old one.
	time.Sleep(1100 * time.Millisecond)
	secondSerial := writeKeypair(t, certPath, keyPath, "kypost.test")

	got, err = rc.get(nil)
	if err != nil {
		t.Fatalf("get after renewal: %v", err)
	}
	leaf, err := x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.SerialNumber.Cmp(secondSerial) != 0 {
		t.Errorf("serial = %v after renewal, want the new %v: a renewal would need a process "+
			"restart, and a restart logs every user out", leaf.SerialNumber, secondSerial)
	}
}

// TestCertificateKeepsServingThroughAMismatchedPair is the renewal race.
//
// ACME clients write the certificate and the private key as two separate files,
// so there is a window in every renewal where the pair on disk does not match.
// Failing the handshake in that window would take the server down briefly on
// every single renewal. An expired-but-serving certificate beats no handshake.
func TestCertificateKeepsServingThroughAMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "c.key")
	goodSerial := writeKeypair(t, certPath, keyPath, "kypost.test")

	rc, err := newReloadingCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("newReloadingCertificate: %v", err)
	}
	if _, err := rc.get(nil); err != nil {
		t.Fatalf("initial get: %v", err)
	}

	// Simulate the mid-renewal window: a NEW certificate written against the OLD
	// key, which is exactly what "cert written, key not yet" looks like.
	time.Sleep(1100 * time.Millisecond)
	otherDir := t.TempDir()
	writeKeypair(t, filepath.Join(otherDir, "n.pem"), filepath.Join(otherDir, "n.key"), "kypost.test")
	newCert, err := os.ReadFile(filepath.Join(otherDir, "n.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, newCert, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := rc.get(nil)
	if err != nil {
		t.Fatalf("get during a mismatched pair returned an error (%v); every renewal would "+
			"briefly refuse handshakes", err)
	}
	leaf, err := x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.SerialNumber.Cmp(goodSerial) != 0 {
		t.Errorf("serial = %v, want the previous good %v retained", leaf.SerialNumber, goodSerial)
	}
}

// TestServeRefusesToStartOnBrokenTLSConfig pins the fail-closed path end to end:
// no silent downgrade to cleartext.
func TestServeRefusesToStartOnBrokenTLSConfig(t *testing.T) {
	srv := newTestServer(t)
	t.Setenv("TLS_CERT_FILE", filepath.Join(t.TempDir(), "nope.pem"))
	t.Setenv("TLS_KEY_FILE", filepath.Join(t.TempDir(), "nope.key"))
	t.Setenv("WEB_PORT", "0")

	srv.Prepare()
	if srv.tlsErr == nil {
		t.Fatal("Prepare recorded no tlsErr for an unreadable keypair")
	}
	if srv.httpServer.TLSConfig != nil {
		t.Error("a broken TLS config was installed on the server")
	}
	if err := srv.Serve(); err == nil {
		t.Error("Serve started despite a broken TLS configuration; it must not fall back to cleartext")
	}
}

// TestPrepareStaysPlainHTTPWithoutCerts guards the default: nothing changes for
// an install that has not configured TLS.
func TestPrepareStaysPlainHTTPWithoutCerts(t *testing.T) {
	srv := newTestServer(t)
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")

	srv.Prepare()
	if srv.tlsErr != nil {
		t.Errorf("tlsErr = %v with no TLS configured", srv.tlsErr)
	}
	if srv.tlsConfig != nil || srv.httpServer.TLSConfig != nil {
		t.Error("a TLS config was built with no certificate configured")
	}
}

// TestTLSTerminationDrivesSecureCookieWithoutProxyTrust is the point of the
// feature, end to end.
//
// With TLS terminated here, r.TLS is non-nil, so isRequestSecure answers on the
// evidence of the connection itself. The session cookie gets Secure and HSTS is
// sent with TRUSTED_PROXY_CIDRS EMPTY — no header is believed, and the whole
// proxy-trust question stops applying to this deployment shape.
func TestTLSTerminationDrivesSecureCookieWithoutProxyTrust(t *testing.T) {
	// Nothing is trusted. The only evidence available is the connection.
	trustProxyCIDRsForTest(t, "")

	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "c.key")
	writeKeypair(t, certPath, keyPath, "127.0.0.1")

	srv := newTestServer(t)
	cfg, err := newTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatalf("newTLSConfig: %v", err)
	}

	ts := httptest.NewUnstartedServer(srv.routes())
	ts.TLS = cfg
	ts.StartTLS()
	defer ts.Close()

	u, err := srv.users.Create(context.Background(), "tls-user", "correct-horse-battery-staple", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	client := ts.Client()
	body, _ := json.Marshal(map[string]string{
		"username": u.Username,
		"password": "correct-horse-battery-staple",
	})
	resp, err := client.Post(ts.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login over TLS: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}

	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "kypost_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie returned")
	}
	if !sessionCookie.Secure {
		t.Error("session cookie lacks Secure over a genuinely TLS connection; the point of " +
			"terminating TLS here is that this needs no forwarded header to be believed")
	}
	if !sessionCookie.HttpOnly {
		t.Error("session cookie lacks HttpOnly")
	}
	if got := resp.Header.Get("Strict-Transport-Security"); got == "" {
		t.Error("no HSTS header on a TLS connection")
	}
}
