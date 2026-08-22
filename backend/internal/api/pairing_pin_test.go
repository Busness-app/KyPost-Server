package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tlsOrigin starts an HTTPS server and returns its URL, its leaf pin, and a
// pool that trusts it — a stand-in for the reverse proxy that terminates TLS in
// front of this server in the deployment docs/Reverse_Proxy_Networking.md
// describes.
func tlsOrigin(t *testing.T) (baseURL, pin string, roots *x509.CertPool) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	roots = x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	return ts.URL, spkiPin(ts.Certificate()), roots
}

// closedHTTPSOrigin returns an https URL whose port has nothing listening, so
// the probe fails immediately with a connection refused rather than sitting out
// pinProbeTimeout. Binding and releasing a real port is what keeps it closed:
// a hardcoded one might be in use by something else on the machine.
func closedHTTPSOrigin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return "https://" + addr
}

// TestSPKIPinMatchesTheCertificatesPublicKey checks the published value against
// an independently marshalled SubjectPublicKeyInfo — the same bytes
// `openssl x509 -pubkey | openssl pkey -pubin -outform der` produces, which is
// what OkHttp's CertificatePinner.pin() hashes on the client side.
func TestSPKIPinMatchesTheCertificatesPublicKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeKeypair(t, certPath, keyPath, "relay.example.com")

	cfg, err := newTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatalf("newTLSConfig: %v", err)
	}

	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	sum := sha256.Sum256(spki)
	want := "sha256/" + base64.StdEncoding.EncodeToString(sum[:])

	if got := leafSPKIPin(cfg); got != want {
		t.Errorf("leafSPKIPin() = %q, want %q", got, want)
	}
}

// TestLeafSPKIPinFollowsARenewal is the whole reason the pin is read at
// link-generation time instead of cached: a renewal that mints a new key must
// change the pin, or every link generated after it pins a key the server no
// longer serves and pairing breaks until a restart.
func TestLeafSPKIPinFollowsARenewal(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeKeypair(t, certPath, keyPath, "relay.example.com")

	cfg, err := newTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatalf("newTLSConfig: %v", err)
	}
	before := leafSPKIPin(cfg)
	if before == "" {
		t.Fatal("leafSPKIPin() empty for a configured certificate")
	}

	// Same trick TestCertificateReloadsOnRenewal uses: the stamp is
	// (modtime, size), so a same-second rewrite needs a distinguishable modtime.
	writeKeypair(t, certPath, keyPath, "relay.example.com")
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatalf("chtimes cert: %v", err)
	}
	if err := os.Chtimes(keyPath, future, future); err != nil {
		t.Fatalf("chtimes key: %v", err)
	}

	if after := leafSPKIPin(cfg); after == before {
		t.Errorf("leafSPKIPin() = %q both before and after renewal; the pin is stale", after)
	}
}

// TestLeafSPKIPinEmptyWithoutTLS keeps the absent-pin path honest: no TLS
// termination here means no local pin, and with no probe either the app falls
// back to trust-on-first-use exactly as it did before pins existed.
func TestLeafSPKIPinEmptyWithoutTLS(t *testing.T) {
	if got := leafSPKIPin(nil); got != "" {
		t.Errorf("leafSPKIPin(nil) = %q, want empty", got)
	}
	if got := leafSPKIPin(&tls.Config{MinVersion: tls.VersionTLS12}); got != "" {
		t.Errorf("leafSPKIPin(no GetCertificate) = %q, want empty", got)
	}
}

func TestProbeSPKIPin(t *testing.T) {
	baseURL, want, roots := tlsOrigin(t)

	t.Run("reads the certificate the origin actually serves", func(t *testing.T) {
		got, err := probeSPKIPin(context.Background(), baseURL, roots)
		if err != nil {
			t.Fatalf("probeSPKIPin: %v", err)
		}
		if got != want {
			t.Errorf("probeSPKIPin() = %q, want %q", got, want)
		}
	})

	t.Run("refuses a chain it cannot verify", func(t *testing.T) {
		// The system pool does not trust the httptest CA. Publishing a pin means
		// telling the app "this key and nothing else" — the server must not
		// assert that about bytes nobody authenticated.
		if got, err := probeSPKIPin(context.Background(), baseURL, nil); err == nil {
			t.Errorf("probeSPKIPin() = %q with an untrusted chain, want an error", got)
		}
	})

	t.Run("refuses a non-https base URL without dialling", func(t *testing.T) {
		if _, err := probeSPKIPin(context.Background(), "http://relay.example.com", roots); err == nil {
			t.Error("probeSPKIPin() accepted an http origin")
		}
		if _, err := probeSPKIPin(context.Background(), "", roots); err == nil {
			t.Error("probeSPKIPin() accepted an empty origin")
		}
	})
}

func TestPairingSPKIPinSourceOrder(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "c.key")
	writeKeypair(t, certPath, keyPath, "relay.example.com")
	localCfg, err := newTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatalf("newTLSConfig: %v", err)
	}
	localPin := leafSPKIPin(localCfg)

	t.Run("the probe wins over a local certificate", func(t *testing.T) {
		// A proxy configured to reach an HTTPS origin serves the device its own
		// certificate, not ours. Publishing our leaf there would fail every new
		// pairing closed, so what the origin actually serves has to win.
		baseURL, want, roots := tlsOrigin(t)
		srv := newTestServer(t)
		srv.serverBaseURL = baseURL
		srv.pinProbeRoots = roots
		srv.tlsConfig = localCfg

		got := srv.pairingSPKIPin(context.Background())
		if got == localPin {
			t.Fatal("published the local leaf while a different certificate is being served")
		}
		if got != want {
			t.Errorf("pairingSPKIPin() = %q, want the probed %q", got, want)
		}
	})

	t.Run("a failed probe falls back to the local certificate", func(t *testing.T) {
		// The direct-TLS deployment whose router will not hairpin: the probe
		// cannot reach us, but our own certificate is the right answer anyway.
		srv := newTestServer(t)
		srv.serverBaseURL = closedHTTPSOrigin(t)
		srv.tlsConfig = localCfg

		if got := srv.pairingSPKIPin(context.Background()); got != localPin {
			t.Errorf("pairingSPKIPin() = %q, want the local %q", got, localPin)
		}
	})

	t.Run("no certificate anywhere means no pin", func(t *testing.T) {
		srv := newTestServer(t)
		srv.serverBaseURL = closedHTTPSOrigin(t)
		if got := srv.pairingSPKIPin(context.Background()); got != "" {
			t.Errorf("pairingSPKIPin() = %q, want empty", got)
		}
	})

	t.Run("an unset SERVER_BASE_URL is never dialled", func(t *testing.T) {
		// The other source of a base URL is externalBaseURL, which falls back to
		// the request's Host header. Dialling that would let a caller aim our
		// outbound connections and choose the pin we publish.
		srv := newTestServer(t)
		srv.pinProbeRoots = x509.NewCertPool()
		if got := srv.probedSPKIPin(context.Background()); got != "" {
			t.Errorf("probedSPKIPin() = %q with no configured base URL", got)
		}
		if srv.pinProbeHost != "" {
			t.Errorf("probedSPKIPin recorded a probe of %q", srv.pinProbeHost)
		}
	})
}

// TestProbeFailureIsCached keeps the pairing panel off the dial timeout. A
// consumer router that will not hairpin NAT makes every probe hang for
// pinProbeTimeout, and the panel re-mints its code every 90 seconds.
func TestProbeFailureIsCached(t *testing.T) {
	baseURL, want, roots := tlsOrigin(t)
	srv := newTestServer(t)
	srv.serverBaseURL = baseURL
	srv.pinProbeRoots = roots

	// A probe of this exact host failed a moment ago, so it must not be retried
	// even though it would now succeed.
	srv.pinProbeHost = baseURL
	srv.pinProbeFailedAt = time.Now()
	if got := srv.probedSPKIPin(context.Background()); got != "" {
		t.Errorf("probedSPKIPin() = %q, want empty from the failure cache", got)
	}

	// Once the entry ages out the probe runs again — a cache that never expired
	// would strand a deployment on trust-on-first-use until a restart.
	srv.pinProbeFailedAt = time.Now().Add(-pinProbeFailureTTL - time.Second)
	if got := srv.probedSPKIPin(context.Background()); got != want {
		t.Errorf("probedSPKIPin() = %q after the cache expired, want %q", got, want)
	}
}

func TestPairingResponsePublishesThePin(t *testing.T) {
	pairingPin := func(t *testing.T, configure func(*Server)) (string, bool) {
		t.Helper()
		srv := newTestServer(t)
		configure(srv)
		req := httptest.NewRequest(http.MethodGet, "/api/notifications/pairing", nil)
		authRequest(srv, req)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("pairing status %d: %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode pairing response: %v", err)
		}
		pin, ok := body["tlsPin"].(string)
		return pin, ok
	}

	t.Run("from the proxy that terminates TLS", func(t *testing.T) {
		baseURL, want, roots := tlsOrigin(t)
		pin, ok := pairingPin(t, func(s *Server) {
			s.serverBaseURL = baseURL
			s.pinProbeRoots = roots
		})
		if !ok {
			t.Fatal("no tlsPin in the pairing response; the app would pair over TOFU")
		}
		if pin != want {
			t.Errorf("tlsPin = %q, want %q", pin, want)
		}
	})

	t.Run("absent when the certificate cannot be established", func(t *testing.T) {
		if pin, ok := pairingPin(t, func(s *Server) {
			s.serverBaseURL = closedHTTPSOrigin(t)
		}); ok {
			t.Errorf("tlsPin = %q with no certificate to read", pin)
		}
	})

	t.Run("absent on a plain-http base URL", func(t *testing.T) {
		baseURL, _, roots := tlsOrigin(t)
		if pin, ok := pairingPin(t, func(s *Server) {
			s.serverBaseURL = strings.Replace(baseURL, "https://", "http://", 1)
			s.pinProbeRoots = roots
		}); ok {
			t.Errorf("tlsPin = %q for an http register endpoint", pin)
		}
	})
}
