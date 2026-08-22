// The certificate pin published in a native pairing link.
//
// The pairing request is the one call that carries the pairing token, the push
// endpoint and the WebPush keys, and without a pin the app sends all of it
// inside a trust-on-first-use window — the certificate is only trusted *after*
// those secrets have already been disclosed. On a network with a locally
// trusted CA (enterprise MDM, a user-installed root, a hostile captive portal)
// an interceptor reads the token, registers its own device against the relay
// first, and hands back credentials it controls. TLS hostname validation does
// not help there; that is exactly what pinning is for.
//
// Empty is never a failure here. The app treats an absent pin as
// trust-on-first-use, which is what pairing did before this existed, so every
// path in this file degrades to unchanged behaviour rather than to a broken
// pairing — and the app fails *closed* on a pin that does not match, so a pin
// we cannot vouch for would be worse than none.

package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	// pinProbeTimeout bounds the outbound handshake in probeSPKIPin. It is
	// short because it sits in the pairing response's critical path: a QR that
	// takes a visible moment to appear is a worse trade than a deployment
	// silently keeping trust-on-first-use.
	pinProbeTimeout = 2 * time.Second

	// pinProbeFailureTTL is how long a failed probe is remembered.
	//
	// Only failures are cached. A success costs one fast handshake and is worth
	// repeating, because reading the pin live is what makes certificate renewal
	// need no action — caching it would mint links pinning a key the server no
	// longer serves. A failure is the slow case (consumer routers routinely do
	// not hairpin NAT, so a server dialling its own public hostname hangs until
	// the timeout), and it is the one worth not repeating every time the panel
	// refreshes its 90-second code.
	pinProbeFailureTTL = 5 * time.Minute
)

// spkiPin is base64 of the SHA-256 of the certificate's SubjectPublicKeyInfo —
// the format OkHttp's CertificatePinner.pin() emits, and byte-identical to
//
//	openssl x509 -pubkey -noout | openssl pkey -pubin -outform der |
//	  openssl dgst -sha256 -binary | base64
//
// The `sha256/` prefix is what the client normalises to; it accepts the value
// with or without.
func spkiPin(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
}

// pairingSPKIPin is the pin to publish in the pairing link, or "".
//
// The probe comes first and the locally configured certificate is the fallback,
// because the probe reads the certificate the device will actually be handed
// and the local one is only an assumption about that. They differ whenever
// something else terminates TLS in front of us — including a reverse proxy
// configured to reach an HTTPS origin, where publishing our own leaf would fail
// every new pairing closed.
func (s *Server) pairingSPKIPin() string {
	if pin := s.probedSPKIPin(); pin != "" {
		return pin
	}
	return leafSPKIPin(s.tlsConfig)
}

// leafSPKIPin reads the pin from the certificate this process serves, or ""
// when it does not terminate TLS.
//
// Read live from GetCertificate on every call rather than cached at startup, so
// a renewal that rotates the key is reflected in the next link generated — see
// reloadingCertificate in tls.go.
func leafSPKIPin(cfg *tls.Config) string {
	if cfg == nil || cfg.GetCertificate == nil {
		return ""
	}
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || cert == nil || len(cert.Certificate) == 0 {
		return ""
	}
	leaf := cert.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return ""
		}
	}
	return spkiPin(leaf)
}

// probedSPKIPin reads the pin from the certificate SERVER_BASE_URL is actually
// serving, or "".
//
// This is what covers the deployment this project documents: a reverse proxy on
// kypost-net terminating TLS, where there is no certificate on our own disk to
// read. With cloudflared there is not even one the operator could mount — the
// device validates a Cloudflare edge certificate — and the probe leaves the
// host over anycast to the same edge, so it never depends on the router
// hairpinning traffic back to itself.
//
// Gated on SERVER_BASE_URL being explicitly configured. The other source of a
// base URL is externalBaseURL, which falls back to the request's Host header:
// dialling that would let a caller both aim our outbound connections and choose
// the pin we publish.
func (s *Server) probedSPKIPin() string {
	base := strings.TrimSpace(s.serverBaseURL)
	if base == "" {
		return ""
	}

	s.pinProbeMu.Lock()
	cachedFailure := s.pinProbeHost == base && time.Since(s.pinProbeFailedAt) < pinProbeFailureTTL
	s.pinProbeMu.Unlock()
	if cachedFailure {
		return ""
	}

	// Deliberately not the request's context. A caller who navigates away mid
	// request would otherwise cancel the dial, and that cancellation would be
	// recorded as a failure and suppress probing for the whole TTL.
	ctx, cancel := context.WithTimeout(context.Background(), pinProbeTimeout)
	defer cancel()
	pin, err := probeSPKIPin(ctx, base, s.pinProbeRoots)
	if err != nil {
		s.pinProbeMu.Lock()
		s.pinProbeHost, s.pinProbeFailedAt = base, time.Now()
		s.pinProbeMu.Unlock()
		// Not an error level: the outcome is the trust-on-first-use pairing this
		// server did before pins existed, and on a private-CA deployment it is
		// permanent and correct. It is logged because it is the only signal that
		// pairing is unpinned, and it is rate-limited by the failure cache.
		s.logger.Info("pairing links will use trust-on-first-use",
			"base_url", base, "reason", "could not read the serving certificate", "error", err.Error())
		return ""
	}
	return pin
}

// probeSPKIPin handshakes with baseURL's host and returns its leaf pin.
//
// The chain is verified as any client would verify it. An unverified peer would
// still be no worse than trust-on-first-use, but publishing a pin means telling
// the app "this key, and refuse everything else" — asserting that on bytes
// nobody authenticated is not a claim this server should make. The cost is that
// a deployment fronted by a private CA gets no pin; that operator's answer is
// TLS_CERT_FILE, which pins from the certificate on disk instead.
//
// roots is nil in production, meaning the system pool. Tests inject the CA of
// an httptest server so the success path can be exercised without the network.
func probeSPKIPin(ctx context.Context, baseURL string, roots *x509.CertPool) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base URL: %w", err)
	}
	host := u.Hostname()
	if !strings.EqualFold(u.Scheme, "https") || host == "" {
		return "", fmt.Errorf("base URL %q is not an https origin", baseURL)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}

	dialer := &tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host,
		RootCAs:    roots,
	}}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	chain := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return "", errors.New("peer presented no certificate")
	}
	return spkiPin(chain[0]), nil
}
