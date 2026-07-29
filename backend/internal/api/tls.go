// Optional inbound TLS termination.
//
// Set TLS_CERT_FILE and TLS_KEY_FILE and this server speaks HTTPS directly
// instead of plain HTTP. Leave them unset and nothing changes.
//
// This exists because "is this connection encrypted?" was only ever answerable
// by trusting a header. Without it, the session cookie's Secure flag, the HSTS
// header, and the login proof-of-work's secure-context requirement all depend on
// X-Forwarded-Proto arriving from a peer inside TRUSTED_PROXY_CIDRS — so a
// deployment with no reverse proxy had no way to be secure at all, and one with a
// proxy had to get the trust configuration right before any of it worked. With
// TLS terminated here, r.TLS is non-nil, isRequestSecure answers yes on the
// evidence of the connection itself, and the whole proxy-header question stops
// applying.
//
// Certificates are NOT baked into the image, deliberately. A self-signed cert in
// a shipped image trains users to click through browser warnings, which destroys
// the thing TLS is for; a real cert in an image leaks its private key into a
// distributable layer and cannot be rotated without a rebuild. These are paths to
// mount.
package api

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// tlsFilesFromEnv reads the configured certificate and key paths.
//
// Both or neither. Exactly one set is a misconfiguration and must be fatal
// rather than quietly falling back to plain HTTP: an operator who supplied a
// certificate path believes the port is encrypted, and serving cleartext on it
// instead is the one outcome worse than refusing to start.
func tlsFilesFromEnv() (certFile, keyFile string, err error) {
	certFile = strings.TrimSpace(os.Getenv("TLS_CERT_FILE"))
	keyFile = strings.TrimSpace(os.Getenv("TLS_KEY_FILE"))
	switch {
	case certFile == "" && keyFile == "":
		return "", "", nil
	case certFile == "":
		return "", "", errors.New("TLS_KEY_FILE is set but TLS_CERT_FILE is not; refusing to serve cleartext on a port you configured for TLS")
	case keyFile == "":
		return "", "", errors.New("TLS_CERT_FILE is set but TLS_KEY_FILE is not; refusing to serve cleartext on a port you configured for TLS")
	}
	return certFile, keyFile, nil
}

// reloadingCertificate serves the keypair from disk, re-reading it when the
// files change.
//
// Without this, a certificate renewal needs a process restart — and a restart
// here logs every user out, because sessions are in-memory by design (see
// Session's doc comment). Certificates from any ACME client rotate every 60-90
// days, so "restart to pick up the new cert" would mean a scheduled, mandatory
// mass logout forever.
//
// Reload is driven by stat rather than by a watcher or a signal: the check
// happens at TLS handshake time, and a stat is trivial next to the asymmetric
// crypto a handshake already does. It also needs no new moving parts, and it
// picks up a change made by any means — certbot, a volume remount, a human with
// an editor.
type reloadingCertificate struct {
	certFile string
	keyFile  string

	mu       sync.RWMutex
	cert     *tls.Certificate
	certStat fileStamp
	keyStat  fileStamp
}

// fileStamp is the (modtime, size) pair used to detect a changed file, matching
// how users.Store guards its read cache.
type fileStamp struct {
	mod  time.Time
	size int64
}

func stampOf(path string) (fileStamp, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{mod: info.ModTime(), size: info.Size()}, nil
}

func newReloadingCertificate(certFile, keyFile string) (*reloadingCertificate, error) {
	rc := &reloadingCertificate{certFile: certFile, keyFile: keyFile}
	// Load eagerly so a bad path or an unreadable key fails at startup, where an
	// operator will see it, rather than at the first handshake — which on a
	// self-hosted server might be days later and look like a network fault.
	if err := rc.reload(); err != nil {
		return nil, err
	}
	return rc, nil
}

// reload reads the keypair and replaces the cached certificate.
func (rc *reloadingCertificate) reload() error {
	certStat, err := stampOf(rc.certFile)
	if err != nil {
		return fmt.Errorf("stat TLS certificate %s: %w", rc.certFile, err)
	}
	keyStat, err := stampOf(rc.keyFile)
	if err != nil {
		return fmt.Errorf("stat TLS key %s: %w", rc.keyFile, err)
	}
	cert, err := tls.LoadX509KeyPair(rc.certFile, rc.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS keypair (%s, %s): %w", rc.certFile, rc.keyFile, err)
	}
	rc.mu.Lock()
	rc.cert = &cert
	rc.certStat = certStat
	rc.keyStat = keyStat
	rc.mu.Unlock()
	return nil
}

// get is the tls.Config.GetCertificate callback.
//
// On a reload failure it keeps serving the certificate it already has. That is
// the important case, not a nicety: ACME clients write the certificate and the
// private key as two separate files, so there is a window in every renewal where
// the pair on disk does not match. Failing the handshake during that window would
// take the server down for a moment on every renewal, forever. An expired
// certificate that still handshakes is strictly better than no handshake at all,
// and the error is logged either way.
func (rc *reloadingCertificate) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if rc.changedOnDisk() {
		if err := rc.reload(); err != nil {
			rc.mu.RLock()
			defer rc.mu.RUnlock()
			if rc.cert != nil {
				return rc.cert, nil
			}
			return nil, err
		}
	}
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	if rc.cert == nil {
		return nil, errors.New("no TLS certificate loaded")
	}
	return rc.cert, nil
}

// changedOnDisk reports whether either file's stamp differs from the cached one.
// A stat error counts as changed, so reload runs and reports the real problem.
func (rc *reloadingCertificate) changedOnDisk() bool {
	certStat, certErr := stampOf(rc.certFile)
	keyStat, keyErr := stampOf(rc.keyFile)
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	if certErr != nil || keyErr != nil {
		return true
	}
	return certStat != rc.certStat || keyStat != rc.keyStat
}

// newTLSConfig builds the server's TLS configuration, or returns (nil, nil) when
// no certificate is configured.
//
// MinVersion is pinned to TLS 1.2. Go's default is already 1.2 for servers, but
// leaving it implicit means a future toolchain default is what decides whether
// this mail server negotiates a protocol from 2006. CipherSuites is deliberately
// NOT set: Go's defaults are curated per release and an operator-frozen list ages
// into the weakest part of the stack.
func newTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	rc, err := newReloadingCertificate(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: rc.get,
	}, nil
}
