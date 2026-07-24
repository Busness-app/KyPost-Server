// Package wkdpublish holds the instance's set of WKD domain-publishing
// claims — domains an admin has proven control over (via a DNS TXT record)
// and for which this instance may serve public keys at the Web Key
// Directory well-known paths, one claim/TXT record per domain. Persisted as
// a single wkd-domains.json at the instance's state root. The api process
// (management + serving) and the poller process (periodic re-check)
// construct independent Stores over the same file and refresh from disk on
// every read, mirroring internal/sendas and internal/contacts.
package wkdpublish

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"kypost-server/backend/internal/fsutil"
)

// Claim is one domain the user is (or is trying to be) authoritative for.
type Claim struct {
	Domain        string `json:"domain"`
	Token         string `json:"token"`
	Verified      bool   `json:"verified"`
	CreatedAt     string `json:"createdAt"`
	VerifiedAt    string `json:"verifiedAt,omitempty"`
	LastCheckedAt string `json:"lastCheckedAt,omitempty"`
}

// Store is the instance's set of WKD domain claims, admin-managed and
// persisted as a single wkd-domains.json at the instance's state root. The
// API and poller processes share no memory, so every read and mutation
// re-reads the file from disk first, matching sendas.Store's convention.
type Store struct {
	mu      sync.Mutex
	baseDir string
	claims  []Claim
}

type claimsFile struct {
	Claims []Claim `json:"claims"`
}

func New(baseDir string) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{baseDir: baseDir, claims: []Claim{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) path() string {
	return filepath.Join(s.baseDir, "wkd-domains.json")
}

func (s *Store) load() error {
	return fsutil.LoadJSONFile(s.path(), s.applyFile, s.persistLocked)
}

func (s *Store) applyFile(cf claimsFile) {
	s.claims = append([]Claim{}, cf.Claims...)
}

func (s *Store) refreshFromDiskLocked() error {
	return fsutil.LoadJSONFile(s.path(), s.applyFile, nil)
}

func (s *Store) persistLocked() error {
	cf := claimsFile{Claims: s.claims}
	if err := fsutil.PersistJSONFile(s.path(), cf); err != nil {
		return fmt.Errorf("write wkd domains: %w", err)
	}
	return nil
}

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSpace(d))
}

func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// List returns all domain claims regardless of verification status.
func (s *Store) List() []Claim {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshFromDiskLocked()
	out := make([]Claim, len(s.claims))
	copy(out, s.claims)
	return out
}

// Create records (or refreshes) a claim for domain. Re-claiming an existing
// domain mints a new token and resets Verified — the operator must re-prove
// control via a fresh DNS TXT record. Domain is normalized (lowercased and
// trimmed) before storing or matching.
func (s *Store) Create(domain string) (Claim, error) {
	d := normalizeDomain(domain)
	if d == "" {
		return Claim{}, fmt.Errorf("wkdpublish: empty domain")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return Claim{}, err
	}
	token, err := newToken()
	if err != nil {
		return Claim{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for i := range s.claims {
		if s.claims[i].Domain == d {
			s.claims[i].Token = token
			s.claims[i].Verified = false
			s.claims[i].CreatedAt = now
			s.claims[i].VerifiedAt = ""
			s.claims[i].LastCheckedAt = ""
			if err := s.persistLocked(); err != nil {
				return Claim{}, err
			}
			return s.claims[i], nil
		}
	}
	c := Claim{Domain: d, Token: token, CreatedAt: now}
	s.claims = append(s.claims, c)
	if err := s.persistLocked(); err != nil {
		return Claim{}, err
	}
	return c, nil
}

// SetVerified updates the verified flag for domain and stamps
// LastCheckedAt. VerifiedAt is stamped only on the transition into
// verified (false -> true); it is left untouched on subsequent
// re-verifications and on transitions into unverified. Returns an error if
// no claim exists for domain.
func (s *Store) SetVerified(domain string, verified bool, checkedAt time.Time) error {
	d := normalizeDomain(domain)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return err
	}
	for i := range s.claims {
		if s.claims[i].Domain != d {
			continue
		}
		s.claims[i].LastCheckedAt = checkedAt.UTC().Format(time.RFC3339)
		if verified && !s.claims[i].Verified {
			s.claims[i].VerifiedAt = s.claims[i].LastCheckedAt
		}
		s.claims[i].Verified = verified
		return s.persistLocked()
	}
	return fmt.Errorf("wkdpublish: no claim for %q", d)
}

// Delete removes the claim for domain entirely. Returns (false, nil) if no
// claim exists for domain.
func (s *Store) Delete(domain string) (bool, error) {
	d := normalizeDomain(domain)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return false, err
	}
	for i := range s.claims {
		if s.claims[i].Domain == d {
			s.claims = append(s.claims[:i], s.claims[i+1:]...)
			return true, s.persistLocked()
		}
	}
	return false, nil
}

// VerifiedDomains returns the set of domains with Verified == true.
func (s *Store) VerifiedDomains() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshFromDiskLocked()
	out := map[string]bool{}
	for _, c := range s.claims {
		if c.Verified {
			out[c.Domain] = true
		}
	}
	return out
}
