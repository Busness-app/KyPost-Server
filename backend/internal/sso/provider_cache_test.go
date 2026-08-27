package sso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// discoveryCounter is an issuer that serves nothing but a discovery document
// and counts how many times it was asked for one.
//
// ssotest.IdP would do as well for the flow, but the subject here is the
// request count, and that is the one thing a shared helper cannot report.
func discoveryCounter(t *testing.T) (issuer string, hits *atomic.Int64) {
	t.Helper()
	hits = &atomic.Int64{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = writeJSONDoc(w, map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/a",
			"token_endpoint":         srv.URL + "/t",
			"jwks_uri":               srv.URL + "/j",
		})
	}))
	t.Cleanup(srv.Close)
	return srv.URL, hits
}

// resetProviderCache empties the package cache so one test cannot answer for
// another.
func resetProviderCache(t *testing.T) {
	t.Helper()
	providerCacheMu.Lock()
	clear(providerCache)
	providerCacheMu.Unlock()
}

// Four public routes call NewProvider, and each call used to be one outbound
// GET to the operator's identity provider.
func TestNewProviderDiscoversOncePerSettings(t *testing.T) {
	resetProviderCache(t)
	issuer, hits := discoveryCounter(t)

	for i := range 5 {
		if _, err := NewProvider(context.Background(), testSettings(issuer), "https://mail.example.com/cb"); err != nil {
			t.Fatalf("NewProvider() call %d error = %v", i, err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("discovery requests = %d after 5 NewProvider calls, want 1", got)
	}
}

// Every setting the provider is built from is part of the key, so an admin
// change is the invalidation and no stale provider survives it.
func TestProviderCacheKeyCoversEverySetting(t *testing.T) {
	base := testSettings("https://auth.example.com")
	const redirect = "https://mail.example.com/cb"
	key := providerCacheKey(base, redirect)

	for _, tc := range []struct {
		name     string
		mutate   func(*SSOSettings)
		redirect string
	}{
		{"issuer", func(c *SSOSettings) { c.IssuerURL = "https://other.example.com" }, redirect},
		{"client id", func(c *SSOSettings) { c.ClientID = "another-client" }, redirect},
		{"client secret", func(c *SSOSettings) { c.ClientSecret = "rotated" }, redirect},
		{"insecure issuer opt-in", func(c *SSOSettings) { c.AllowInsecureIssuer = true }, redirect},
		{"redirect uri", func(*SSOSettings) {}, "https://mail.example.com/other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			tc.mutate(&changed)
			if got := providerCacheKey(changed, tc.redirect); got == key {
				t.Errorf("changing the %s did not change the cache key", tc.name)
			}
		})
	}

	// And the same settings still agree with themselves.
	if providerCacheKey(base, redirect) != key {
		t.Error("providerCacheKey is not stable for identical settings")
	}
}

// A rotated IdP configuration is picked up without a restart.
func TestProviderCacheEntriesExpire(t *testing.T) {
	resetProviderCache(t)
	issuer, hits := discoveryCounter(t)

	if _, err := NewProvider(context.Background(), testSettings(issuer), "https://mail.example.com/cb"); err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}
	// Age the entry past its TTL rather than sleeping for it.
	providerCacheMu.Lock()
	for k, entry := range providerCache {
		entry.expires = time.Now().Add(-time.Second)
		providerCache[k] = entry
	}
	providerCacheMu.Unlock()

	if _, err := NewProvider(context.Background(), testSettings(issuer), "https://mail.example.com/cb"); err != nil {
		t.Fatalf("NewProvider() after expiry error = %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("discovery requests = %d, want 2 (one per side of the TTL)", got)
	}
}

// A failure is not cached: the next attempt must reach a provider that has come
// back up, and the map must not fill with entries that answer with an error.
func TestProviderCacheDoesNotCacheFailures(t *testing.T) {
	resetProviderCache(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "provider is down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	for i := range 2 {
		if _, err := NewProvider(context.Background(), testSettings(srv.URL), "https://mail.example.com/cb"); err == nil {
			t.Fatalf("NewProvider() call %d accepted a failed discovery", i)
		}
	}
	providerCacheMu.Lock()
	n := len(providerCache)
	providerCacheMu.Unlock()
	if n != 0 {
		t.Fatalf("cache holds %d entries after two failed discoveries, want 0", n)
	}
}

// The key space is admin-configured, but it is still bounded.
func TestProviderCacheIsBounded(t *testing.T) {
	resetProviderCache(t)

	p := &Provider{issuer: "https://auth.example.com"}
	for i := range providerCacheEntries * 3 {
		cacheProvider(providerCacheKey(testSettings("https://auth.example.com"), string(rune('a'+i))), p)
	}
	providerCacheMu.Lock()
	n := len(providerCache)
	providerCacheMu.Unlock()
	if n > providerCacheEntries {
		t.Fatalf("cache holds %d entries, want at most %d", n, providerCacheEntries)
	}
}
