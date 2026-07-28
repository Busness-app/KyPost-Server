package imap

import (
	"io"
	"testing"
)

// APIClient must satisfy io.Closer: that is the contract both cache-eviction
// sites type-assert against (api.closeMailClient and the poller's
// userMailClient), so losing it would silently reinstate the connection leak
// with everything still compiling.
func TestAPIClientIsAnIOCloser(t *testing.T) {
	var _ io.Closer = (*APIClient)(nil)
}

// Close is reached on clients that never connected (a cached client evicted
// before its first fetch) and can be reached twice, so neither may panic or
// error.
func TestCloseIsNilSafeAndIdempotent(t *testing.T) {
	c := NewAPIClientFromStoredConfig("/nonexistent/imap-config.json", "/nonexistent/imap.key")
	if err := c.Close(); err != nil {
		t.Fatalf("first Close on a never-connected client: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if c.dialer != nil {
		t.Fatal("dialer should be nil after Close")
	}
}
