package wkdpublish

import (
	"errors"
	"net"
	"testing"
)

func TestCheckTXT(t *testing.T) {
	orig := LookupTXT
	defer func() { LookupTXT = orig }()

	LookupTXT = func(name string) ([]string, error) {
		if name != "_kypost-wkd.example.com" {
			t.Fatalf("unexpected lookup name %q", name)
		}
		return []string{"v=spf1 -all", "kypost-wkd-verify=abc123"}, nil
	}
	ok, err := CheckTXT("example.com", "abc123")
	if err != nil || !ok {
		t.Fatalf("expected match, got ok=%v err=%v", ok, err)
	}

	ok, _ = CheckTXT("example.com", "wrongtoken")
	if ok {
		t.Fatal("wrong token must not match")
	}

	LookupTXT = func(string) ([]string, error) { return nil, errors.New("some transient failure") }
	if ok, err := CheckTXT("example.com", "abc123"); ok || err == nil {
		t.Fatal("a non-DNSError lookup error should propagate and not match")
	}
}

// TestCheckTXTNotFoundIsDefinitive covers R1: an actual NXDOMAIN/NODATA
// result (a *net.DNSError with IsNotFound set — what net.LookupTXT returns
// when the record genuinely doesn't exist, e.g. after an operator deletes
// it) must be reported as a definitive (false, nil), not an error. Callers
// rely on this to distinguish "no proof at all" (must suspend) from a
// transient resolver failure (must not suspend).
func TestCheckTXTNotFoundIsDefinitive(t *testing.T) {
	orig := LookupTXT
	defer func() { LookupTXT = orig }()

	LookupTXT = func(string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "_kypost-wkd.example.com", IsNotFound: true}
	}
	ok, err := CheckTXT("example.com", "abc123")
	if err != nil {
		t.Fatalf("NXDOMAIN/NODATA must not be reported as an error, got %v", err)
	}
	if ok {
		t.Fatal("NXDOMAIN/NODATA must not match")
	}
}

// TestCheckTXTTransientDNSErrorPropagates covers the other half of R1: a
// *net.DNSError that is NOT IsNotFound (e.g. a timeout) must still propagate
// as an error rather than being silently treated as "not found".
func TestCheckTXTTransientDNSErrorPropagates(t *testing.T) {
	orig := LookupTXT
	defer func() { LookupTXT = orig }()

	LookupTXT = func(string) ([]string, error) {
		return nil, &net.DNSError{Err: "i/o timeout", Name: "_kypost-wkd.example.com", IsTimeout: true}
	}
	ok, err := CheckTXT("example.com", "abc123")
	if err == nil {
		t.Fatal("a timeout DNSError must propagate as an error, not be treated as not-found")
	}
	if ok {
		t.Fatal("a timeout must not match")
	}
}
