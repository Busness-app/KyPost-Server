package wkdpublish

import (
	"errors"
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

	LookupTXT = func(string) ([]string, error) { return nil, errors.New("nxdomain") }
	if ok, err := CheckTXT("example.com", "abc123"); ok || err == nil {
		t.Fatal("lookup error should propagate and not match")
	}
}
