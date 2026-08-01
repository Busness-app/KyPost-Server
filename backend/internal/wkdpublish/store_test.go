package wkdpublish_test

import (
	"testing"
	"time"

	"kypost-server/backend/internal/wkdpublish"
)

func TestCreateAndList(t *testing.T) {
	s, err := wkdpublish.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Create("Example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.Domain != "example.com" {
		t.Fatalf("domain not normalized: %q", c.Domain)
	}
	if c.Token == "" || c.Verified {
		t.Fatal("new claim must have a token and be unverified")
	}
	got, err := s.List()
	if err != nil || len(got) != 1 {
		t.Fatalf("List = %d claims, err=%v", len(got), err)
	}
}

func TestReclaimRefreshesTokenAndResetsVerified(t *testing.T) {
	s, _ := wkdpublish.New(t.TempDir())
	first, _ := s.Create("example.com")
	if err := s.SetVerified("example.com", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	second, _ := s.Create("example.com")
	if second.Token == first.Token {
		t.Fatal("re-claim should mint a new token")
	}
	if second.Verified {
		t.Fatal("re-claim should reset Verified")
	}
	if claims, err := s.List(); err != nil || len(claims) != 1 {
		t.Fatalf("re-claim must not duplicate the domain: %d claims, err=%v", len(claims), err)
	}
}

func TestSetVerifiedAndVerifiedDomains(t *testing.T) {
	s, _ := wkdpublish.New(t.TempDir())
	s.Create("example.com")
	s.Create("other.org")
	if err := s.SetVerified("example.com", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	vd, err := s.VerifiedDomains()
	if err != nil {
		t.Fatal(err)
	}
	if !vd["example.com"] || vd["other.org"] {
		t.Fatalf("VerifiedDomains = %v", vd)
	}
}

func TestDelete(t *testing.T) {
	s, _ := wkdpublish.New(t.TempDir())
	s.Create("example.com")
	ok, err := s.Delete("example.com")
	if err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}
	if claims, err := s.List(); err != nil || len(claims) != 0 {
		t.Fatalf("claim not removed: %d claims, err=%v", len(claims), err)
	}
}
