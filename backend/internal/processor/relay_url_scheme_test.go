package processor

import "testing"

// Every request this sender makes carries the per-server relay key as a bearer
// token, so a plaintext relay URL discloses that credential (and the
// notification body) to anyone on the path. It must be refused at construction.
func TestValidateRelayURLRefusesPlaintext(t *testing.T) {
	refused := []string{
		"http://relay.example.com",
		"http://203.0.113.10:8080",
		"ws://relay.example.com",
		"ftp://relay.example.com",
		"relay.example.com", // no scheme at all: parses with an empty Host
		"",
	}
	for _, raw := range refused {
		if err := ValidateRelayURL(raw); err == nil {
			t.Errorf("ValidateRelayURL(%q) = nil, want an error", raw)
		}
	}
}

// https anywhere, and http only when it cannot leave the host — which is how
// the relay is exercised locally and by the tests in this package.
func TestValidateRelayURLAllowsHTTPSAndLoopback(t *testing.T) {
	allowed := []string{
		"https://relay.example.com",
		"https://relay.example.com:8443/base",
		"http://localhost:8787",
		"http://127.0.0.1:8787",
		"http://[::1]:8787",
	}
	for _, raw := range allowed {
		if err := ValidateRelayURL(raw); err != nil {
			t.Errorf("ValidateRelayURL(%q) = %v, want nil", raw, err)
		}
	}
}

// A fully configured plaintext relay — key and all, nothing else missing — must
// still produce no sender. Everything downstream (auto-registration and every
// /send) inherits the refusal from the constructor, so this is the one place the
// scheme has to be enforced.
func TestNewRelaySenderRefusesPlaintextRelayURL(t *testing.T) {
	t.Setenv("PUSH_RELAY_URL", "http://relay.example.com")
	t.Setenv("PUSH_RELAY_KEY", "test-api-key")

	if sender := newRelaySenderFromEnvWithPrefix(nil, "PUSH_RELAY"); sender != nil {
		t.Fatal("a plaintext PUSH_RELAY_URL produced a usable sender")
	}
}

// The control: the same configuration over https is accepted, so the guard
// rejects the scheme and not the configuration.
func TestNewRelaySenderAcceptsHTTPSRelayURL(t *testing.T) {
	t.Setenv("APNS_RELAY_URL", "https://relay.example.com/")
	t.Setenv("APNS_RELAY_KEY", "test-api-key")

	sender := newRelaySenderFromEnvWithPrefix(nil, "APNS_RELAY")
	if sender == nil {
		t.Fatal("an https APNS_RELAY_URL produced no sender")
	}
	if sender.relayURL != "https://relay.example.com" {
		t.Fatalf("relayURL = %q, want %q", sender.relayURL, "https://relay.example.com")
	}
}
