package mailmsg

import (
	"bytes"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNormalizeSMTPMessage(t *testing.T) {
	got, err := NormalizeSMTPMessage([]byte("Subject: hi\n\nbody\rmore\n"))
	if err != nil {
		t.Fatalf("NormalizeSMTPMessage: %v", err)
	}
	want := []byte("Subject: hi\r\n\r\nbody\r\nmore\r\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("normalized message = %q, want %q", got, want)
	}
	if _, err := NormalizeSMTPMessage([]byte("Subject: hi\x00\r\n\r\nbody")); err == nil {
		t.Fatal("NUL byte accepted")
	}
	if _, err := NormalizeSMTPMessage([]byte("Subject: " + strings.Repeat("x", 999) + "\r\n\r\nbody")); err == nil {
		t.Fatal("overlong SMTP line accepted")
	}
}

func TestValidateSMTPEnvelopeRejectsCommandInjection(t *testing.T) {
	for _, tc := range []struct {
		name       string
		from       string
		recipients []string
	}{
		{"sender CRLF", "sender@example.com\r\nRCPT TO:<attacker@example.com>", []string{"victim@example.com"}},
		{"recipient CRLF", "sender@example.com", []string{"victim@example.com\r\nX-Injected: yes"}},
		{"sender display name", "Sender <sender@example.com>", []string{"victim@example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSMTPEnvelope(tc.from, tc.recipients); err == nil {
				t.Fatal("accepted an unsafe SMTP envelope")
			}
		})
	}

	if err := validateSMTPEnvelope("sender@example.com", []string{"victim@example.com"}); err != nil {
		t.Fatalf("rejected a valid SMTP envelope: %v", err)
	}
}

// TestResolveSMTPTarget covers the fallback chain shared by every
// outbound-send call site: payload.SMTPHost, then SMTP_HOST env var, then
// deriveSMTPHost(payload.Host), then a hardcoded default port of 587 (or an
// error when no host can be determined at all).
func TestResolveSMTPTarget(t *testing.T) {
	t.Run("uses payload SMTPHost directly", func(t *testing.T) {
		payload := IMAPConfigPayload{
			Host:     "imap.example.com",
			SMTPHost: "smtp.explicit.example.com",
			SMTPPort: 2525,
		}
		host, port, addr, err := ResolveSMTPTarget(payload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if host != "smtp.explicit.example.com" {
			t.Errorf("host = %q, want smtp.explicit.example.com", host)
		}
		if port != 2525 {
			t.Errorf("port = %d, want 2525", port)
		}
		if addr != "smtp.explicit.example.com:2525" {
			t.Errorf("addr = %q, want smtp.explicit.example.com:2525", addr)
		}
	})

	t.Run("falls back to SMTP_HOST env var when payload host empty", func(t *testing.T) {
		t.Setenv("SMTP_HOST", "smtp.fromenv.example.com")
		payload := IMAPConfigPayload{
			Host: "imap.example.com",
		}
		host, port, addr, err := ResolveSMTPTarget(payload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if host != "smtp.fromenv.example.com" {
			t.Errorf("host = %q, want smtp.fromenv.example.com", host)
		}
		if port != 587 {
			t.Errorf("port = %d, want default 587", port)
		}
		if addr != "smtp.fromenv.example.com:587" {
			t.Errorf("addr = %q, want smtp.fromenv.example.com:587", addr)
		}
	})

	t.Run("falls back to deriveSMTPHost(payload.Host) when payload and env both empty", func(t *testing.T) {
		payload := IMAPConfigPayload{
			Host: "imap.example.com",
		}
		host, port, addr, err := ResolveSMTPTarget(payload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := deriveSMTPHost("imap.example.com")
		if host != want {
			t.Errorf("host = %q, want %q (from deriveSMTPHost)", host, want)
		}
		if port != 587 {
			t.Errorf("port = %d, want default 587", port)
		}
		if addr != want+":587" {
			t.Errorf("addr = %q, want %s:587", addr, want)
		}
	})

	t.Run("errors when completely unconfigured", func(t *testing.T) {
		payload := IMAPConfigPayload{
			Host: "",
		}
		_, _, _, err := ResolveSMTPTarget(payload)
		if err == nil {
			t.Fatal("expected error when no smtp host can be determined, got nil")
		}
	})
}

// TestSMTPSendWithTimeoutDoesNotLeakOnHang is the check for the timeout
// rewrite. Against a server that accepts the TCP connection and then never
// speaks, the old goroutine+time.After version returned to the caller on
// time but left the goroutine blocked in smtp.SendMail forever, holding the
// socket and the message bytes. This asserts the goroutine count returns to
// baseline, which only holds if the timeout actually tears the connection
// down rather than abandoning it.
func TestSMTPSendWithTimeoutDoesNotLeakOnHang(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c // accept, then say nothing at all
		}
	}()

	before := runtime.NumGoroutine()

	start := time.Now()
	err = SMTPSendWithTimeout(ln.Addr().String(), nil, "a@example.com",
		[]string{"b@example.com"}, []byte("Subject: hi\r\n\r\nbody"), 300*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error from a server that never responds")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("took %s, want the send to give up near the 300ms deadline", elapsed)
	}

	select {
	case c := <-accepted:
		defer c.Close()
	default:
		t.Fatal("server never saw the connection; test did not exercise the hang")
	}

	// Allow the runtime a moment to reap anything that is genuinely finishing.
	for i := 0; i < 50; i++ {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines: before=%d after=%d — the timed-out send leaked", before, runtime.NumGoroutine())
}
