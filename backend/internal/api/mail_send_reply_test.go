package api

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kypost-server/backend/internal/mailmsg"
)

// captureSMTP accepts one message on loopback and returns what DATA carried.
func captureSMTP(t *testing.T) (string, int, func(wait time.Duration) string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var data strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		_, _ = conn.Write([]byte("220 ready\r\n"))
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case inData && line == ".\r\n":
				inData = false
				_, _ = conn.Write([]byte("250 queued\r\n"))
			case inData:
				mu.Lock()
				data.WriteString(line)
				mu.Unlock()
			case line == "DATA\r\n":
				inData = true
				_, _ = conn.Write([]byte("354 go\r\n"))
			case strings.HasPrefix(line, "QUIT"):
				_, _ = conn.Write([]byte("221 bye\r\n"))
				return
			default:
				_, _ = conn.Write([]byte("250 ok\r\n"))
			}
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, func(wait time.Duration) string {
		select {
		case <-done:
		case <-time.After(wait):
		}
		mu.Lock()
		defer mu.Unlock()
		return data.String()
	}
}

// A reply names the original by its list messageId; the server reads the
// original's headers and writes In-Reply-To/References itself, so header text
// from the client or from a hostile original never reaches the wire unvetted.
func TestMailSendReplyThreading(t *testing.T) {
	previous := mailmsg.AllowInsecureSMTP
	mailmsg.AllowInsecureSMTP = true // Test-only loopback SMTP transport.
	t.Cleanup(func() { mailmsg.AllowInsecureSMTP = previous })

	setup := func(t *testing.T, lines map[int][]string) (*Server, *fakeMailClient, string, func(time.Duration) string) {
		srv := newTestServer(t)
		srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
		all, _ := srv.users.List()
		userID := all[0].ID
		host, port, captured := captureSMTP(t)
		if err := writeIMAPConfigPayload(srv.userIMAPConfigPath(userID), srv.imapConfigKeyPath, imapConfigPayload{
			Host: "imap.example.com", Port: 993, Username: "alice@example.com", Password: "pw",
			Mailbox: "INBOX", SMTPHost: host, SMTPPort: port, UpdatedAt: "test",
		}); err != nil {
			t.Fatal(err)
		}
		fake := &fakeMailClient{headerLines: lines}
		srv.userMu.Lock()
		srv.userMail[userID] = &serverMailEntry{client: fake, updatedAt: "test"}
		srv.userMu.Unlock()
		return srv, fake, userID, captured
	}
	send := func(srv *Server, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/mail/send", strings.NewReader(body))
		authRequest(srv, req)
		rec := httptest.NewRecorder()
		srv.withAuth(srv.handleMailSend)(rec, req)
		return rec
	}

	t.Run("threads from the original's headers", func(t *testing.T) {
		srv, fake, _, captured := setup(t, map[int][]string{42: {
			"Message-ID: <orig@x.test>",
			"References: <root@x.test>\r\n Bcc: victim@x.test",
		}})
		rec := send(srv, `{"to":"bob@example.com","subject":"Re: s","body":"b","replyToMessageId":"42","replyToMailbox":"Archive"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		raw := captured(5 * time.Second)
		if !strings.Contains(raw, "In-Reply-To: <orig@x.test>\r\n") || !strings.Contains(raw, "References: <root@x.test>\r\n <orig@x.test>\r\n") {
			t.Fatalf("threading headers missing from the delivered message:\n%s", raw)
		}
		if strings.Contains(raw, "victim") {
			t.Fatalf("header text from the original leaked into the reply:\n%s", raw)
		}
		if fake.headerMailbox != "Archive" {
			t.Fatalf("headers read from %q, want the named mailbox", fake.headerMailbox)
		}
	})

	t.Run("refusals send nothing", func(t *testing.T) {
		for name, tc := range map[string]struct {
			lines map[int][]string
			body  string
			code  int
		}{
			"malformed reference": {nil, `{"to":"bob@example.com","body":"b","replyToMessageId":"05"}`, http.StatusBadRequest},
			"unsafe mailbox":      {nil, `{"to":"bob@example.com","body":"b","replyToMessageId":"5","replyToMailbox":"IN\"BOX"}`, http.StatusBadRequest},
			"original not found":  {map[int][]string{}, `{"to":"bob@example.com","body":"b","replyToMessageId":"5"}`, http.StatusNotFound},
		} {
			srv, _, _, captured := setup(t, tc.lines)
			if rec := send(srv, tc.body); rec.Code != tc.code {
				t.Fatalf("%s: status %d, want %d: %s", name, rec.Code, tc.code, rec.Body.String())
			}
			if got := captured(200 * time.Millisecond); got != "" {
				t.Fatalf("%s: a refused reply was delivered:\n%s", name, got)
			}
		}
	})

	t.Run("an original without a Message-ID sends unthreaded", func(t *testing.T) {
		srv, _, _, captured := setup(t, map[int][]string{7: {}})
		if rec := send(srv, `{"to":"bob@example.com","body":"b","replyToMessageId":"7"}`); rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		if raw := captured(5 * time.Second); strings.Contains(raw, "In-Reply-To") || !strings.Contains(raw, "To: bob@example.com") {
			t.Fatalf("unexpected message:\n%s", raw)
		}
	})
}
