package api

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kypost-server/backend/internal/mailmsg"
)

// captureSMTPDelivery accepts one loopback SMTP session and hands back DATA.
// ponytail: a sibling of the reply-threading test's capture; merge them once
// both stacks land.
func captureSMTPDelivery(t *testing.T) (string, int, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		_, _ = conn.Write([]byte("220 ready\r\n"))
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case inData && line == ".\r\n":
				inData = false
				got <- data.String()
				_, _ = conn.Write([]byte("250 queued\r\n"))
			case inData:
				data.WriteString(line)
			case strings.HasPrefix(line, "QUIT"):
				_, _ = conn.Write([]byte("221 bye\r\n"))
				return
			case line == "DATA\r\n":
				inData = true
				_, _ = conn.Write([]byte("354 go\r\n"))
			default:
				_, _ = conn.Write([]byte("250 ok\r\n"))
			}
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, got
}

func TestMailSendCalendarReply(t *testing.T) {
	previous := mailmsg.AllowInsecureSMTP
	mailmsg.AllowInsecureSMTP = true // Test-only loopback SMTP transport.
	t.Cleanup(func() { mailmsg.AllowInsecureSMTP = previous })

	const ics = "BEGIN:VCALENDAR\nVERSION:2.0\nMETHOD:REPLY\nBEGIN:VEVENT\nUID:e1@x.test\nATTENDEE;PARTSTAT=ACCEPTED:mailto:alice@example.com\nEND:VEVENT\nEND:VCALENDAR\n"
	send := func(t *testing.T, payload map[string]any) (*httptest.ResponseRecorder, <-chan string) {
		srv := newTestServer(t)
		srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
		userID := srv.mustBootstrapUserID(t)
		host, port, got := captureSMTPDelivery(t)
		if err := writeIMAPConfigPayload(srv.userIMAPConfigPath(userID), srv.imapConfigKeyPath, imapConfigPayload{
			Host: "imap.example.com", Port: 993, Username: "alice@example.com", Password: "pw", Mailbox: "INBOX", SMTPHost: host, SMTPPort: port,
		}); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(payload)
		return doJSONAuthRaw(srv, body, userID), got
	}

	rec, got := send(t, map[string]any{"to": "organizer@x.test", "subject": "Accepted", "body": "Accepted", "calendarReply": map[string]string{"ics": ics}})
	var ack struct {
		CalendarReply *bool `json:"calendarReply"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ack) != nil || ack.CalendarReply == nil || !*ack.CalendarReply {
		t.Fatalf("status %d, want 200 with calendarReply:true: %s", rec.Code, rec.Body.String())
	}
	var raw string
	select {
	case raw = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("nothing delivered")
	}
	if !strings.Contains(raw, "Content-Type: multipart/alternative;") || !strings.Contains(raw, "Content-Type: text/calendar; method=REPLY; charset=UTF-8") {
		t.Fatalf("delivered message lacks the iTIP part:\n%s", raw)
	}

	// An ordinary send says nothing about calendar replies.
	plain, plainGot := send(t, map[string]any{"to": "organizer@x.test", "body": "b"})
	<-plainGot
	if plain.Code != http.StatusOK || strings.Contains(plain.Body.String(), "calendarReply") {
		t.Fatalf("plain send: %d %s", plain.Code, plain.Body.String())
	}

	for name, payload := range map[string]map[string]any{
		"not a reply":  {"to": "organizer@x.test", "body": "b", "calendarReply": map[string]string{"ics": strings.Replace(ics, "METHOD:REPLY", "METHOD:REQUEST", 1)}},
		"with encrypt": {"to": "organizer@x.test", "body": "b", "encrypt": true, "calendarReply": map[string]string{"ics": ics}},
	} {
		rec, got := send(t, payload)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d, want 400: %s", name, rec.Code, rec.Body.String())
		}
		select {
		case raw := <-got:
			t.Fatalf("%s: a refused reply was delivered:\n%s", name, raw)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func doJSONAuthRaw(srv *Server, body []byte, userID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/mail/send", strings.NewReader(string(body)))
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleMailSend)(rec, req)
	return rec
}
