package mailmsg

// Telling "the server never took the message" apart from "the server took the
// message and then the connection broke".
//
// Both come back from a send as a non-nil error, and for ordinary mail that is
// the right amount of detail — the user retries. The pickup path cannot treat
// them the same: it deletes its stored record when a send fails, to stop
// undeliverable records from holding a quota slot for seven days. Delete on the
// second case and the recipient gets the link email for a message the server
// has already thrown away, which is strictly worse than the leak being fixed.
//
// The window is real and narrow: net/smtp's writer.Close() returning nil means
// the server answered 250 to the DATA, and client.Quit() runs after that. A
// connection dropped between those two points is an accepted message reported
// as a failure.

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// smtpScript runs a minimal SMTP server that accepts one message. If
// dropAfterData is set it closes the connection immediately after answering
// 250 to the message body, without ever responding to QUIT.
func smtpScript(t *testing.T, dropAfterData bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(conn)
		w := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }

		w("220 test ready")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")

			if inData {
				if line == "." {
					inData = false
					w("250 accepted")
					if dropAfterData {
						// Accepted, then vanish before QUIT is answered.
						return
					}
					continue
				}
				continue
			}

			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				// No extensions: no STARTTLS to negotiate, no AUTH to run.
				w("250 test")
			case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
				w("250 ok")
			case strings.HasPrefix(line, "DATA"):
				inData = true
				w("354 go ahead")
			case strings.HasPrefix(line, "QUIT"):
				w("221 bye")
				return
			default:
				w("250 ok")
			}
		}
	}()
	return ln.Addr().String()
}

func sendTo(addr string) error {
	return SMTPSendWithTimeout(addr, nil, "a@example.com", []string{"b@example.com"},
		[]byte("Subject: hi\r\n\r\nbody"), 5*time.Second)
}

// The ordinary case still has to be a clean success, or the sentinel below
// would be indistinguishable from "this never works".
func TestSMTPSendSucceedsAgainstAWellBehavedServer(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_SMTP", "1")
	AllowInsecureSMTP = true
	t.Cleanup(func() { AllowInsecureSMTP = false })

	if err := sendTo(smtpScript(t, false)); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// The message was accepted; only the goodbye failed. Callers that undo work on
// failure need to be able to see that.
func TestSMTPSendReportsAcceptanceWhenOnlyQuitFails(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_SMTP", "1")
	AllowInsecureSMTP = true
	t.Cleanup(func() { AllowInsecureSMTP = false })

	err := sendTo(smtpScript(t, true))
	if err == nil {
		t.Skip("server closed cleanly enough that QUIT succeeded; nothing to assert")
	}
	if !errors.Is(err, ErrSMTPAcceptedThenFailed) {
		t.Fatalf("err = %v, want it to wrap ErrSMTPAcceptedThenFailed; a caller "+
			"would now delete a message the recipient was told about", err)
	}
}

// A failure before DATA is accepted must NOT claim acceptance, or the quota
// leak this distinction exists to fix comes straight back.
func TestSMTPSendDoesNotClaimAcceptanceWhenRefusedEarly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("554 no service here\r\n"))
	}()

	err = sendTo(ln.Addr().String())
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if errors.Is(err, ErrSMTPAcceptedThenFailed) {
		t.Fatalf("a pre-acceptance rejection reported acceptance: %v", err)
	}
}
