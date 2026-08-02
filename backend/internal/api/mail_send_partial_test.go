package api

// The response to a send must not claim success for deliveries that have not
// been attempted yet.
//
// An encrypted send to a mix of keyed and keyless recipients is not one SMTP
// transaction. To/CC share a ciphertext, each BCC gets its own, and every
// keyless recipient gets a pickup-link mail. finishMailSend used to write
// {"ok":true} after the FIRST of those and leave the rest running behind the
// answer, so a send where every blind copy bounced and every pickup link failed
// still reported clean success — the failures existed only in the server log,
// which the person who pressed Send cannot see.
//
// finishMailSend already carries a warning channel (extraWarning, surfaced as
// response.warning and rendered by the composer). These tests pin the ordering
// that makes it usable: the follow-on deliveries run BEFORE the response is
// written, and they do not run at all when the primary delivery failed.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// finishArgs fills in the parameters these tests do not care about, so each
// test body shows only the thing it is about.
func (s *Server) finishForTest(t *testing.T, userID string, recipients []string, msg []byte, afterPrimary func() string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mail/send", nil)
	s.finishMailSend(rec, req, userID,
		"127.0.0.1", 1, "127.0.0.1:1", "user", "pw",
		"alice@example.com",
		[]string{"bob@example.com"}, nil, []string{"carol@example.com"},
		recipients, msg,
		mailRequest{Subject: "hi", Body: "hello", Mode: "plain"},
		nil, "", afterPrimary)
	return rec
}

// TestFinishMailSendRunsFollowOnDeliveriesBeforeAnswering is the core ordering
// guard. Passing no primary recipients skips SMTP entirely (finishMailSend's
// empty-recipient guard), which isolates the question being asked: does the
// follow-on work happen on the near side of the response, and does what it
// reports reach the caller?
func TestFinishMailSendRunsFollowOnDeliveriesBeforeAnswering(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	const warning = "2 of 3 blind copies could not be delivered"
	called := false
	rec := srv.finishForTest(t, userID, nil, nil, func() string {
		called = true
		return warning
	})

	if !called {
		t.Fatal("follow-on deliveries never ran; the response was written without them")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Body.String(); !strings.Contains(got, warning) {
		t.Fatalf("response did not carry the delivery warning\n got: %s\nwant it to contain: %q", got, warning)
	}
}

// TestFinishMailSendSkipsFollowOnDeliveriesWhenPrimaryFails proves the ordering
// did not cost the existing guarantee. The primary send is the hard-error-gated
// one: if it fails the caller gets 502 and is expected to retry the whole
// message, so the BCC copies and pickup links must not have gone out first —
// otherwise the retry duplicates them.
//
// SMTP points at 127.0.0.1:1, which refuses connections near-instantly; a 502
// is this package's established "reached the network layer and failed" signal.
func TestFinishMailSendSkipsFollowOnDeliveriesWhenPrimaryFails(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	called := false
	rec := srv.finishForTest(t, userID, []string{"bob@example.com"}, []byte("Subject: hi\r\n\r\nhello"), func() string {
		called = true
		return ""
	})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
	if called {
		t.Fatal("blind copies and pickup links were sent even though the primary delivery failed; a retry now duplicates them")
	}
}

// TestPartialDeliveryWarningCountsEveryUnreachedRecipient covers the wording
// the two failure kinds produce. They are counted separately because they fail
// for different reasons and the sender's next move differs: a bounced blind
// copy is an address or server problem, a failed pickup link means that
// recipient got nothing at all.
func TestPartialDeliveryWarningCountsEveryUnreachedRecipient(t *testing.T) {
	tests := []struct {
		name       string
		bccFailed  int
		bccTotal   int
		pickFailed int
		pickTotal  int
		want       string
	}{
		{name: "everything delivered", want: ""},
		{
			name:      "some blind copies bounced",
			bccFailed: 2, bccTotal: 3,
			want: "2 of 3 blind copies were not delivered",
		},
		{
			name:       "some pickup links failed",
			pickFailed: 1, pickTotal: 4,
			want: "1 of 4 secure links could not be sent",
		},
		{
			name:      "both kinds failed",
			bccFailed: 1, bccTotal: 1, pickFailed: 2, pickTotal: 2,
			want: "1 of 1 blind copies were not delivered; 2 of 2 secure links could not be sent",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := partialDeliveryWarning(tc.bccFailed, tc.bccTotal, tc.pickFailed, tc.pickTotal)
			if got != tc.want {
				t.Fatalf("partialDeliveryWarning(%d,%d,%d,%d) = %q, want %q",
					tc.bccFailed, tc.bccTotal, tc.pickFailed, tc.pickTotal, got, tc.want)
			}
		})
	}
}
