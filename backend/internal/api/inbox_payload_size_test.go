package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/mailcache"
)

// TestInboxPayloadSize measures the wire bytes one inbox-screen load costs on
// the path the SPA takes: GET /api/inbox?limit=500 served from a warm cache,
// through the real gzip middleware. It asserts nothing about the numbers — run
// it with -v and read them.
//
// Baseline when this was written: bodies on, no compression, 500 messages of
// ordinary HTML mail = 13.3 MiB, re-requested every 15 seconds by ReadPage's
// poll. The list rows render none of those bodies.
func TestInboxPayloadSize(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user: %v", err)
	}
	userID := all[0].ID
	cfg := config.Default()

	const count = 500
	bodySizes := []int{64, 2 << 10, 20 << 10, 60 << 10, 120 << 10}

	t.Logf("%d-message window, per average body size:", count)
	t.Logf("  %-12s %-16s %-16s %-16s", "body/msg", "bodies, plain", "bodies, gzip", "bodies=0, gzip")
	for _, bodyBytes := range bodySizes {
		cache := testInboxCache(t)
		entries := make([]mailcache.Entry, 0, count)
		for i := 0; i < count; i++ {
			entries = append(entries, mailcache.Entry{
				UID:           i + 1,
				MessageID:     fmt.Sprintf("%d", i+1),
				Subject:       "Your order has shipped - tracking details inside",
				Sender:        fmt.Sprintf("notifications-%d@marketing.example.com", i),
				SentTo:        "yoshi@example.com",
				Keywords:      []string{"Promotions"},
				Status:        "read",
				AtUTC:         "2026-08-25T11:04:33Z",
				Body:          syntheticHTMLBody(i, bodyBytes),
				BodyMode:      "html",
				PGPClassified: true,
			})
		}
		if err := cache.Upsert("INBOX", entries); err != nil {
			t.Fatalf("Upsert: %v", err)
		}

		measure := func(acceptEncoding string, withBodies bool) int {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/inbox?limit=500", nil)
			req.Header.Set("Accept-Encoding", acceptEncoding)
			withGzip(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				srv.serveInbox(w, context.Background(), userID, &fakeMailClient{}, cache, cfg, "", count, 0, false, withBodies)
			})).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			return rec.Body.Len()
		}

		t.Logf("  %-12s %-16s %-16s %-16s",
			human(int64(bodyBytes)),
			human(int64(measure("identity", true))),
			human(int64(measure("gzip", true))),
			human(int64(measure("gzip", false))))
	}
}

// TestInboxDeltaPayloadSize measures the since= cursor protocol the backend
// implements and no shipped client uses — the remaining win after bodies=0.
func TestInboxDeltaPayloadSize(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID
	cfg := config.Default()

	const count = 500
	cache := testInboxCache(t)
	entries := make([]mailcache.Entry, 0, count)
	for i := 0; i < count; i++ {
		entries = append(entries, mailcache.Entry{
			UID:           i + 1,
			MessageID:     fmt.Sprintf("%d", i+1),
			Subject:       "Your order has shipped - tracking details inside",
			Sender:        fmt.Sprintf("notifications-%d@marketing.example.com", i),
			Keywords:      []string{"Promotions"},
			Status:        "read",
			AtUTC:         "2026-08-25T11:04:33Z",
			Body:          syntheticHTMLBody(i, 20<<10),
			BodyMode:      "html",
			PGPClassified: true,
		})
	}
	if err := cache.Upsert("INBOX", entries); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	fake := &fakeMailClient{overviews: overviewsFromEntries(entries)}

	rec1 := httptest.NewRecorder()
	srv.serveInbox(rec1, context.Background(), userID, fake, cache, cfg, "", count, 0, true, false)
	first := decodeInboxResponse(t, rec1)
	t.Logf("delta since=0 (cold client), bodies=0: %s", human(int64(rec1.Body.Len())))

	rec2 := httptest.NewRecorder()
	srv.serveInbox(rec2, context.Background(), userID, fake, cache, cfg, "", count, first.Cursor, true, false)
	t.Logf("delta since=%d (warm client, nothing changed): %s", first.Cursor, human(int64(rec2.Body.Len())))
}

// TestInboxWarmPathReachability probes the two preconditions mailcache.Snapshot
// puts on serving the inbox screen without touching IMAP, against the exact
// request the SPA sends (limit=500, no since=).
func TestInboxWarmPathReachability(t *testing.T) {
	cases := []struct {
		name       string
		cached     int
		classified bool
	}{
		{"500 cached, PGP-classified (handler-warmed)", 500, true},
		{"499 cached, PGP-classified (mailbox smaller than the page)", 499, true},
		{"500 cached, not PGP-classified (daemon-warmed)", 500, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t)
			all, _ := srv.users.List()
			cache := testInboxCache(t)
			entries := make([]mailcache.Entry, 0, tc.cached)
			for i := 0; i < tc.cached; i++ {
				entries = append(entries, mailcache.Entry{
					UID: i + 1, MessageID: fmt.Sprintf("%d", i+1),
					Subject: "s", Sender: "a@example.com", Status: "read",
					AtUTC: "2026-08-25T11:04:33Z", Body: "hello", BodyMode: "plain",
					PGPClassified: tc.classified,
				})
			}
			if err := cache.Upsert("INBOX", entries); err != nil {
				t.Fatalf("Upsert: %v", err)
			}
			fake := &fakeMailClient{}
			rec := httptest.NewRecorder()
			srv.serveInbox(rec, context.Background(), all[0].ID, fake, cache, config.Default(), "", 500, 0, false, true)
			t.Logf("cached=%d classified=%v -> live IMAP body fetches: %d (0 = served from cache)",
				tc.cached, tc.classified, fake.unreadCalls)
		})
	}
}

func overviewsFromEntries(entries []mailcache.Entry) []imapadapter.Overview {
	out := make([]imapadapter.Overview, 0, len(entries))
	for _, e := range entries {
		out = append(out, imapadapter.Overview{
			UID:       e.UID,
			MessageID: e.MessageID,
			Subject:   e.Subject,
			Sender:    e.Sender,
			Keywords:  e.Keywords,
			Status:    e.Status,
			AtUTC:     e.AtUTC,
		})
	}
	return out
}

// syntheticHTMLBody builds a marketing-email-shaped HTML body of about n bytes
// with realistic redundancy: repeated tag/class vocabulary, prose from a word
// list, and per-message unique tokens. A body of repeated "a" compresses ~100x
// and would make every gzip number here a lie.
func syntheticHTMLBody(seed, n int) string {
	if n <= 0 {
		return ""
	}
	words := strings.Fields("order shipped tracking details inside your package arrives thursday " +
		"unsubscribe preferences manage account view browser offer expires shop now " +
		"free returns members earn points rewards balance summary statement receipt " +
		"delivery address confirm update payment method saved cards billing history")
	rng := uint64(seed)*6364136223846793005 + 1442695040888963407
	next := func(mod int) int {
		rng = rng*6364136223846793005 + 1442695040888963407
		return int((rng >> 33) % uint64(mod))
	}
	var b strings.Builder
	b.Grow(n + 256)
	b.WriteString("<html><body style=\"margin:0;padding:0;background:#f4f4f4\">")
	for b.Len() < n {
		b.WriteString("<table class=\"row-")
		fmt.Fprintf(&b, "%d", next(1000))
		b.WriteString("\" cellpadding=\"0\"><tr><td style=\"font-family:Helvetica,Arial;font-size:14px\"><p>")
		for w := 0; w < 12+next(20); w++ {
			b.WriteString(words[next(len(words))])
			b.WriteByte(' ')
		}
		b.WriteString("</p><a href=\"https://click.example.com/t/")
		fmt.Fprintf(&b, "%016x", rng)
		b.WriteString("\">Shop now</a></td></tr></table>")
	}
	b.WriteString("</body></html>")
	return b.String()[:n]
}

func human(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
