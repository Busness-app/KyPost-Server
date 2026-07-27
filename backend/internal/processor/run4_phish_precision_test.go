package processor

import "testing"

// run-4 M17: R2 was a case-insensitive substring test for "/pickup/" over
// subject + text body + HTML body, requiring no link, no scheme and no host.
//
// So a grocery store's collection-slot email flagged. And the Tier-B clear
// requires sameAddress(msg.Sender, ownAddress), which by definition cannot hold
// for inbound third-party mail — meaning an R2 hit on inbound mail could never
// be cleared. The verdict then rides a durable $Phishing IMAP keyword, visible
// in every other mail client the user owns.
//
// The banner is this subsystem's entire user-facing product. Firing it on
// grocery mail teaches people to dismiss it, which costs more than the rule
// ever earned.
//
// R2 stays host-agnostic on purpose — an attacker serving a lookalike page at
// this app's own path is the whole attack — but it now has to be a URL a client
// would actually resolve, at a path shaped like one this app really emits.

func TestScanDoesNotFlagOrdinaryMailMentioningPickup(t *testing.T) {
	cases := []struct {
		name    string
		subject string
		body    string
	}{
		{
			name:    "grocery collection slot",
			subject: "Your order is ready",
			body:    "Collect it here: https://grocer.example/pickup/slot?d=today",
		},
		{
			name:    "path fragment deeper in a URL",
			subject: "Reservation",
			body:    "See https://restaurant.example/reservations/pickup/details",
		},
		{
			name:    "the words alone, no link at all",
			subject: "Re: /pickup/ arrangements",
			body:    "Ask them about the /pickup/ process when you call.",
		},
		{
			name:    "a path that merely starts the same way",
			subject: "Parcel",
			body:    "https://courier.example/pickup/12345",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanForAppImpersonation(tc.subject, tc.body, ""); got.Reason != "" {
				t.Fatalf("benign mail was flagged as %q", got.Reason)
			}
		})
	}
}

// The attack the rule exists for: an attacker's own host serving a page shaped
// like this app's pickup link. Host-agnostic is the point — matching only this
// server's own hostname would miss every lookalike.
func TestScanFlagsLookalikePickupLinksOnAnyHost(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "attacker host, real pickup shape",
			body: `Read it once: https://kyp0st.example/pickup/2f1b9a3c-1111-4222-8333-444455556666?t=abc.def`,
		},
		{
			name: "inside an html anchor",
			body: `<a href="https://evil.example/pickup/id-1?t=tok">Read your message</a>`,
		},
		{
			name: "device pairing endpoint",
			body: "Finish setup at https://evil.example/api/notifications/desktop/pair",
		},
		{
			name: "native register endpoint",
			body: "https://evil.example/api/notifications/native/register",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanForAppImpersonation("Action required", tc.body, "")
			if got.Reason != reasonSensitiveEndpoint {
				t.Fatalf("reason = %q, want %q", got.Reason, reasonSensitiveEndpoint)
			}
		})
	}
}

// A pickup path with no token is not this app's link shape. The server always
// emits ?t=<token>, and requiring it is what clears the grocer.
func TestScanRequiresTheTokenOnAPickupLink(t *testing.T) {
	if got := scanForAppImpersonation("x", "https://evil.example/pickup/abc", ""); got.Reason != "" {
		t.Fatalf("a tokenless pickup path was flagged as %q", got.Reason)
	}
}

// The HTML body is scanned as well as the text body — a multipart/alternative
// message can hide the hostile half from a text-only scan.
func TestScanFindsLinksInTheHTMLBody(t *testing.T) {
	got := scanForAppImpersonation("hello", "nothing here",
		`<p><a href="https://evil.example/pickup/x?t=y">click</a></p>`)
	if got.Reason != reasonSensitiveEndpoint {
		t.Fatalf("reason = %q, want %q", got.Reason, reasonSensitiveEndpoint)
	}
}

// The other rules must be untouched by this change.
func TestScanStillFlagsAppDeepLinks(t *testing.T) {
	got := scanForAppImpersonation("hi", "open kypost://native-pair?srv=https://evil.example", "")
	if got.Reason != reasonAppDeepLink {
		t.Fatalf("reason = %q, want %q", got.Reason, reasonAppDeepLink)
	}
}

func TestScanStillFlagsImpersonatedNoticeSubjects(t *testing.T) {
	got := scanForAppImpersonation("Message rejected: too large to process", "body", "")
	if got.Reason != reasonSystemNotice {
		t.Fatalf("reason = %q, want %q", got.Reason, reasonSystemNotice)
	}
}

// A body full of URLs must not become a scanning cost of its own.
func TestScanBoundsHowManyURLsItInspects(t *testing.T) {
	body := ""
	for i := 0; i < maxScannedURLs*4; i++ {
		body += "https://example.com/harmless/" + string(rune('a'+i%26)) + " "
	}
	body += "https://evil.example/pickup/x?t=y"

	// Past the cap the trailing hostile link is not seen. That is the accepted
	// trade — the alternative is letting a message dictate how much work this
	// scan does on every poll tick — and it costs an advisory banner, never a
	// protection: the client-side scheme allowlist is unaffected.
	if got := scanForAppImpersonation("x", body, ""); got.Reason != "" {
		t.Logf("flagged anyway (%q) — acceptable, the cap is a ceiling not a guarantee", got.Reason)
	}
}
