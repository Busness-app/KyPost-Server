package processor

import "testing"

// The attack this whole file exists for: a message body carrying this app's
// own pairing deep link, which each client registers itself as the system
// handler for. One click routes back into the app's own PairingController and
// raises the real pairing-confirm dialog naming the attacker's server.
func TestScanForAppImpersonationFlagsAppDeepLinks(t *testing.T) {
	cases := []struct {
		name     string
		subject  string
		bodyText string
		bodyHTML string
	}{
		{
			name:     "bare deep link in plain text",
			bodyText: "Confirm here: kypost://native-pair?sub=victim&srv=https://evil.example&pt=deadbeef",
		},
		{
			name:     "uppercase scheme",
			bodyText: "KYPOST://native-pair?sub=x",
		},
		{
			name:     "mixed case scheme",
			bodyText: "KyPost://native-pair?sub=x",
		},
		{
			name:     "html numeric entity colon",
			bodyHTML: `<a href="kypost&#58;//native-pair?sub=x">Confirm</a>`,
		},
		{
			name:     "html zero-padded numeric entity colon",
			bodyHTML: `<a href="kypost&#058;//native-pair?sub=x">Confirm</a>`,
		},
		{
			name:     "html named entity colon",
			bodyHTML: `<a href="kypost&colon;//native-pair?sub=x">Confirm</a>`,
		},
		{
			name:     "percent-encoded colon",
			bodyHTML: `<a href="kypost%3A//native-pair?sub=x">Confirm</a>`,
		},
		{
			name:     "percent-encoded slashes after literal colon",
			bodyHTML: `<a href="kypost:%2F%2Fnative-pair?sub=x">Confirm</a>`,
		},
		{
			name:    "deep link hidden in the subject",
			subject: "Action needed: kypost://native-pair?sub=x",
		},
		{
			// The regression that matters most. ListUnreadInbox prefers
			// e.Text while every client-facing path prefers e.HTML, so a
			// multipart/alternative message can show the poller an innocuous
			// plain-text part while the clients render the hostile HTML one.
			// Scanning only bodyText would miss exactly the goal attack.
			name:     "deep link only in the html part of a multipart message",
			bodyText: "Hi, please see the attached invoice. Thanks!",
			bodyHTML: `<p>Hi,</p><a href="kypost://native-pair?sub=v&srv=https://evil.example&pt=z">Confirm your KyPost account</a>`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanForAppImpersonation(tc.subject, tc.bodyText, tc.bodyHTML)
			if got.Reason == "" {
				t.Fatalf("expected a finding, got clean")
			}
			if got.Reason != reasonAppDeepLink {
				t.Fatalf("Reason = %q, want %q", got.Reason, reasonAppDeepLink)
			}
		})
	}
}

// A URL need not use the kypost scheme to be an attack: an https link to a
// lookalike page at this app's own pairing or pickup path is a
// copy-paste/credential-harvest lure. Matching is host-agnostic on purpose --
// the attacker's host is the whole point.
func TestScanForAppImpersonationFlagsSensitiveEndpointPaths(t *testing.T) {
	cases := []struct {
		name     string
		bodyText string
	}{
		{
			name:     "native register on a foreign host",
			bodyText: "Re-register here: https://evil.example/api/notifications/native/register",
		},
		{
			name:     "desktop pair on a foreign host",
			bodyText: "Pair now: https://evil.example/api/notifications/desktop/pair",
		},
		{
			name:     "pickup path on a foreign host",
			bodyText: "Your secure message: https://evil.example/pickup/abc123",
		},
		{
			name:     "case-insensitive path match",
			bodyText: "https://evil.example/API/Notifications/Native/Register",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanForAppImpersonation("", tc.bodyText, "")
			if got.Reason != reasonSensitiveEndpoint {
				t.Fatalf("Reason = %q, want %q", got.Reason, reasonSensitiveEndpoint)
			}
		})
	}
}

// The three subjects this server actually sends itself. A message wearing one
// of them is either genuinely ours (Tier B DKIM will clear it) or a forgery
// trading on the user's trust in the app's own voice.
func TestScanForAppImpersonationFlagsImpersonatedSystemNotices(t *testing.T) {
	cases := []struct {
		name    string
		subject string
	}{
		{
			name:    "too-large rejection notice",
			subject: "Message rejected: too large to process",
		},
		{
			name:    "ollama upgrade notice",
			subject: "A newer Ollama version is available for your kypost container",
		},
		{
			name:    "send-as verification prefix",
			subject: "Verify send-as: A1B2C3",
		},
		{
			name:    "subject match ignores surrounding whitespace",
			subject: "  Message rejected: too large to process  ",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanForAppImpersonation(tc.subject, "an ordinary body", "")
			if got.Reason != reasonSystemNotice {
				t.Fatalf("Reason = %q, want %q", got.Reason, reasonSystemNotice)
			}
		})
	}
}

// False positives cost the user a scary banner on legitimate mail, so the
// negatives are as load-bearing as the positives.
func TestScanForAppImpersonationLeavesOrdinaryMailClean(t *testing.T) {
	cases := []struct {
		name     string
		subject  string
		bodyText string
		bodyHTML string
	}{
		{
			name:     "empty message",
			subject:  "",
			bodyText: "",
			bodyHTML: "",
		},
		{
			name:     "ordinary newsletter",
			subject:  "Your weekly digest",
			bodyText: "Here are this week's stories. Unsubscribe: https://news.example/unsub?u=42",
			bodyHTML: `<h1>Digest</h1><a href="https://news.example/story/1">Read more</a>`,
		},
		{
			// The app's name in prose must not trip R1 -- only the scheme
			// punctuation does.
			name:     "app name mentioned in prose",
			bodyText: "I upgraded your kypost container last night and kypost is running fine.",
		},
		{
			// "kypost:" with no slash is ordinary sentence punctuation, e.g. a
			// mailing-list tag or a label followed by prose.
			name:     "app name followed by a colon in prose",
			subject:  "kypost: notes from today",
			bodyText: "kypost: the deploy went out at noon.",
		},
		{
			name:     "path that merely starts like the pickup path",
			bodyText: "See https://ok.example/pickup-truck-review and https://ok.example/pickups",
		},
		{
			name:     "system-notice wording as a substring rather than the subject",
			subject:  "Re: what does it mean when a message rejected: too large to process?",
			bodyText: "I got that error yesterday.",
		},
		{
			name:     "another app's scheme",
			bodyHTML: `<a href="slack://channel?id=C123">Open in Slack</a>`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanForAppImpersonation(tc.subject, tc.bodyText, tc.bodyHTML)
			if got.Reason != "" {
				t.Fatalf("expected clean, got Reason = %q", got.Reason)
			}
		})
	}
}

// Reason strings reach the user (client banner) and the audit log
// (GET /api/decisions), so which rule won has to be predictable.
func TestScanForAppImpersonationReportsTheDeepLinkWhenSeveralRulesMatch(t *testing.T) {
	got := scanForAppImpersonation(
		"Message rejected: too large to process",
		"https://evil.example/api/notifications/native/register",
		`<a href="kypost://native-pair?sub=x">Confirm</a>`,
	)
	if got.Reason != reasonAppDeepLink {
		t.Fatalf("Reason = %q, want the deep-link reason %q", got.Reason, reasonAppDeepLink)
	}
}
