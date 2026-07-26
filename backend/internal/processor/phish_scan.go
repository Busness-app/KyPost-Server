package processor

import (
	"regexp"
	"strings"
)

// Anti-phishing Tier A: a pure, deterministic check for mail that impersonates
// this app itself.
//
// The threat is specific rather than general. Every client registers itself as
// the system handler for the kypost:// scheme (the Flatpak's
// x-scheme-handler/kypost, Android's native-pair intent filter), so an
// <a href="kypost://native-pair?srv=https://evil.example&pt=..."> in a message
// body used to route one click back into the app's own PairingController and
// raise the real pairing-confirm dialog naming an attacker's server -- phishing
// wearing the trusted UI.
//
// The clients now refuse non-allowlisted schemes on their own, unconditionally
// and with no server input. This scan exists to *tell the user why* a message
// is hostile, not to be the thing that stops it. That is why every rule here
// can afford to be conservative: a miss costs a banner, never the block.
//
// Deliberately not here: lookalike/homograph domains, anchor-text-vs-href
// mismatch scoring, urgency-language heuristics, reputation lists. Those are
// probabilistic, and this verdict is shown to the user as a statement of fact.
// The Ollama classifier is likewise never consulted -- a security verdict must
// not be non-deterministic, nor rationed by an LLM rate-limit budget.

// Reason strings reach both the user (as the client warning banner) and the
// audit log (the Decision's Detail, via GET /api/decisions), so they are
// phrased for a person rather than as error codes.
const (
	reasonAppDeepLink       = "contains a kypost:// app link"
	reasonSensitiveEndpoint = "links to a KyPost pairing or pickup endpoint"
	reasonSystemNotice      = "impersonates a KyPost system notice"
)

// phishFinding is the scan result. An empty Reason means clean -- there is no
// separate bool to fall out of sync with it.
type phishFinding struct {
	Reason string
}

// R1. The scheme punctuation is what makes this a link rather than the app's
// name in prose, so the separator is required: "kypost: notes from today" is an
// ordinary subject line, while "kypost://" is an attack. The alternations cover
// the encodings a sender can use in HTML and still have the client resolve a
// working URL -- raw colon, decimal entity (zero-padded or not), named entity,
// and percent-encoded colon -- plus a percent-encoded first slash.
//
// ponytail: this is not full HTML-entity/percent normalisation, so a
// sufficiently creative encoding will slip past. That is an accepted ceiling,
// not an oversight: the client-side scheme allowlist blocks the navigation
// regardless of what this regex thinks, so a bypass costs the user a missing
// banner and never the refusal itself. Normalising properly would mean
// reimplementing a browser's URL parser here, against untrusted input, to
// improve a message string.
var appDeepLinkPattern = regexp.MustCompile(`(?i)kypost\s*(?::|&#0*58;|&colon;|%3a)\s*(?:/|%2f)`)

// R2. Host-agnostic on purpose: the attacker's own host serving a lookalike
// page at this app's pairing or pickup path is the whole attack, so matching
// the path alone is the point. Trailing slash on /pickup/ keeps
// "/pickup-truck-review" clean.
//
// This will also fire on legitimate KyPost mail -- the server emails its own
// /pickup/ links. That is exactly why Tier B (DKIM over the account's own
// domain) gates the flag, and why the consequence for an https URL is advisory
// only.
var sensitiveEndpointPaths = []string{
	"/api/notifications/native/register",
	"/api/notifications/desktop/pair",
	"/pickup/",
}

// R3. The subjects this server actually sends to its own users. Matched whole
// (after trimming) rather than as substrings, so a genuine question quoting the
// wording -- "what does it mean when a message rejected: too large to
// process?" -- stays clean.
var impersonatedNoticeSubjects = []string{
	"Message rejected: too large to process",                        // poller.notifyMessageTooLarge
	"A newer Ollama version is available for your kypost container", // api/ollama_version.go
}

// The send-as verification notice carries a per-alias code, so it is matched by
// prefix rather than in the whole-subject list above.
const sendAsNoticeSubjectPrefix = "verify send-as: "

// scanForAppImpersonation reports whether this message impersonates KyPost.
//
// bodyText and bodyHTML are both taken because they are not interchangeable:
// the poller's own fetch (imap.ListUnreadInbox) prefers the text/plain part
// while every client-facing path prefers text/html, so a
// multipart/alternative message can show this scan an innocuous plain-text
// part while the clients render a hostile HTML one. Scanning either alone
// would miss the headline attack.
//
// First match wins, cheapest and most specific rule first.
func scanForAppImpersonation(subject, bodyText, bodyHTML string) phishFinding {
	haystack := subject + "\n" + bodyText + "\n" + bodyHTML

	if appDeepLinkPattern.MatchString(haystack) {
		return phishFinding{Reason: reasonAppDeepLink}
	}

	lowerHaystack := strings.ToLower(haystack)
	for _, path := range sensitiveEndpointPaths {
		if strings.Contains(lowerHaystack, path) {
			return phishFinding{Reason: reasonSensitiveEndpoint}
		}
	}

	trimmedSubject := strings.TrimSpace(subject)
	for _, notice := range impersonatedNoticeSubjects {
		if strings.EqualFold(trimmedSubject, notice) {
			return phishFinding{Reason: reasonSystemNotice}
		}
	}
	if strings.HasPrefix(strings.ToLower(trimmedSubject), sendAsNoticeSubjectPrefix) {
		return phishFinding{Reason: reasonSystemNotice}
	}

	return phishFinding{}
}
