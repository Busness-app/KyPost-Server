package processor

import (
	"context"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/mailcache"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/state"
)

// Anti-phishing Tier A: a pure, deterministic check for mail that impersonates
// this app itself.
//
// The threat is specific. Every client registers as the system handler for the
// kypost:// scheme (the Flatpak's x-scheme-handler/kypost, Android's
// native-pair intent filter), so an
// <a href="kypost://native-pair?srv=https://evil.example&pt=..."> in a message
// body is one click from the app's own pairing-confirm dialog naming an
// attacker's server: phishing wearing the trusted UI.
//
// The clients refuse non-allowlisted schemes themselves, with no server input.
// This scan exists to tell the user WHY a message is hostile, not to be what
// stops it — which is why every rule here can afford to be conservative. A miss
// costs a banner, never the block.
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
// ponytail: not full HTML-entity/percent normalisation, so a creative encoding
// slips past. Accepted ceiling: the client-side scheme allowlist blocks the
// navigation regardless, so a bypass costs a missing banner, never the refusal.
// Upgrade path: none — doing it properly means reimplementing a browser's URL
// parser against untrusted input to improve a message string.
var appDeepLinkPattern = regexp.MustCompile(`(?i)kypost\s*(?::|&#0*58;|&colon;|%3a)\s*(?:/|%2f)`)

// R2. Host-agnostic on purpose: an attacker's own host serving a lookalike
// page at this app's pairing or pickup path IS the attack, so the path alone is
// what matters.
//
// It must be a path in a URL a client would resolve, never a substring match.
// A false positive here is not cosmetic: the Tier-B clear requires
// sameAddress(msg.Sender, ownAddress), which inbound third-party mail can never
// satisfy, so a wrong hit can never be cleared and rides a durable $Phishing
// IMAP keyword into every other client the user owns. The banner is this
// subsystem's whole product; firing it on a grocer's collection-slot page
// teaches people to dismiss it.
var sensitiveEndpointPaths = []string{
	"/api/notifications/native/register",
	"/api/notifications/desktop/pair",
}

// pickupPathPrefix plus a non-empty "t" query parameter is the shape this
// server's own pickup links have (see api.sendPickupNotification:
// "<base>/pickup/<uuid>?t=<token>"). Requiring the token is what separates a
// lookalike from a shop's collection-slot page: an impersonation has to carry
// one to be convincing, and a grocer has no reason to.
const pickupPathPrefix = "/pickup/"

// urlPattern finds absolute http(s) URLs. Deliberately not a full URL grammar:
// it stops at whitespace and at the delimiters that end an href or a
// parenthesised link in prose.
var urlPattern = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>)\]]+`)

// maxScannedURLs bounds the work one message can demand. This runs on every
// unread message on every poll tick, and a body can carry an unbounded number
// of links. Past the cap a hostile link goes unseen, which costs an advisory
// banner and never a protection — the client-side scheme allowlist that
// actually refuses navigation is not involved here.
const maxScannedURLs = 200

// linksToSensitiveEndpoint reports whether haystack contains a URL pointing at
// one of this app's sensitive paths.
func linksToSensitiveEndpoint(haystack string) bool {
	matches := urlPattern.FindAllString(haystack, maxScannedURLs)
	for _, raw := range matches {
		// Trailing punctuation from prose ("...see https://x/y.") is not part
		// of the URL a client would resolve.
		u, err := url.Parse(strings.TrimRight(raw, ".,;:!?"))
		if err != nil {
			continue
		}
		path := strings.ToLower(u.Path)
		for _, sensitive := range sensitiveEndpointPaths {
			if path == sensitive || strings.HasPrefix(path, sensitive+"/") {
				return true
			}
		}
		if strings.HasPrefix(path, pickupPathPrefix) && strings.TrimSpace(u.Query().Get("t")) != "" {
			return true
		}
	}
	return false
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

	if linksToSensitiveEndpoint(haystack) {
		return phishFinding{Reason: reasonSensitiveEndpoint}
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

// phishKeyword is the durable verdict channel: an IMAP keyword, set on the
// message in the mailbox itself.
//
// Chosen over a new inboxEmail wire field or a mailcache.Entry field because it
// survives the mail cache's churning top-N window and poller restarts, is
// already carried to every client by bucket()'s entry.Keywords, is already
// inside mailcache's entryMeta (so Rev bumps exactly once when the flag lands
// and delta clients learn about it for free), and is removable by the user from
// the existing webmail keyword editor -- a no-code escape hatch for a false
// positive.
//
// $Phishing is the reserved RFC 8621 keyword, so other MUAs understand it too.
// Deliberately NOT added to config.Labels.Allowlist: collectAllowedKeywords
// must never turn it into a tab, because the message does not move -- not on
// disk, and not visually.
//
// IMAP keywords are case-insensitive, so every comparison against this must be
// too; a server may hand back "$phishing".
const phishKeyword = "$Phishing"

// decisionStatusFlaggedPhishing is the audit channel, alongside the existing
// "rejected_too_large" / "applied" / "failed" statuses. Nothing in the frontend
// switches on Status strings, so a new value costs nothing there.
const decisionStatusFlaggedPhishing = "flagged_phishing"

// applyPhishKeyword sets the flag on one message, once. See the call site for
// why this does not go through applySingleKeywordWithRetry's retry loop.
func applyPhishKeyword(ctx context.Context, c imapadapter.Client, messageID string) error {
	if err := c.EnsureLabel(ctx, phishKeyword); err != nil {
		return err
	}
	return c.ApplyLabel(ctx, messageID, phishKeyword)
}

// hasPhishKeyword reports whether this message already carries the flag,
// case-insensitively.
func hasPhishKeyword(keywords []string) bool {
	for _, kw := range keywords {
		if strings.EqualFold(strings.TrimSpace(kw), phishKeyword) {
			return true
		}
	}
	return false
}

// flagAppImpersonation is the poller's best-effort receive-side anti-phishing
// step, run once per newly-seen inbound message. Like harvestAutocrypt, it
// never returns an error -- every failure is logged and swallowed, so it can
// never disturb mail processing. It reports whether the message was flagged, so
// the caller can mirror the keyword into the mail cache.
//
// What "flagged" means, and does not mean: the message keeps its place in
// INBOX, its unread state, and its body. It is not moved, archived, filed to
// Junk, deleted, or bounced, and no notice is emailed. The user is told, and
// the client refuses the dangerous scheme on its own. That refusal is
// unconditional and needs nothing from here, which is what makes every step
// below safe to fail.
//
// ownAddress is the account's own full mail address, resolved once per tick by
// the caller rather than re-read per message.
func (p *Poller) flagAppImpersonation(ctx context.Context, uc userCtx, msg imapadapter.Message, ownAddress string) bool {
	// An oversized message's Body was deliberately left empty rather than
	// pulled into memory, so there is nothing to scan; rejectOversizedMessage
	// already owns this case.
	if msg.TooLarge {
		return false
	}
	// Already flagged on an earlier tick. handleMessage failures leave a
	// message unmarked and therefore re-seen, so without this the audit log
	// would gain a duplicate row (and burn a DNS lookup) every 90 seconds.
	if hasPhishKeyword(msg.Keywords) {
		return false
	}

	finding := scanForAppImpersonation(msg.Subject, msg.Body, msg.BodyHTML)
	if finding.Reason == "" {
		// The common case, and the reason this is affordable: ordinary mail
		// pays one regex plus three substring scans, and no network work at
		// all.
		return false
	}

	// Tier B. Only reached by mail that already looks like app impersonation,
	// so the DNS cost is paid on a vanishing fraction of messages. This server
	// emails its own notices (and its own /pickup/ links), so this is what
	// keeps a genuine notice from wearing a phishing warning.
	//
	// The gate requires BOTH a valid DKIM signature over the account's own
	// domain AND a From address equal to the account's own address. DKIM alone
	// was not enough, and was in fact no gate at all for most users: it keyed
	// on the *domain* of the account address, so for an account at
	// victim@gmail.com the domain is "gmail.com" and every message any Gmail
	// user sends carries a valid d=gmail.com signature. Any attacker with a
	// free account on the victim's own provider cleared the gate and got their
	// kypost:// deep link delivered with no banner. The same held for
	// outlook.com, yahoo.com, icloud.com — i.e. for most people connecting this
	// client to a mailbox they already had.
	//
	// Pairing the two closes that: a shared-domain provider will only DKIM-sign
	// a From header it authenticated the sender for, so "signed by the account
	// domain AND from the account's own address" means the account itself sent
	// it. Neither half is sufficient alone — a From address is trivially forged
	// without DKIM, and DKIM without the From check is the hole above.
	//
	// A DNS failure makes the real verifier fail closed, which leaves the
	// message flagged: fail-safe in verdict, fail-soft in consequence -- the
	// only cost is an advisory banner on legitimate mail, and the https link
	// still opens. Logged at Info, not Error, because it is not a malfunction.
	if ownDomain := domainOf(ownAddress); ownDomain != "" && sameAddress(msg.Sender, ownAddress) {
		if uid, err := strconv.Atoi(strings.TrimSpace(msg.ID)); err == nil {
			if raw, err := uc.mail.FetchRawMessage(ctx, uid); err == nil && len(raw) > 0 {
				if verifyDKIMForDomain(raw, ownDomain) {
					p.log.Info(
						"app-impersonation scan: message is DKIM-authenticated and from the account's own address, not flagging",
						"user_id", uc.id, "message_id", msg.ID, "domain", ownDomain, "reason", finding.Reason,
					)
					return false
				}
			} else if err != nil {
				p.log.Info("app-impersonation scan: raw fetch failed, treating as unauthenticated", "user_id", uc.id, "message_id", msg.ID, "error", err.Error())
			}
		}
	}

	detail := finding.Reason
	// A keyword the server refuses costs the banner, not the audit row, so the
	// failure is folded into Detail rather than returned.
	//
	// Single attempt, deliberately not applySingleKeywordWithRetry: that spends
	// 3 attempts x 30s, and a server without "PERMANENTFLAGS \*" refuses this
	// keyword every time. A burst of flagged mail would stall the whole poll
	// tick past its 8-minute context -- starving every other user's mail to
	// re-ask a server that already said no, for a banner the client-side scheme
	// allowlist does not need in order to block the attack.
	if err := applyPhishKeyword(ctx, uc.mail, msg.ID); err != nil {
		p.log.Error("app-impersonation scan: keyword apply failed", "user_id", uc.id, "message_id", msg.ID, "error", err.Error())
		detail += "; keyword could not be applied: " + err.Error()
	}
	if err := uc.store.AddDecision(state.Decision{
		MessageID: msg.ID,
		Sender:    msg.Sender,
		SentTo:    msg.SentTo,
		Subject:   msg.Subject,
		Status:    decisionStatusFlaggedPhishing,
		Detail:    detail,
	}); err != nil {
		p.log.Error("app-impersonation scan: failed to record decision", "user_id", uc.id, "message_id", msg.ID, "error", err.Error())
	}
	p.log.Info("app-impersonation scan: message flagged", "user_id", uc.id, "message_id", msg.ID, "sender", msg.Sender, "reason", finding.Reason)
	return true
}

// mirrorPhishKeyword writes the flag into the cached copy of a message.
//
// tickUser warms the mail cache from the whole fetched batch before the
// per-message loop runs, so a message flagged inside that loop would otherwise
// sit in the cache with stale keywords until the next tick. The webmail classic
// path reads that cache, so without this the warning would be up to a poll
// interval late on precisely the message the user is most likely to open now.
//
// Keywords is part of mailcache's entryMeta, so this bumps Rev exactly once and
// delta clients see one "updated" entry -- no new field and no diffing change.
// Best-effort: the IMAP keyword set above is the durable channel, so a cache
// failure costs only the immediacy.
func (p *Poller) mirrorPhishKeyword(cache *mailcache.Store, msg imapadapter.Message) {
	if cache == nil {
		return
	}
	// Copy rather than append in place: msg.Keywords shares its backing array
	// with the batch tickUser warmed the cache from, and mutating it would make
	// this mirror's effect depend on iteration order.
	flagged := msg
	flagged.Keywords = append(append(make([]string, 0, len(msg.Keywords)+1), msg.Keywords...), phishKeyword)
	if err := cache.Upsert("INBOX", mailCacheEntriesFromMessages([]imapadapter.Message{flagged})); err != nil {
		p.log.Error("app-impersonation scan: failed to mirror keyword into mail cache", "message_id", msg.ID, "error", err.Error())
	}
}

// sameAddress reports whether a message's From header names exactly the
// account's own address. sender arrives in whatever shape the IMAP server's
// envelope produced — bare "a@b.example", or `"Display Name" <a@b.example>` —
// so the angle-addr is extracted before comparing, and never the display name:
// a display name is entirely sender-controlled, so matching on it would let
// `From: "victim@gmail.com" <attacker@gmail.com>` clear the gate.
func sameAddress(sender, ownAddress string) bool {
	own := strings.ToLower(strings.TrimSpace(ownAddress))
	if own == "" {
		return false
	}
	candidate := strings.TrimSpace(sender)
	if parsed, err := mail.ParseAddress(candidate); err == nil {
		candidate = parsed.Address
	} else if i := strings.LastIndex(candidate, "<"); i >= 0 {
		// ParseAddress rejects some real-world envelope shapes (unquoted
		// display names containing punctuation, for one). Fall back to the
		// angle-addr rather than treating the whole string as an address,
		// which would compare the display name too.
		if j := strings.Index(candidate[i:], ">"); j > 0 {
			candidate = candidate[i+1 : i+j]
		}
	}
	return strings.EqualFold(strings.TrimSpace(candidate), own)
}

// accountAddress resolves the full mail address of the account itself, for the
// DKIM + From gate to authenticate against. Empty when it cannot be determined,
// which leaves a tripped message flagged rather than quietly cleared.
//
// Returns the whole address, not just its domain: the domain alone is not a
// usable identity on a shared provider — see the gate in flagAppImpersonation.
//
// A thin I/O shim on purpose: the account address lives in the sealed IMAP
// config, which no unit test in this package can construct. Keeping the read
// here and passing the resulting address into flagAppImpersonation as a plain
// string is what makes the actual decision logic testable.
func (p *Poller) accountAddress(userID string) string {
	payload, exists, err := mailmsg.ReadIMAPConfigPayload(p.userIMAPConfigPath(userID), p.imapKeyPath)
	if err != nil || !exists {
		return ""
	}
	return strings.TrimSpace(payload.Username)
}
