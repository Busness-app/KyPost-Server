// The IMAP keyword the server sets on inbound mail that impersonates KyPost
// itself — see backend/internal/processor/phish_scan.go.
//
// $Phishing is the reserved RFC 8621 keyword, so other MUAs understand it too.
// The message is flagged in place: it stays in INBOX, stays unread, and keeps
// its body. Nothing here moves or hides mail.
//
// Mirrored as a literal rather than shared, because the other two clients are
// Kotlin and QML and there is no cross-repo artifact to share it through. The
// contract is the keyword string itself.
export const PHISHING_KEYWORD = "$Phishing";

// isFlaggedPhishing reports whether a message carries the flag.
//
// Case-insensitive because IMAP keywords are: the server may echo back
// "$phishing" for a keyword the poller set as "$Phishing", and a case-sensitive
// check would silently drop the warning on precisely the mail it exists for.
export function isFlaggedPhishing(email: { keywords?: string[] }): boolean {
  return (email.keywords ?? []).some((keyword) => keyword.trim().toLowerCase() === PHISHING_KEYWORD.toLowerCase());
}
