package processor

import (
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/wkdpublish"
)

// recheckWKDInterval is how stale a verified claim may get before the ticker
// re-confirms its DNS TXT proof.
const recheckWKDInterval = 12 * time.Hour

// recheckWKDDomains re-confirms the instance's WKD domain claims against
// DNS, suspending any whose TXT proof has vanished and re-enabling any that
// reappear. The loop intentionally covers both verified and suspended
// claims — suspended ones need re-checking too, since that's how a claim
// re-enables once its TXT record reappears. Best-effort: every error is
// logged and swallowed, never affecting mail processing. A transient
// DNS/lookup error never flips a claim — only a definitive result (a
// successful lookup, whether or not it finds the token, or a confirmed
// NXDOMAIN/NODATA "not found" — see wkdpublish.CheckTXT) does.
//
// p.wkdStore is the SAME *wkdpublish.Store instance the API server uses
// (both are constructed once in app.go and injected), not a second Store
// opened over the same file — see wkdpublish.Store's doc comment for why
// that sharing matters.
func (p *Poller) recheckWKDDomains() {
	if p.wkdStore == nil {
		// Defensive only: app.go always injects a wkdStore in production.
		// Guards Poller values built without New() (e.g. test helpers that
		// construct &Poller{...} directly and never set wkdStore).
		return
	}
	store := p.wkdStore
	claims, err := store.List()
	if err != nil {
		// Nothing to re-check against: a claims file that will not read is a
		// state problem an operator has to see, not a quiet no-op behind a
		// stale in-memory copy.
		p.log.Error("wkd recheck: read claims failed", "error", err.Error())
		return
	}
	for _, c := range claims {
		// Only re-check claims that are due; a claim checked more
		// recently than recheckWKDInterval is left alone.
		if c.LastCheckedAt != "" {
			if last, perr := time.Parse(time.RFC3339, c.LastCheckedAt); perr == nil &&
				time.Since(last) < recheckWKDInterval {
				continue
			}
		}
		ok, cerr := wkdpublish.CheckTXT(c.Domain, c.Token)
		if cerr != nil {
			// DNS trouble: don't flip on a transient error; just log and
			// move on, leaving LastCheckedAt untouched so a genuinely
			// stale claim stays eligible for the next tick.
			p.log.Info("wkd recheck: lookup error", "domain", c.Domain, "error", cerr.Error())
			continue
		}
		if serr := store.SetVerified(c.Domain, ok, time.Now()); serr != nil {
			p.log.Error("wkd recheck: set verified failed", "domain", c.Domain, "error", serr.Error())
		}
	}
}
