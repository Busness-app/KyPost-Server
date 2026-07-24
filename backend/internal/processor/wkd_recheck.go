package processor

import (
	"time"

	"kypost-server/backend/internal/wkdpublish"
)

// recheckWKDInterval is how stale a verified claim may get before the ticker
// re-confirms its DNS TXT proof.
const recheckWKDInterval = 12 * time.Hour

// recheckWKDDomains re-confirms every active user's WKD domain claims
// against DNS, suspending any whose TXT proof has vanished and re-enabling
// any that reappear. Best-effort: every error is logged and swallowed, never
// affecting mail processing. A DNS/lookup error never flips a claim — only a
// successful lookup that fails to find the token does.
func (p *Poller) recheckWKDDomains() {
	all, err := p.users.List()
	if err != nil {
		p.log.Error("wkd recheck: list users failed", "error", err.Error())
		return
	}
	for _, u := range all {
		if !u.Active {
			continue
		}
		store, err := wkdpublish.New(p.userStateDir(u.ID))
		if err != nil {
			p.log.Error("wkd recheck: open store failed", "user_id", u.ID, "error", err.Error())
			continue
		}
		for _, c := range store.List() {
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
}
