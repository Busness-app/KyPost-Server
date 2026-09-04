package imap

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	goimap "github.com/BrianLeishman/go-imap"

	"github.com/Busness-app/kypost-server/backend/internal/mailmsg"
)

// FetchRawMessage issues a raw UID FETCH for BODY.PEEK[] against uid in the
// currently selected mailbox — the complete, untouched RFC 5322 byte stream
// (headers + body, exactly as stored), not a MIME-parsed copy. This is
// deliberately distinct from every other body-reading path in this package
// (GetMessageBodies, ListOverviews, etc.), which all go through go-imap's
// own MIME parser: DKIM signature verification (see dkim_verify.go) must
// operate on the exact bytes a signature was originally computed over, and
// a re-parsed/re-serialized copy would not reliably reproduce them.
//
// This method is reached automatically, without any user click, from the
// poller's send-as verification sweep (processor.checkPendingSendAsAliases,
// once per pending alias per poll tick, for every message whose subject
// matched the alias's verification code) — the same "runs unattended against
// attacker-influenced mail" shape as ListUnreadInbox, so it gets the same
// server-side pre-fetch size bound: a "UID <uid> LARGER <cap>" SEARCH before
// ever issuing the raw FETCH, so an oversized message's literal is never
// requested from the server in the first place (unlike the post-fetch check
// in parseRawMessageRecord, which is kept below as defense-in-depth but
// can't undo buffering the underlying library already did by the time it
// runs).
// mailbox is explicit rather than "whatever is currently selected" because
// handlePGPPayload calls this with a mailbox taken from the request. An
// implicit selection there would fetch the requested UID out of whichever
// folder the connection last touched — a different message, returned as
// though it were the right one.
func (c *APIClient) FetchRawMessage(ctx context.Context, mailbox string, uid int) ([]byte, error) {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return nil, err
	}

	if err := c.selectMailboxLocked(d, mailbox); err != nil {
		return nil, err
	}

	sb := goimap.Search().UID(strconv.Itoa(uid)).Larger(int(mailmsg.MaxInboundMessageBytes))
	oversizedUIDs, err := d.SearchUIDs(sb)
	if err != nil {
		return nil, fmt.Errorf("imap search oversized: %w", err)
	}
	if len(oversizedUIDs) > 0 {
		return nil, mailmsg.ErrMessageTooLarge
	}

	cmd := "UID FETCH " + strconv.Itoa(uid) + " BODY.PEEK[]"
	raw, err := d.Exec(cmd, true, goimap.RetryCount, nil)
	if err != nil {
		return nil, fmt.Errorf("imap fetch raw message: %w", err)
	}

	records, err := d.ParseFetchResponse(raw)
	if err != nil {
		return nil, fmt.Errorf("imap fetch raw message: %w", err)
	}

	out, err := parseRawMessageRecord(records, uid)
	if err != nil {
		return nil, fmt.Errorf("imap fetch raw message: %w", err)
	}
	return out, nil
}

// parseRawMessageRecord extracts the full BODY[] literal for uid from parsed
// FETCH records — the pure logic behind FetchRawMessage, split out so it can
// be tested directly against synthetic records without a live IMAP
// connection. Mirrors parseHeaderFieldsRecords's token-walking approach (see
// auth_results.go for the verified token-shape notes that apply equally
// here), but matches on the bare "BODY[" marker (no HEADER.FIELDS clause)
// and returns the single matching UID's raw bytes rather than a per-UID
// slice of header lines.
func parseRawMessageRecord(records [][]*goimap.Token, uid int) ([]byte, error) {
	for _, tks := range records {
		tks = unwrapTokens(tks)

		var (
			recordUID  int
			uidFound   bool
			value      string
			valueFound bool
		)

		for i := 0; i < len(tks); i++ {
			t := tks[i]

			if strings.EqualFold(t.Str, "UID") {
				if i+1 >= len(tks) {
					return nil, fmt.Errorf("parse raw message: UID token has no following value")
				}
				if tks[i+1].Type != goimap.TNumber {
					return nil, fmt.Errorf("parse raw message: expected TNumber after UID, got %s", goimap.GetTokenName(tks[i+1].Type))
				}
				recordUID = tks[i+1].Num
				uidFound = true
				i++
				continue
			}

			// BODY[] marker (no HEADER.FIELDS clause): the value is the first
			// TAtom/TQuoted/TNil token that follows the "]" terminator.
			if strings.HasPrefix(strings.ToUpper(t.Str), "BODY[") {
				var got bool
				for j := i + 1; j < len(tks); j++ {
					switch tks[j].Type {
					case goimap.TNil:
						value = ""
						got = true
					case goimap.TAtom, goimap.TQuoted:
						value = tks[j].Str
						got = true
					}
					if got {
						break
					}
				}
				if !got {
					return nil, fmt.Errorf("parse raw message: BODY[] token has no value")
				}
				valueFound = true
			}
		}

		if !uidFound {
			return nil, fmt.Errorf("parse raw message: record has no UID token")
		}
		if recordUID != uid {
			continue
		}
		if !valueFound {
			return nil, fmt.Errorf("parse raw message: no BODY[] value found for UID %d", uid)
		}
		// Defense-in-depth: FetchRawMessage already runs a pre-fetch
		// "UID <uid> LARGER <cap>" SEARCH so an oversized message's literal
		// is normally never requested from the server at all. But the
		// message could have grown between that SEARCH and this FETCH, and
		// the goimap library itself has no size-limiting hook of its own
		// (its Exec/ParseFetchResponse always read the full BODY[] literal
		// off the wire into value, a Go string, before we ever see it
		// here), so this re-check is the last line of defense: refuse to
		// hand an oversized raw message on to the rest of the pipeline
		// (DKIM verification, send-as checks, etc.) rather than silently
		// processing it.
		if int64(len(value)) > mailmsg.MaxInboundMessageBytes {
			return nil, mailmsg.ErrMessageTooLarge
		}
		return []byte(value), nil
	}

	return nil, fmt.Errorf("parse raw message: no record found for UID %d", uid)
}
