package api

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"kypost-server/backend/internal/pgpmail"
)

// zBase32 is the alphabet from the Z-Base-32 encoding used by WKD.
const zBase32 = "ybndrfg8ejkmcpqxot1uwisza345h769"

// wkdHashLocalPart returns the WKD "hashed local-part": the lowercased
// local-part hashed with SHA-1 and encoded with Z-Base-32 (no padding).
func wkdHashLocalPart(localPart string) string {
	sum := sha1.Sum([]byte(strings.ToLower(localPart)))
	var b strings.Builder
	bits := 0
	var acc uint32
	for _, c := range sum {
		acc = acc<<8 | uint32(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			b.WriteByte(zBase32[(acc>>uint(bits))&0x1f])
		}
	}
	if bits > 0 {
		b.WriteByte(zBase32[(acc<<uint(5-bits))&0x1f])
	}
	return b.String()
}

// validateDiscoveredKey parses an armored public key obtained from an
// untrusted discovery source and confirms it is safe to auto-use for email:
// it must be usable (not revoked/expired) and actually carry email as a UID.
func validateDiscoveredKey(armored, email string) (string, error) {
	key, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		return "", fmt.Errorf("parse discovered key: %w", err)
	}
	status, err := pgpmail.CheckKeyStatus(armored)
	if err != nil {
		return "", err
	}
	if !status.Usable() {
		return "", fmt.Errorf("discovered key for %s is revoked or expired", email)
	}
	target := strings.ToLower(strings.TrimSpace(email))
	entity := key.GetEntity()
	if entity == nil {
		return "", fmt.Errorf("discovered key has no entity")
	}
	for _, uid := range entity.Identities {
		if strings.ToLower(strings.TrimSpace(uid.UserId.Email)) == target {
			return key.GetFingerprint(), nil
		}
	}
	return "", fmt.Errorf("discovered key does not carry %s as a user ID", email)
}

// wkdBaseURLOverride, when set (tests only), replaces the derived
// scheme+host so lookups hit an httptest.Server. Mirrors keyserverBaseURL.
var wkdBaseURLOverride string

// wkdCandidateURLs returns the advanced-method URL first, then the
// direct-method URL, for the given local-part/domain.
func wkdCandidateURLs(localPart, domain string) []string {
	hu := wkdHashLocalPart(localPart)
	l := url.QueryEscape(localPart)
	if wkdBaseURLOverride != "" {
		// Tests: single host serves the direct-method path.
		return []string{
			wkdBaseURLOverride + "/.well-known/openpgpkey/hu/" + hu + "?l=" + l,
		}
	}
	return []string{
		"https://openpgpkey." + domain + "/.well-known/openpgpkey/" + domain + "/hu/" + hu + "?l=" + l,
		"https://" + domain + "/.well-known/openpgpkey/hu/" + hu + "?l=" + l,
	}
}

// fetchWKDKey attempts Web Key Directory discovery for email, trying the
// advanced method then the direct method. It returns an armored public key
// validated to carry email as a UID and to be currently usable.
func fetchWKDKey(ctx context.Context, email string) (string, string, error) {
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return "", "", fmt.Errorf("invalid email %q", email)
	}
	localPart, domain := email[:at], email[at+1:]
	client := newSSRFSafeHTTPClient(10 * time.Second)

	var lastErr error
	for _, u := range wkdCandidateURLs(localPart, domain) {
		allowedSchemes := []string{"https"}
		if wkdBaseURLOverride != "" {
			allowedSchemes = []string{"http", "https"}
		}
		if err := validateOutboundURL(u, allowedSchemes...); err != nil {
			lastErr = fmt.Errorf("unsafe WKD URL: %w", err)
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || readErr != nil {
			lastErr = fmt.Errorf("wkd %s: status %d", u, resp.StatusCode)
			continue
		}
		key, err := crypto.NewKey(body) // WKD serves binary keys
		if err != nil {
			lastErr = fmt.Errorf("wkd %s: parse: %w", u, err)
			continue
		}
		armored, err := key.GetArmoredPublicKey()
		if err != nil {
			lastErr = err
			continue
		}
		fp, err := validateDiscoveredKey(armored, email)
		if err != nil {
			lastErr = err
			continue
		}
		return armored, fp, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no WKD key for %s", email)
	}
	return "", "", lastErr
}
