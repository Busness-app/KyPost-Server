package api

import (
	"crypto/sha1"
	"fmt"
	"strings"

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
