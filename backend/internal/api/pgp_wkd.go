package api

import (
	"crypto/sha1"
	"strings"
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
