package api

import (
	"encoding/base64"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// buildAutocryptHeader returns the value for an outbound "Autocrypt:" header
// advertising the sender's own public key: "addr=<from>; keydata=<base64>",
// where keydata is the binary (unarmored) public key. It returns ok=false —
// meaning "do not advertise" — when there is no key, the key does not parse,
// or the send address is not carried as a user ID on the key (Autocrypt
// requires addr to equal the From address). No prefer-encrypt is emitted.
func buildAutocryptHeader(pubKeyArmored, fromAddr string) (string, bool) {
	if strings.TrimSpace(pubKeyArmored) == "" {
		return "", false
	}
	key, err := crypto.NewKeyFromArmored(pubKeyArmored)
	if err != nil {
		return "", false
	}
	target := strings.ToLower(strings.TrimSpace(fromAddr))
	if target == "" {
		return "", false
	}
	entity := key.GetEntity()
	if entity == nil {
		return "", false
	}
	found := false
	for _, uid := range entity.Identities {
		if strings.ToLower(strings.TrimSpace(uid.UserId.Email)) == target {
			found = true
			break
		}
	}
	if !found {
		return "", false
	}
	binary, err := key.GetPublicKey()
	if err != nil {
		return "", false
	}
	return "addr=" + target + "; keydata=" + base64.StdEncoding.EncodeToString(binary), true
}
