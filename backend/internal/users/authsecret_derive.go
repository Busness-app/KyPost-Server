package users

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// authSecretInfo is the HKDF label the browser uses, and is what
// domain-separates the authentication half from anything else ever derived from
// the same PBKDF2 stretch. It MUST match AUTH_INFO in
// frontend/src/lib/authSecret.ts.
const authSecretInfo = "kypost/auth/v1"

// authSecretStretchBytes and authSecretBytes mirror STRETCH_BYTES and
// AUTH_SECRET_BYTES in frontend/src/lib/authSecret.ts.
const (
	authSecretStretchBytes = 32
	authSecretBytes        = 32
)

// DeriveAuthSecret reproduces, server-side, the value a browser derives from a
// password and the login parameters this server served it:
//
//	hex( HKDF-SHA256( PBKDF2-SHA256(password, base64decode(salt), iterations, 32),
//	                  salt = "", info = "kypost/auth/v1", 32 ) )
//
// It exists so UpgradeToDerivedAuth can CHECK the auth secret a client supplies
// instead of trusting it. The upgrade is the one moment the server holds both
// the plaintext password and the claimed secret, so it is the one moment the
// claim is verifiable — and without the check, anyone who knows the current
// password can pin the account to a credential of their own choosing.
//
// Must stay byte-for-byte in step with frontend/src/lib/authSecret.ts; the
// round-trip is pinned by TestUpgradeToDerivedAuthAcceptsTheGenuineDerivation.
func DeriveAuthSecret(password, loginSalt string, iterations int) (string, error) {
	if err := validateLoginSalt(loginSalt); err != nil {
		return "", err
	}
	if err := validateLoginIterations(iterations); err != nil {
		return "", err
	}
	salt, err := base64.StdEncoding.DecodeString(loginSalt)
	if err != nil {
		return "", fmt.Errorf("decode login salt: %w", err)
	}

	stretch := pbkdf2.Key([]byte(password), salt, iterations, authSecretStretchBytes, sha256.New)

	out := make([]byte, authSecretBytes)
	// Empty HKDF salt, matching the browser: the stretch is already
	// salted by PBKDF2, and the label is what provides separation.
	if _, err := hkdf.New(sha256.New, stretch, nil, []byte(authSecretInfo)).Read(out); err != nil {
		return "", fmt.Errorf("derive auth secret: %w", err)
	}
	return hex.EncodeToString(out), nil
}

// authSecretMatchesPassword reports whether authSecret is the genuine
// derivation of password under the given login parameters, in constant time.
func authSecretMatchesPassword(password, authSecret, loginSalt string, iterations int) error {
	expected, err := DeriveAuthSecret(password, loginSalt, iterations)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(authSecret)) != 1 {
		return errors.New("auth secret is not derived from the verified password")
	}
	return nil
}
