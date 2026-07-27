// Package sendas implements the per-user store of "send-as" email alias
// records: a user proves control of a secondary email address via an
// automatic background check (a later task), and once verified can send mail
// claiming that address as From. This package only stores and transitions
// Alias records — it has no knowledge of email sending or verification
// checking.
package sendas

// Alias is one send-as alias record: a secondary email address a user is
// proving control of, or has already proven control of.
type Alias struct {
	ID               string `json:"id"`
	UserID           string `json:"userId"`
	Email            string `json:"email"` // normalized lowercase
	DisplayName      string `json:"displayName,omitempty"`
	VerificationCode string `json:"verificationCode"` // embedded in the probe email's subject
	Status           string `json:"status"`           // "pending" | "verified" | "failed"
	CreatedAt        string `json:"createdAt"`
	ExpiresAt        string `json:"expiresAt"` // CreatedAt + 5 minutes; hard cutoff for "pending"
	VerifiedAt       string `json:"verifiedAt,omitempty"`
	FailedAt         string `json:"failedAt,omitempty"`

	// Auto marks a record the server created for the user rather than one the
	// user asked for: currently only the account's own address, probed
	// automatically so WKD publication (which requires this same proof for
	// every address) does not silently stop working for people who never
	// thought to challenge their own address. Two behaviours hang off it —
	// SweepTerminal keeps failed Auto records, because that record is the only
	// thing telling the user their address could not be proven, and the prober
	// reads FailedAt off it to back off rather than re-probing on a loop.
	Auto bool `json:"auto,omitempty"`
}
