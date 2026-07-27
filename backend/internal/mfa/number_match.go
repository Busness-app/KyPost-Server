package mfa

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// matchDigitCount is the length of the number-match value, fixed at 2 to match
// what the shipped Android client accepts: MfaChallengePayloadParser discards
// anything else, and MfaNumberMatch.optionsFor then returns null, which its own
// comment says "silently drops the screen back to a bare Approve button".
const matchDigitCount = 2

// decoyCount is how many wrong options accompany the right one, so the tap is a
// real choice rather than a single button wearing a number.
const decoyCount = 2

// maxMatchAttempts bounds wrong submissions per challenge. Two digits is a
// hundred possibilities and the challenge lives for minutes, so without a cap
// the endpoint is a workable oracle for anyone holding device credentials.
// Three keeps a legitimate mis-tap recoverable while leaving a 3% guess.
const maxMatchAttempts = 3

// ErrMatchDigitsMismatch reports that an approval did not carry the number
// shown in the browser that started the login.
var ErrMatchDigitsMismatch = errors.New("mfa: approval did not match the number shown in the browser")

// ErrMatchAttemptsExhausted reports that a challenge has absorbed too many
// wrong numbers and will not be approved even with the right one.
var ErrMatchAttemptsExhausted = errors.New("mfa: too many incorrect approval attempts for this challenge")

// newNumberMatch returns the value the browser displays plus distinct decoys,
// all two-digit, all from crypto/rand. Predictable values would let an attacker
// who triggered the login simply tell the victim which tile to press.
func newNumberMatch() (match string, decoys []string, err error) {
	match, err = randomTwoDigits()
	if err != nil {
		return "", nil, err
	}
	used := map[string]bool{match: true}
	decoys = make([]string, 0, decoyCount)
	for len(decoys) < decoyCount {
		candidate, cerr := randomTwoDigits()
		if cerr != nil {
			return "", nil, cerr
		}
		if used[candidate] {
			continue
		}
		used[candidate] = true
		decoys = append(decoys, candidate)
	}
	return match, decoys, nil
}

func randomTwoDigits() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", matchDigitCount, n.Int64()), nil
}

// ResolvePushWithMatch is ResolvePush with the number-match check.
//
// An APPROVE must carry the challenge's own MatchDigits. A DENY does not: the
// safe answer has to stay available unconditionally, because the person most
// likely to press it is someone being MFA-fatigued who is looking at a number
// they cannot possibly match.
//
// A wrong number is counted and refused, leaving the challenge pending so a
// legitimate mis-tap can be retried — until the attempt budget is spent, after
// which not even the correct value is accepted.
func (s *Store) ResolvePushWithMatch(id, deviceID string, approve bool, matchDigits string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.m[id]
	if !ok || time.Now().After(ch.ExpiresAt) {
		delete(s.m, id)
		return "", ErrChallengeNotFound
	}
	if ch.PushStatus == PushApproved || ch.PushStatus == PushDenied {
		return ch.PushStatus, ErrChallengeAlreadyResolved
	}

	if approve {
		if ch.MatchAttempts >= maxMatchAttempts {
			return "", ErrMatchAttemptsExhausted
		}
		// Constant-time: the comparison is cheap and the value is short-lived,
		// but a length-or-prefix leak here would shrink an already small space.
		if subtle.ConstantTimeCompare([]byte(matchDigits), []byte(ch.MatchDigits)) != 1 {
			ch.MatchAttempts++
			s.m[id] = ch
			if ch.MatchAttempts >= maxMatchAttempts {
				return "", ErrMatchAttemptsExhausted
			}
			return "", ErrMatchDigitsMismatch
		}
		ch.PushStatus = PushApproved
	} else {
		ch.PushStatus = PushDenied
	}
	ch.RespondedBy = deviceID
	s.m[id] = ch
	return ch.PushStatus, nil
}
