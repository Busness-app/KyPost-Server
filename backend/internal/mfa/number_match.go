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

// maxMatchAttempts is ONE. The first wrong number locks push approval for the
// challenge and the sign-in falls back to TOTP.
//
// The budget was three, justified as "leaving a 3% guess". That figure is the
// arithmetic for TYPING two blind digits — 3 draws from 100. The device is not
// asked to type: dispatchPushChallenge ships matchDigits alongside decoyCount
// decoys, so the approver picks from decoyCount+1 options. The real space is 3,
// not 100, and three draws from three is a blind-approval rate between 70% and
// 100% depending on whether the client greys out a tile it already tried.
//
// That is the MFA-fatigue attack this control exists to stop: an attacker
// holding the password triggers the sign-in, reads the number off their own
// browser, and needs only for the victim to tap something to make the
// notification go away.
//
// One draw makes the blind rate 1/(decoyCount+1) and makes a wrong tap
// terminal, which is the honest reading of the event — a device that answered
// with a number nobody at the real browser could have shown it is not a device
// that should get another go. The cost is a legitimate mis-tap finishing the
// sign-in on TOTP instead of on the phone, which is an inconvenience, not a
// lockout: push approval requires TOTP to be enabled first
// (handleMFAPushEnabled), so the fallback always exists.
//
// Raising this is not the way to make mis-taps cheaper. Raise decoyCount — but
// that is the shipped Android client's contract (MfaNumberMatch.optionsFor), so
// it moves in lockstep with a client release, not on its own.
const maxMatchAttempts = 1

// ErrMatchAttemptsExhausted reports that push approval is locked for this
// challenge: a wrong number was submitted, so the challenge will not be approved
// by push even with the right one. The challenge itself stays live for TOTP.
var ErrMatchAttemptsExhausted = errors.New("mfa: push approval is locked for this challenge; finish the sign-in with your authenticator")

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

// ResolvePushWithMatch records the one push decision a challenge gets, subject
// to the number-match check.
//
// An APPROVE must carry the challenge's own MatchDigits. A DENY does not: the
// safe answer has to stay available unconditionally, because the person most
// likely to press it is someone being MFA-fatigued who is looking at a number
// they cannot possibly match.
//
// A wrong number moves the challenge to PushLocked — terminal, and NOT the same
// as denied. The push channel is finished for this sign-in, but the challenge
// stays live so the browser can complete it with TOTP; handlePushRespond turns
// this into a 429 and LoginPage switches the form over.
//
// Locking on the first wrong number rather than counting toward a budget is the
// point of maxMatchAttempts — read its comment before adding retries back.
func (s *Store) ResolvePushWithMatch(id, deviceID string, approve bool, matchDigits string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.m[id]
	if !ok || time.Now().After(ch.ExpiresAt) {
		delete(s.m, id)
		return "", ErrChallengeNotFound
	}
	if isPushResolved(ch.PushStatus) {
		if ch.PushStatus == PushLocked {
			// Terminal, but not a decision anyone made — report it as the lock
			// it is so the device says "use your authenticator" rather than
			// "already answered".
			return ch.PushStatus, ErrMatchAttemptsExhausted
		}
		return ch.PushStatus, ErrChallengeAlreadyResolved
	}

	if approve {
		// Constant-time: the comparison is cheap and the value is short-lived,
		// but a length-or-prefix leak here would shrink an already small space.
		if subtle.ConstantTimeCompare([]byte(matchDigits), []byte(ch.MatchDigits)) != 1 {
			ch.MatchAttempts++
			ch.PushStatus = PushLocked
			ch.RespondedBy = deviceID
			s.m[id] = ch
			return PushLocked, ErrMatchAttemptsExhausted
		}
		ch.PushStatus = PushApproved
	} else {
		ch.PushStatus = PushDenied
	}
	ch.RespondedBy = deviceID
	s.m[id] = ch
	return ch.PushStatus, nil
}
