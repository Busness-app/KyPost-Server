// Admission control for this package's memory-hard key derivations.
//
// The limit lives HERE, next to the primitive it bounds, and not in the HTTP
// layer that used to own it. It was a semaphore in package api that callers
// had to remember to wrap themselves, and the doc comment on it said "every
// path that performs scrypt in response to a request must use it" while
// listing four callers. It was not four. MFA confirmation, the re-auth used by
// every password-confirm flow, recovery-code generation (ten derivations in a
// single request), CardDAV app-password generation (authenticated, no lockout,
// no cost to repeat), the hash and PGP rewrap at the end of a password change,
// and administrative create/reset all reached the KDF without passing
// through it. A ceiling that half the callers walk around is not a ceiling, and
// the memory it was sized to bound is the thing that OOM-kills a container and
// takes every in-memory session with it.
//
// Nothing in this package derives a key except through withKDFSlot below, so
// forgetting is no longer possible: a new caller gets the limit by calling
// HashPassword or a Verify function at all.
package users

import (
	"context"
	"errors"
	"time"
)

// MaxConcurrentKDF bounds simultaneous memory-hard derivations process-wide.
// Each Argon2id derivation holds 64 MiB (legacy scrypt verifies hold 128 MiB),
// so this caps peak KDF memory at roughly MaxConcurrentKDF times that,
// regardless of how many callers arrive at once. The per-IP lockouts bound
// how many attempts an address may make; nothing bounded how many could be in
// flight together, which is what turns an auth endpoint into an OOM primitive
// on a memory-limited container.
//
// This is not the only admission gate an Argon2id derivation passes through.
// ky-primitives/password enforces its own independent budget below this one —
// password.MaxMemoryKiB (total memory across every derivation the library is
// running, in ANY process that links it), password.MaxLanes, and its own ~2 s
// wait — and a caller that already holds a kypost slot then queues inside
// that budget too. MaxConcurrentKDF*int(password.DefaultParams().Memory) must
// stay within password.MaxMemoryKiB, or this package will hand out slots the
// library then makes callers queue for anyway, doubling the wait instead of
// bounding it once; see TestMaxConcurrentKDFFitsWithinLibraryMemoryBudget in
// kdf_test.go.
const MaxConcurrentKDF = 4

// ErrKDFBusy means the derivation slots were saturated for longer than
// KDFMaxQueueWait. Callers must shed — answer 503 with Retry-After — and must
// not spend a lockout strike: the credential was never examined, so counting it
// would let a load spike lock out the users trying to sign in through it.
//
// It is returned rather than swallowed for a reason worth stating plainly: a
// caller that folds it into "false" reports "the server is overloaded" as "your
// password is wrong", which is both a lie and a lockout.
var ErrKDFBusy = errors.New("users: no key-derivation slot available")

// KDFMaxQueueWait bounds how long a caller may wait for a derivation slot. A
// var so tests can shrink it; production always uses the value below.
//
// Capping concurrent derivations caps scrypt's memory, but an unbounded queue
// replaces that with a backlog of goroutines and a drain time set by the
// attacker: four slots at ~200 ms makes two thousand queued logins a hundred
// seconds in which nobody can sign in, change a password, or reach CardDAV,
// since all of those paths share these slots. Neither ReadTimeout nor a client
// hanging up unblocks a goroutine parked on a channel send.
//
// Shedding is the honest answer — the server cannot currently afford to check
// this credential, which is a 503, not a 401. Sized at roughly ten derivations'
// worth of queue.
//
// This is only the FIRST of two waits a caller can pay before getting a slot.
// ky-primitives/password admits behind this one with its own ~2 s wait (see
// MaxConcurrentKDF's comment), so the worst case before a caller finally sees
// ErrKDFBusy is the SUM of the two waits, not just this one.
var KDFMaxQueueWait = 2 * time.Second

// kdfSlots is the semaphore itself: package-level, because the bound it
// enforces is a property of the process's memory, not of any one Store, Server
// or request. Two Stores over the same volume (the api and daemon processes
// each open one) still share this within a process.
var kdfSlots = make(chan struct{}, MaxConcurrentKDF)

// kdfSlotHeld marks a context whose goroutine already holds a slot, so a
// derivation started inside WithKDFSlot reuses it instead of taking a second.
//
// Without this, the composition deadlocks itself: a caller that wraps a region
// to time it or to batch several derivations under one slot would hold one and
// then block acquiring another, and with MaxConcurrentKDF such callers in
// flight every slot is held by something waiting for a slot. The marker makes
// re-entry free, which is also the right accounting — derivations nested inside
// one slot run one after another and never overlap in memory.
type kdfSlotHeld struct{}

// WithKDFSlot runs fn holding one derivation slot, so that every derivation fn
// performs shares it rather than queueing separately.
//
// Two callers need this rather than the implicit per-derivation acquisition:
// one that must MEASURE a derivation without billing the queue wait to it (the
// login budget in package api meters real seconds, and a two-second wait billed
// against a 200 ms reservation would let a burst empty the instance bucket),
// and one that performs several derivations in a row and should not re-queue
// between them.
//
// Returns ErrKDFBusy or ctx.Err() WITHOUT running fn.
func WithKDFSlot(ctx context.Context, fn func(context.Context)) error {
	if ctx.Value(kdfSlotHeld{}) != nil {
		fn(ctx)
		return nil
	}
	if err := acquireKDFSlot(ctx); err != nil {
		return err
	}
	defer func() { <-kdfSlots }()
	fn(context.WithValue(ctx, kdfSlotHeld{}, struct{}{}))
	return nil
}

// withKDFSlot is what every derivation in this package goes through. Same
// admission rules as WithKDFSlot, without handing the marked context back —
// the primitives have nothing to nest.
func withKDFSlot(ctx context.Context, fn func()) error {
	if ctx.Value(kdfSlotHeld{}) != nil {
		fn()
		return nil
	}
	if err := acquireKDFSlot(ctx); err != nil {
		return err
	}
	defer func() { <-kdfSlots }()
	fn()
	return nil
}

func acquireKDFSlot(ctx context.Context) error {
	// Check cancellation before queueing: a client that has already gone away
	// should not be given a slot ahead of one that is still waiting.
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(KDFMaxQueueWait)
	defer timer.Stop()
	select {
	case kdfSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ErrKDFBusy
	}
}
