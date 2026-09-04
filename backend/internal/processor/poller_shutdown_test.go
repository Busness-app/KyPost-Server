package processor

import (
	"context"
	"testing"
	"time"

	imapadapter "github.com/Busness-app/kypost-server/backend/internal/adapters/imap"
)

// Shutdown must actually reach the work, not just the loop that schedules it.
//
// Stop() cancels the poller's own context, and the tick used to run under
// context.Background() with an 8-minute timeout — so Stop returned instantly,
// Run's select exited, and the IMAP fetch, classifier call and state writes
// underneath carried on. Wait(), which shutdown blocks on, waited for exactly
// those. Against Docker's 10-second default grace period that meant routine
// restarts SIGKILLed mid-write.

// blockingMailbox blocks in ListUnreadInbox until its context is cancelled,
// standing in for an IMAP server that has accepted the connection and stopped
// answering. It is the shape that made the old bug survivable in testing: the
// call returns eventually, so nothing looks wrong until a shutdown has to wait
// for it.
type blockingMailbox struct {
	entered chan struct{}
	noopMailClient
}

func (m *blockingMailbox) ListUnreadInbox(ctx context.Context, checkpoint string) ([]imapadapter.Message, string, error) {
	select {
	case m.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, checkpoint, ctx.Err()
}

func TestTickIsCancelledByStop(t *testing.T) {
	mail := &blockingMailbox{entered: make(chan struct{}, 1)}
	p, u := newTickTestPoller(t, mail)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.tickUser(u, time.Time{})
	}()

	select {
	case <-mail.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the tick never reached the mailbox")
	}

	p.Stop()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not cancel the in-flight tick; shutdown would wait out the 8-minute timeout")
	}
}

// tick() is also reachable directly, from the admin "poll now" button
// (TriggerNow) and the unread sweep. Those do not go through Run's select, so
// without their own check a request arriving during shutdown starts a full tick
// that shutdown then waits for.
func TestTickRefusesToStartAfterStop(t *testing.T) {
	mail := &blockingMailbox{entered: make(chan struct{}, 1)}
	p, _ := newTickTestPoller(t, mail)

	p.Stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.tick()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tick started work after Stop")
	}

	select {
	case <-mail.entered:
		t.Fatal("a tick that started after Stop reached the mailbox")
	default:
	}
}
