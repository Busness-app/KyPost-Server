package health

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// Status carries a slice, so a plain struct copy shares its backing array with
// whoever it came from — the same hazard users.clone() exists for on the account
// cache. Nothing here is about what the strings SAY; it is about two readers of
// one Service, or one caller and the Service, writing to the same memory.
//
// A FailureReason with spare capacity is what makes it bite: append then writes
// INTO the shared array instead of allocating a fresh one. The live callers
// today pass a single string literal, so their slice has len == cap and append
// reallocates — which is why this was latent rather than breaking. It is one
// `MarkUnhealthy(reasons...)` away from not being.

// unhealthyWithSpareCapacity marks the service unhealthy with a FailureReason
// whose cap exceeds its len, the shape that shares memory on append.
func unhealthyWithSpareCapacity(t *testing.T) *Service {
	t.Helper()
	reasons := make([]string, 1, 8)
	reasons[0] = "imap unreachable for all users"

	svc := NewService()
	svc.MarkUnhealthy(reasons...)
	return svc
}

// Two readers of the same Service must not be able to overwrite each other's
// data. This is the shape of two concurrent /api/health requests.
func TestGetStatusDoesNotShareItsFailureReasonArray(t *testing.T) {
	svc := unhealthyWithSpareCapacity(t)

	a := svc.GetStatus()
	b := svc.GetStatus()

	a.FailureReason = append(a.FailureReason, "reader-a")
	b.FailureReason = append(b.FailureReason, "reader-b")

	if got := a.FailureReason[len(a.FailureReason)-1]; got != "reader-a" {
		t.Fatalf("one reader's append overwrote another's: a ends with %q, want %q", got, "reader-a")
	}
}

// The Service must not keep a handle on a slice its caller still owns, or a
// caller reusing that slice silently rewrites the recorded health.
func TestSetStatusDoesNotKeepTheCallersSlice(t *testing.T) {
	reasons := make([]string, 1, 8)
	reasons[0] = "imap unreachable for all users"

	svc := NewService()
	svc.MarkUnhealthy(reasons...)

	reasons[0] = "something else entirely"

	if got := svc.GetStatus().FailureReason[0]; got != "imap unreachable for all users" {
		t.Fatalf("the caller rewrote the stored reason after the fact: %q", got)
	}
}

// MergeDaemonReport is a pure function over a caller-supplied Status. Appending
// to its input's slice mutates memory it does not own, whatever that memory
// happens to be.
func TestMergeDaemonReportDoesNotMutateItsInput(t *testing.T) {
	reasons := make([]string, 1, 8)
	reasons[0] = "imap unreachable for all users"
	in := Status{Healthy: false, FailureReason: reasons}

	got := MergeDaemonReport(in, "", time.Now())

	if len(in.FailureReason) != 1 || in.FailureReason[0] != "imap unreachable for all users" {
		t.Fatalf("the input Status was modified: %v", in.FailureReason)
	}
	// The spare capacity beyond the caller's len must be untouched too — that
	// is the memory an append would have scribbled on.
	if beyond := reasons[:2][1]; beyond != "" {
		t.Fatalf("wrote past the caller's slice into its spare capacity: %q", beyond)
	}
	if len(got.FailureReason) < 2 {
		t.Fatalf("the merged status lost its own reason: %v", got.FailureReason)
	}
}

// The reason the above matters at all: /api/health is served concurrently, and
// every request reads this one Service and then appends to what it got back.
// Run under -race, which CI does.
func TestConcurrentHealthReadsDoNotRace(t *testing.T) {
	svc := unhealthyWithSpareCapacity(t)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := MergeDaemonReport(svc.GetStatus(), "", time.Now())
			if len(st.FailureReason) == 0 {
				t.Error("merged status carried no reason")
				return
			}
			if !strings.Contains(strings.Join(st.FailureReason, " "), "daemon") {
				t.Errorf("merged status lost the daemon reason: %v", st.FailureReason)
			}
		}()
	}
	wg.Wait()
}
