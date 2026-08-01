package health

import "testing"

func TestNativePushSignalDefaultsToNotFailing(t *testing.T) {
	s := NewService()
	st := s.GetStatus()
	if st.NativePushFailing {
		t.Fatalf("fresh service should not report native push failing")
	}
	if st.NativePushLastError != "" || st.NativePushFailingAt != "" {
		t.Fatalf("no failure details expected on a fresh service, got err=%q at=%q", st.NativePushLastError, st.NativePushFailingAt)
	}
}

func TestRecordNativePushFailureRaisesAndStampsOnce(t *testing.T) {
	s := NewService()
	s.RecordNativePushFailure("relay unreachable")

	st := s.GetStatus()
	if !st.NativePushFailing {
		t.Fatalf("expected native push failing after a failure")
	}
	if st.NativePushLastError != "relay unreachable" {
		t.Fatalf("unexpected last error: %q", st.NativePushLastError)
	}
	firstStamp := st.NativePushFailingAt
	if firstStamp == "" {
		t.Fatalf("expected a failing-since timestamp")
	}

	// A later failure refreshes the reason but must not move the failing-since
	// stamp, so the signal reports how long the relay has been down.
	s.RecordNativePushFailure("relay 401")
	st = s.GetStatus()
	if st.NativePushFailingAt != firstStamp {
		t.Fatalf("failing-since should be stable across failures: %q -> %q", firstStamp, st.NativePushFailingAt)
	}
	if st.NativePushLastError != "relay 401" {
		t.Fatalf("expected refreshed last error, got %q", st.NativePushLastError)
	}
}

func TestRecordNativePushSuccessClearsFailure(t *testing.T) {
	s := NewService()
	s.RecordNativePushFailure("relay 500")
	s.RecordNativePushSuccess()

	st := s.GetStatus()
	if st.NativePushFailing {
		t.Fatalf("success should clear the failing flag")
	}
	if st.NativePushLastError != "" || st.NativePushFailingAt != "" {
		t.Fatalf("success should clear failure details, got err=%q at=%q", st.NativePushLastError, st.NativePushFailingAt)
	}
	if st.NativePushLastSuccess == "" {
		t.Fatalf("success should stamp last-success time")
	}
}

// The native-push signal is independent of the overall Healthy flag so a relay
// outage never flips Healthy (which drives container restarts).
func TestNativePushFailureDoesNotAffectHealthy(t *testing.T) {
	s := NewService()
	s.RecordNativePushFailure("relay down")
	if st := s.GetStatus(); !st.Healthy {
		t.Fatalf("native push failure must not flip overall Healthy")
	}
}

// Same contract as native push: the classifier signal reports a model that is
// missing or unreachable without flipping Healthy, which drives restarts that
// would not install it. It is sticky across MarkHealthy, and its timestamp is
// the first failure, not the latest.
func TestClassifierFailureIsStickyAndDoesNotAffectHealthy(t *testing.T) {
	s := NewService()
	s.RecordClassifierFailure()
	first := s.GetStatus()
	if !first.ClassifierFailing || first.ClassifierFailingAt == "" {
		t.Fatalf("failure not recorded: %+v", first)
	}
	if !first.Healthy {
		t.Fatal("a classifier failure must not flip overall Healthy")
	}

	s.MarkHealthy()
	s.RecordClassifierFailure()
	again := s.GetStatus()
	if !again.ClassifierFailing {
		t.Fatal("MarkHealthy cleared the sticky classifier flag")
	}
	if again.ClassifierFailingAt != first.ClassifierFailingAt {
		t.Fatalf("ClassifierFailingAt moved to the latest failure: %q -> %q", first.ClassifierFailingAt, again.ClassifierFailingAt)
	}

	s.RecordClassifierSuccess()
	if st := s.GetStatus(); st.ClassifierFailing || st.ClassifierFailingAt != "" {
		t.Fatalf("success did not clear the classifier flag: %+v", st)
	}
}
