package health

import (
	"sync"
	"time"
)

type Status struct {
	Healthy              bool     `json:"healthy"`
	UnhealthyFor         int64    `json:"unhealthyForSeconds"`
	LastCheckUTC         string   `json:"lastCheckUtc"`
	FailureReason        []string `json:"failureReason"`
	AICreditsExhausted   bool     `json:"aiCreditsExhausted"`
	AICreditsExhaustedAt string   `json:"aiCreditsExhaustedAt,omitempty"`

	// Native (mobile/FCM) push relay health. Independent of the overall Healthy
	// flag on purpose: a relay/key outage must not flip Healthy (which drives
	// container restarts) — it just surfaces here so it can't fail silently.
	// NativePushFailing defaults to false, so "off" and "working" both report
	// false; it goes true only when a configured relay actually fails.
	NativePushFailing     bool   `json:"nativePushFailing"`
	NativePushLastError   string `json:"nativePushLastError,omitempty"`
	NativePushFailingAt   string `json:"nativePushFailingAt,omitempty"`
	NativePushLastSuccess string `json:"nativePushLastSuccessUtc,omitempty"`

	// Classification health, on the same terms as native push: independent of
	// Healthy, because a server that cannot classify still delivers mail
	// perfectly well and restarting it every five minutes (which is what flipping
	// Healthy does) fixes nothing.
	//
	// It reports that classify attempts are FAILING, whatever the cause — the
	// configured model missing or still downloading, Ollama unreachable, an
	// upstream error, credits exhausted (which also raises the more specific flag
	// above). Read it as "labels are not being applied right now", not as a
	// model-install status. It exists because a model pull that failed at startup
	// showed up nowhere except a log line nobody was watching; every other cause
	// happens to need the same signal.
	//
	// No error text: the reason a classify call failed can carry an upstream
	// response body, and this struct is served to admins over /api/health.
	ClassifierFailing   bool   `json:"classifierFailing"`
	ClassifierFailingAt string `json:"classifierFailingAt,omitempty"`

	// Cross-process liveness. Under supervisord the poller runs as a separate
	// process with its own Service, so everything above that only the daemon
	// observes reaches the API through a stored DaemonReport (daemon.go).
	// DaemonHeartbeatUTC is when it last reported; DaemonStale means it has
	// stopped, and unlike the two subsystem flags it DOES flip Healthy —
	// nothing this server exists to do happens without the poller.
	DaemonHeartbeatUTC string `json:"daemonHeartbeatUtc,omitempty"`
	DaemonStale        bool   `json:"daemonStale,omitempty"`
}

type Service struct {
	mu             sync.Mutex
	status         Status
	unhealthySince *time.Time

	// AI-credits flag is sticky: it is preserved across SetStatus/MarkHealthy
	// calls and only changes via SetAICreditsExhausted / ClearAICreditsExhausted.
	aiCreditsExhausted   bool
	aiCreditsExhaustedAt string

	// Native-push relay state is sticky and independent of Healthy, updated only
	// via RecordNativePush{Success,Failure}.
	nativePushFailing     bool
	nativePushLastError   string
	nativePushFailingAt   string
	nativePushLastSuccess string

	// Classifier state, sticky and independent of Healthy, updated only via
	// RecordClassifier{Success,Failure}.
	classifierFailing   bool
	classifierFailingAt string
}

func NewService() *Service {
	now := time.Now().UTC().Format(time.RFC3339)
	return &Service{status: Status{Healthy: true, LastCheckUTC: now}}
}

func (s *Service) SetStatus(st Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.Healthy {
		s.unhealthySince = nil
		st.UnhealthyFor = 0
	} else if s.unhealthySince == nil {
		now := time.Now().UTC()
		s.unhealthySince = &now
	}
	st.LastCheckUTC = time.Now().UTC().Format(time.RFC3339)
	if s.unhealthySince != nil {
		st.UnhealthyFor = int64(time.Since(*s.unhealthySince).Seconds())
	}
	s.status = st
}

func (s *Service) MarkHealthy() {
	s.SetStatus(Status{Healthy: true, FailureReason: nil})
}

func (s *Service) MarkUnhealthy(reasons ...string) {
	s.SetStatus(Status{Healthy: false, FailureReason: reasons})
}

func (s *Service) GetStatus() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status
	if s.unhealthySince != nil {
		st.UnhealthyFor = int64(time.Since(*s.unhealthySince).Seconds())
	}
	st.LastCheckUTC = time.Now().UTC().Format(time.RFC3339)
	st.AICreditsExhausted = s.aiCreditsExhausted
	st.AICreditsExhaustedAt = s.aiCreditsExhaustedAt
	st.NativePushFailing = s.nativePushFailing
	st.NativePushLastError = s.nativePushLastError
	st.NativePushFailingAt = s.nativePushFailingAt
	st.NativePushLastSuccess = s.nativePushLastSuccess
	st.ClassifierFailing = s.classifierFailing
	st.ClassifierFailingAt = s.classifierFailingAt
	return st
}

// RecordClassifierSuccess clears the classifier flag: the model answered, so it
// is installed and reachable whatever happened before.
func (s *Service) RecordClassifierSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.classifierFailing = false
	s.classifierFailingAt = ""
}

// RecordClassifierFailure raises it. The first failure stamps ClassifierFailingAt
// and later ones leave it alone, so the field reports how long classification has
// been down — which is what distinguishes one bad message from a model that was
// never installed.
func (s *Service) RecordClassifierFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.classifierFailing {
		s.classifierFailing = true
		s.classifierFailingAt = time.Now().UTC().Format(time.RFC3339)
	}
}

// SetAICreditsExhausted raises the sticky AI-credits flag. It is independent of
// the healthy/unhealthy status so it survives MarkHealthy/MarkUnhealthy calls.
func (s *Service) SetAICreditsExhausted(atUTC string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.aiCreditsExhausted = true
	s.aiCreditsExhaustedAt = atUTC
}

// ClearAICreditsExhausted lowers the sticky AI-credits flag.
func (s *Service) ClearAICreditsExhausted() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.aiCreditsExhausted = false
	s.aiCreditsExhaustedAt = ""
}

// RecordNativePushSuccess clears the native-push failing flag after the relay
// accepts a send (or reports a token stale — either way the relay responded).
func (s *Service) RecordNativePushSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nativePushFailing = false
	s.nativePushLastError = ""
	s.nativePushFailingAt = ""
	s.nativePushLastSuccess = time.Now().UTC().Format(time.RFC3339)
}

// RecordNativePushFailure raises the native-push failing flag when a configured
// relay fails to deliver (unreachable, 401 orphaned key, 5xx, 429, timeout).
// The first failure stamps NativePushFailingAt; later ones only refresh the
// reason, so the flag reports how long the relay has been down.
func (s *Service) RecordNativePushFailure(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.nativePushFailing {
		s.nativePushFailing = true
		s.nativePushFailingAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.nativePushLastError = reason
}
