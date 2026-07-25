package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"kypost-server/backend/internal/fsutil"
)

type Store struct {
	mu                 sync.Mutex
	baseDir            string
	checkpoint         string
	processedSet       map[string]time.Time
	decisions          []Decision
	notifications      []NotificationSubscription
	notificationsDirty bool
	nativeDevices      []NativeDevice
	nativeDevicesDirty bool
	subscriberID       string
	nativeDeliveryMode string
	pullNotifications  []PullNotification
	pullSeq            int64
	pullDirty          bool

	aiCreditsExhausted          bool
	aiCreditsExhaustedAt        string
	ollamaUpdateNotifiedVersion string
	desktopPairingCodes         map[string]string // code -> expiresAt (RFC3339)
	pairingCodesDirty           bool
	desktopPairingAttempts      []PairingAttempt // tracks failed pairing attempts for rate limiting
	pairingAttemptsDirty        bool
}

type PairingAttempt struct {
	Code      string `json:"code"`      // the pairing code that was attempted
	AttemptAt string `json:"attemptAt"` // RFC3339 timestamp
	Success   bool   `json:"success"`   // whether the attempt succeeded
}

// Native notification delivery modes. "push" (the default) sends via the
// Cloudflare/Firebase relay; "pull" bypasses the relay entirely and instead
// queues notifications server-side for the mobile app to fetch over plain HTTP.
const (
	DeliveryModePush = "push"
	DeliveryModePull = "pull"
)

// maxPullNotifications bounds the per-user pull queue so an offline device can
// never grow the state file without limit; the oldest entries are dropped.
const maxPullNotifications = 100

type Decision struct {
	MessageID string `json:"messageId"`
	Sender    string `json:"sender"`
	SentTo    string `json:"sentTo,omitempty"`
	Subject   string `json:"subject"`
	Label     string `json:"label"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
	AtUTC     string `json:"atUtc"`
}

type NotificationSubscription struct {
	Endpoint  string `json:"endpoint"`
	Auth      string `json:"auth"`
	P256DH    string `json:"p256dh"`
	UserAgent string `json:"userAgent,omitempty"`
	UpdatedAt string `json:"updatedAt"`
}

type NativeDevice struct {
	DeviceID     string `json:"deviceId"`
	Platform     string `json:"platform"`
	PushToken    string `json:"pushToken"`
	DeviceName   string `json:"deviceName,omitempty"`
	AppVersion   string `json:"appVersion,omitempty"`
	UserAgent    string `json:"userAgent,omitempty"`
	RegisteredAt string `json:"registeredAt"`
	UpdatedAt    string `json:"updatedAt"`
	// UserID is a self-describing/defense-in-depth stamp of the owning user;
	// per-user isolation is already structural via the state directory layout.
	UserID string `json:"userId,omitempty"`
	// MFAApprover reports whether this device may approve/deny push-2FA login
	// challenges. New pairings set it true. Devices paired before this field
	// existed decode as false and are handled by the graceful-default rule at
	// challenge-fanout time (see api.approverDevices).
	MFAApprover bool `json:"mfaApprover"`
	// Transport specifies the push delivery transport: "fcm", "apns", or "unifiedpush".
	// Empty/absent means derive from Platform: "ios"/"macos" -> "apns", else "fcm".
	Transport string `json:"transport,omitempty"`
	// SecretHash is the scrypt-encoded hash (users.HashPassword format) of this
	// device's own pairing secret, minted once at registration. The raw secret
	// is never stored, only this hash, and it must never be serialized into an
	// API response — see Redacted().
	SecretHash string `json:"secretHash,omitempty"`
}

// Redacted returns a copy of d with SecretHash cleared, safe to serialize into
// an API response.
func (d NativeDevice) Redacted() NativeDevice {
	d.SecretHash = ""
	return d
}

// PullNotification is one queued notification awaiting an App Pull fetch. Seq
// is a per-user monotonic cursor the client advances so it never re-fetches a
// notification it has already seen.
type PullNotification struct {
	Seq       int64             `json:"seq"`
	Title     string            `json:"title"`
	Body      string            `json:"body"`
	Data      map[string]string `json:"data,omitempty"`
	CreatedAt string            `json:"createdAt"`
}

type stateFile struct {
	LastCheckpoint              string                     `json:"lastCheckpoint"`
	Processed                   map[string]string          `json:"processed"`
	Notifications               []NotificationSubscription `json:"notifications,omitempty"`
	NativeDevices               []NativeDevice             `json:"nativeDevices,omitempty"`
	SubscriberID                string                     `json:"subscriberId,omitempty"`
	NativeDeliveryMode          string                     `json:"nativeDeliveryMode,omitempty"`
	PullNotifications           []PullNotification         `json:"pullNotifications,omitempty"`
	PullSeq                     int64                      `json:"pullSeq,omitempty"`
	AICreditsExhausted          bool                       `json:"aiCreditsExhausted,omitempty"`
	AICreditsExhaustedAt        string                     `json:"aiCreditsExhaustedAt,omitempty"`
	OllamaUpdateNotifiedVersion string                     `json:"ollamaUpdateNotifiedVersion,omitempty"`
	DesktopPairingCodes         map[string]string          `json:"desktopPairingCodes,omitempty"`
	DesktopPairingAttempts      []PairingAttempt           `json:"desktopPairingAttempts,omitempty"`
}

func New(baseDir string) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		baseDir:                baseDir,
		processedSet:           map[string]time.Time{},
		decisions:              []Decision{},
		desktopPairingCodes:    map[string]string{},
		desktopPairingAttempts: []PairingAttempt{},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	if err := s.loadDecisions(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) path() string {
	return filepath.Join(s.baseDir, "state.json")
}

func (s *Store) decisionsPath() string {
	return filepath.Join(s.baseDir, "decisions.json")
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s.persistLocked()
		}
		return err
	}
	var sf stateFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return err
	}
	s.applyStateFile(sf)
	return nil
}

func (s *Store) applyStateFile(sf stateFile) {
	s.checkpoint = sf.LastCheckpoint
	s.aiCreditsExhausted = sf.AICreditsExhausted
	s.aiCreditsExhaustedAt = sf.AICreditsExhaustedAt
	s.ollamaUpdateNotifiedVersion = sf.OllamaUpdateNotifiedVersion
	s.subscriberID = strings.TrimSpace(sf.SubscriberID)
	s.notifications = append([]NotificationSubscription{}, sf.Notifications...)
	s.notificationsDirty = false
	s.nativeDevices = append([]NativeDevice{}, sf.NativeDevices...)
	s.nativeDevicesDirty = false
	s.nativeDeliveryMode = normalizeDeliveryMode(sf.NativeDeliveryMode)
	s.pullNotifications = append([]PullNotification{}, sf.PullNotifications...)
	s.pullSeq = sf.PullSeq
	s.pullDirty = false

	processed := make(map[string]time.Time, len(sf.Processed))
	for id, ts := range sf.Processed {
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		processed[id] = t
	}
	s.processedSet = processed

	// Load desktop pairing codes, removing expired ones
	now := time.Now().UTC()
	validCodes := make(map[string]string)
	for code, expiresAtStr := range sf.DesktopPairingCodes {
		expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
		if err != nil {
			continue
		}
		if expiresAt.After(now) {
			validCodes[code] = expiresAtStr
		}
	}
	s.desktopPairingCodes = validCodes
	s.pairingCodesDirty = len(validCodes) < len(sf.DesktopPairingCodes)

	// Load pairing attempts, removing old ones (keep last 24 hours for rate limiting)
	cutoff := now.Add(-24 * time.Hour)
	validAttempts := make([]PairingAttempt, 0, len(sf.DesktopPairingAttempts))
	for _, attempt := range sf.DesktopPairingAttempts {
		attemptAt, err := time.Parse(time.RFC3339, attempt.AttemptAt)
		if err != nil {
			continue
		}
		if attemptAt.After(cutoff) {
			validAttempts = append(validAttempts, attempt)
		}
	}
	s.desktopPairingAttempts = validAttempts
	s.pairingAttemptsDirty = len(validAttempts) < len(sf.DesktopPairingAttempts)
}

func (s *Store) refreshStateFromDiskLocked() error {
	b, err := os.ReadFile(s.path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	var sf stateFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return err
	}
	s.applyStateFile(sf)
	return nil
}

func (s *Store) refreshNotificationsFromDiskLocked() error {
	b, err := os.ReadFile(s.path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	var sf struct {
		Notifications []NotificationSubscription `json:"notifications,omitempty"`
	}
	if err := json.Unmarshal(b, &sf); err != nil {
		return err
	}
	s.notifications = append([]NotificationSubscription{}, sf.Notifications...)
	s.notificationsDirty = false
	return nil
}

func (s *Store) refreshNativeDevicesFromDiskLocked() error {
	b, err := os.ReadFile(s.path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	var sf struct {
		NativeDevices []NativeDevice `json:"nativeDevices,omitempty"`
	}
	if err := json.Unmarshal(b, &sf); err != nil {
		return err
	}
	s.nativeDevices = append([]NativeDevice{}, sf.NativeDevices...)
	s.nativeDevicesDirty = false
	return nil
}

func (s *Store) refreshPullFromDiskLocked() error {
	b, err := os.ReadFile(s.path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	var sf struct {
		NativeDeliveryMode string             `json:"nativeDeliveryMode,omitempty"`
		PullNotifications  []PullNotification `json:"pullNotifications,omitempty"`
		PullSeq            int64              `json:"pullSeq,omitempty"`
	}
	if err := json.Unmarshal(b, &sf); err != nil {
		return err
	}
	s.nativeDeliveryMode = normalizeDeliveryMode(sf.NativeDeliveryMode)
	s.pullNotifications = append([]PullNotification{}, sf.PullNotifications...)
	s.pullSeq = sf.PullSeq
	s.pullDirty = false
	return nil
}

// normalizeDeliveryMode coerces any stored/requested value to a known mode,
// defaulting to push so an absent or unrecognized value never disables
// notifications.
func normalizeDeliveryMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), DeliveryModePull) {
		return DeliveryModePull
	}
	return DeliveryModePush
}

// update runs mutate as one read-modify-write cycle over state.json,
// holding both the in-process mutex and the inter-process file lock for the
// whole cycle, refreshing from disk first and persisting after.
//
// Both halves of that lock are required. Per-user state.json is written by
// the api process (device pairing, notification subscriptions, delivery
// mode) AND by the daemon process (MarkProcessed on every classified
// message, pull-notification enqueue) — see supervisord.conf. Refreshing
// from disk before mutating narrows the lost-update window but does not
// close it; only holding a lock across read, mutate, and write does.
//
// Every mutator in this file must go through here rather than hand-rolling
// the refresh/persist pair.
func (s *Store) update(mutate func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fsutil.WithFileLock(s.path(), func() error {
		if err := s.refreshStateFromDiskLocked(); err != nil {
			return err
		}
		if err := mutate(); err != nil {
			return err
		}
		return s.persistLocked()
	})
}

// Cleanup is the one operation here that touches both files, so it takes
// both locks. Lock order is state.json then decisions.json; nothing takes
// them the other way round (AddDecision takes decisions.json alone), so
// there is no deadlock. Both are refreshed from disk before trimming — a
// stale in-memory decisions slice trimmed and written back would silently
// drop everything the other process appended since this Store last read it.
func (s *Store) Cleanup(keepDays int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fsutil.WithFileLock(s.path(), func() error {
		if err := s.refreshStateFromDiskLocked(); err != nil {
			return err
		}
		return fsutil.WithFileLock(s.decisionsPath(), func() error {
			if err := s.refreshDecisionsFromDiskLocked(); err != nil {
				return err
			}
			cutoff := time.Now().Add(-time.Duration(keepDays) * 24 * time.Hour)
			for id, ts := range s.processedSet {
				if ts.Before(cutoff) {
					delete(s.processedSet, id)
				}
			}
			trimmed := make([]Decision, 0, len(s.decisions))
			for _, d := range s.decisions {
				t, err := time.Parse(time.RFC3339, d.AtUTC)
				if err != nil || !t.Before(cutoff) {
					trimmed = append(trimmed, d)
				}
			}
			s.decisions = trimmed
			if err := s.persistDecisionsLocked(); err != nil {
				return err
			}
			return s.persistLocked()
		})
	})
}

func (s *Store) Seen(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.processedSet[id]
	return ok
}

func (s *Store) MarkProcessed(id string) error {
	return s.update(func() error {
		s.processedSet[id] = time.Now().UTC()
		return nil
	})
}

func (s *Store) SetCheckpoint(value string) error {
	return s.update(func() error {
		s.checkpoint = value
		return nil
	})
}

func (s *Store) Checkpoint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkpoint
}

func (s *Store) GetOrCreateSubscriberID() (string, error) {
	var id string
	err := s.update(func() error {
		if s.subscriberID != "" {
			id = s.subscriberID
			return nil
		}
		fresh, err := fsutil.NewUUIDv4()
		if err != nil {
			return err
		}
		s.subscriberID = fresh
		id = fresh
		return nil
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// NativeDeliveryMode returns the active native delivery mode ("push" or
// "pull"), reading through to disk so a mode change made by the API server is
// picked up by the poller running in the same process.
func (s *Store) NativeDeliveryMode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshPullFromDiskLocked()
	return normalizeDeliveryMode(s.nativeDeliveryMode)
}

// SetNativeDeliveryMode persists the native delivery mode. Unknown values are
// coerced to push.
func (s *Store) SetNativeDeliveryMode(mode string) error {
	return s.update(func() error {
		s.nativeDeliveryMode = normalizeDeliveryMode(mode)
		s.pullDirty = true
		return nil
	})
}

// EnqueuePullNotification appends a notification to the App Pull queue, stamping
// it with the next sequence number and trimming the queue to its bound.
func (s *Store) EnqueuePullNotification(n PullNotification) error {
	return s.update(func() error {
		s.pullSeq++
		n.Seq = s.pullSeq
		if strings.TrimSpace(n.CreatedAt) == "" {
			n.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		s.pullNotifications = append(s.pullNotifications, n)
		if len(s.pullNotifications) > maxPullNotifications {
			s.pullNotifications = s.pullNotifications[len(s.pullNotifications)-maxPullNotifications:]
		}
		s.pullDirty = true
		return nil
	})
}

// PullNotificationsAfter returns queued notifications with Seq greater than
// after, together with the current cursor (the highest assigned sequence). The
// client advances after to the returned cursor between polls.
func (s *Store) PullNotificationsAfter(after int64) ([]PullNotification, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshPullFromDiskLocked()
	out := make([]PullNotification, 0, len(s.pullNotifications))
	for _, n := range s.pullNotifications {
		if n.Seq > after {
			out = append(out, n)
		}
	}
	return out, s.pullSeq
}

func (s *Store) AddDecision(d Decision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// decisions.json is its own file with its own lock. It is appended to by
	// the daemon on every classification and read by the api for the audit
	// view, so it needs the same cross-process serialization as state.json —
	// and it must re-read before appending, or the daemon's in-memory slice
	// silently overwrites anything the api wrote.
	return fsutil.WithFileLock(s.decisionsPath(), func() error {
		if err := s.refreshDecisionsFromDiskLocked(); err != nil {
			return err
		}
		if d.AtUTC == "" {
			d.AtUTC = time.Now().UTC().Format(time.RFC3339)
		}
		s.decisions = append(s.decisions, d)
		return s.persistDecisionsLocked()
	})
}

// refreshDecisionsFromDiskLocked re-reads decisions.json. A missing file is
// not an error (nothing has been recorded yet).
func (s *Store) refreshDecisionsFromDiskLocked() error {
	b, err := os.ReadFile(s.decisionsPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var d []Decision
	if err := json.Unmarshal(b, &d); err != nil {
		return err
	}
	s.decisions = d
	return nil
}

func (s *Store) Decisions(limit int) []Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.decisions) == 0 {
		return []Decision{}
	}
	out := make([]Decision, len(s.decisions))
	copy(out, s.decisions)
	// Compare parsed instants, not RFC3339 strings. String ordering only
	// happens to work while every value is UTC with identical formatting;
	// one offset-bearing or fractional-second timestamp written by any
	// future call site would silently scramble the ordering instead of
	// failing. An unparseable timestamp sorts last (zero time) rather than
	// taking the whole sort with it.
	at := func(d Decision) time.Time {
		t, err := time.Parse(time.RFC3339, d.AtUTC)
		if err != nil {
			return time.Time{}
		}
		return t
	}
	sort.SliceStable(out, func(i, j int) bool {
		return at(out[i]).After(at(out[j]))
	})
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}

func (s *Store) ProcessedSince(since time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, processedAt := range s.processedSet {
		if !processedAt.Before(since) {
			count++
		}
	}
	return count
}

func (s *Store) persistLocked() error {
	if !s.notificationsDirty {
		if err := s.refreshNotificationsFromDiskLocked(); err != nil {
			return err
		}
	}
	if !s.nativeDevicesDirty {
		if err := s.refreshNativeDevicesFromDiskLocked(); err != nil {
			return err
		}
	}
	if !s.pullDirty {
		if err := s.refreshPullFromDiskLocked(); err != nil {
			return err
		}
	}

	processed := make(map[string]string, len(s.processedSet))
	for id, ts := range s.processedSet {
		processed[id] = ts.Format(time.RFC3339)
	}
	b, err := json.MarshalIndent(stateFile{
		LastCheckpoint:              s.checkpoint,
		Processed:                   processed,
		Notifications:               s.notifications,
		NativeDevices:               s.nativeDevices,
		SubscriberID:                s.subscriberID,
		NativeDeliveryMode:          s.nativeDeliveryMode,
		PullNotifications:           s.pullNotifications,
		PullSeq:                     s.pullSeq,
		AICreditsExhausted:          s.aiCreditsExhausted,
		AICreditsExhaustedAt:        s.aiCreditsExhaustedAt,
		OllamaUpdateNotifiedVersion: s.ollamaUpdateNotifiedVersion,
		DesktopPairingCodes:         s.desktopPairingCodes,
		DesktopPairingAttempts:      s.desktopPairingAttempts,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := fsutil.AtomicWriteFile(s.path(), b, 0o600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	s.notificationsDirty = false
	s.nativeDevicesDirty = false
	s.pullDirty = false
	return nil
}

func (s *Store) ListNotificationSubscriptions() []NotificationSubscription {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshNotificationsFromDiskLocked()
	out := make([]NotificationSubscription, len(s.notifications))
	copy(out, s.notifications)
	return out
}

func (s *Store) UpsertNotificationSubscription(sub NotificationSubscription) error {
	return s.update(func() error {
		s.notificationsDirty = true
		for i, existing := range s.notifications {
			if existing.Endpoint == sub.Endpoint {
				s.notifications[i] = sub
				return nil
			}
		}
		s.notifications = append(s.notifications, sub)
		return nil
	})
}

func (s *Store) RemoveNotificationSubscription(endpoint string) (bool, error) {
	removed := false
	err := s.update(func() error {
		for i, sub := range s.notifications {
			if sub.Endpoint != endpoint {
				continue
			}
			s.notifications = append(s.notifications[:i], s.notifications[i+1:]...)
			s.notificationsDirty = true
			removed = true
			return nil
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return removed, nil
}

func (s *Store) ListNativeDevices() []NativeDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshNativeDevicesFromDiskLocked()
	out := make([]NativeDevice, len(s.nativeDevices))
	copy(out, s.nativeDevices)
	return out
}

func (s *Store) UpsertNativeDevice(device NativeDevice) error {
	return s.update(func() error { return s.upsertNativeDeviceLocked(device) })
}

func (s *Store) upsertNativeDeviceLocked(device NativeDevice) error {
	device.DeviceID = strings.TrimSpace(device.DeviceID)
	device.Platform = strings.ToLower(strings.TrimSpace(device.Platform))
	device.PushToken = strings.TrimSpace(device.PushToken)
	if device.DeviceID == "" {
		id, err := fsutil.NewUUIDv4()
		if err != nil {
			return err
		}
		device.DeviceID = id
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if strings.TrimSpace(device.RegisteredAt) == "" {
		device.RegisteredAt = now
	}
	device.UpdatedAt = now

	for i, existing := range s.nativeDevices {
		if existing.DeviceID == device.DeviceID {
			if device.RegisteredAt == "" {
				device.RegisteredAt = existing.RegisteredAt
			}
			// A re-registration (e.g. routine push-token refresh) must not
			// silently undo an explicit MFAApprover choice made via
			// SetNativeDeviceMFAApprover — only that dedicated endpoint may
			// change approver status for an already-known device.
			device.MFAApprover = existing.MFAApprover
			s.nativeDevices[i] = device
			s.nativeDevicesDirty = true
			return nil
		}
	}

	// Same push token + platform is the same physical device re-registering
	// without its device ID (e.g. a re-pair from a fresh deep link): update
	// that row in place instead of pairing the device a second time.
	if device.PushToken != "" {
		for i, existing := range s.nativeDevices {
			if existing.PushToken == device.PushToken && existing.Platform == device.Platform {
				device.DeviceID = existing.DeviceID
				device.RegisteredAt = existing.RegisteredAt
				device.MFAApprover = existing.MFAApprover
				s.nativeDevices[i] = device
				s.nativeDevicesDirty = true
				return nil
			}
		}
	}

	s.nativeDevices = append(s.nativeDevices, device)
	s.nativeDevicesDirty = true
	return nil
}

func (s *Store) RemoveNativeDevice(deviceID string) (bool, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return false, nil
	}
	removed := false
	err := s.update(func() error {
		for i, device := range s.nativeDevices {
			if device.DeviceID != deviceID {
				continue
			}
			s.nativeDevices = append(s.nativeDevices[:i], s.nativeDevices[i+1:]...)
			s.nativeDevicesDirty = true
			removed = true
			return nil
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return removed, nil
}

// GetNativeDevice returns a single device by ID, reading through to disk.
func (s *Store) GetNativeDevice(deviceID string) (NativeDevice, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshNativeDevicesFromDiskLocked()
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return NativeDevice{}, false
	}
	for _, d := range s.nativeDevices {
		if d.DeviceID == deviceID {
			return d, true
		}
	}
	return NativeDevice{}, false
}

// SetNativeDeviceMFAApprover flips a device's MFAApprover flag. It returns
// updated=false (and no error) when no device matches deviceID.
func (s *Store) SetNativeDeviceMFAApprover(deviceID string, approver bool) (bool, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return false, nil
	}
	updated := false
	err := s.update(func() error {
		for i := range s.nativeDevices {
			if s.nativeDevices[i].DeviceID == deviceID {
				s.nativeDevices[i].MFAApprover = approver
				s.nativeDevices[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
				s.nativeDevicesDirty = true
				updated = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return updated, nil
}

// SetAICreditsExhausted marks that the classifier reported the weekly chat limit / out of
// AI credits. It returns true only on the false->true transition so callers can
// notify exactly once until the flag is reset. The flag is persisted so it
// survives a restart.
func (s *Store) SetAICreditsExhausted(atUTC string) (bool, error) {
	transitioned := false
	err := s.update(func() error {
		if s.aiCreditsExhausted {
			return nil
		}
		if strings.TrimSpace(atUTC) == "" {
			atUTC = time.Now().UTC().Format(time.RFC3339)
		}
		s.aiCreditsExhausted = true
		s.aiCreditsExhaustedAt = atUTC
		transitioned = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return transitioned, nil
}

// ClearAICreditsExhausted resets the AI-credits flag. It returns true only when
// the flag was previously set (true->false transition).
func (s *Store) ClearAICreditsExhausted() (bool, error) {
	transitioned := false
	err := s.update(func() error {
		if !s.aiCreditsExhausted {
			return nil
		}
		s.aiCreditsExhausted = false
		s.aiCreditsExhaustedAt = ""
		transitioned = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return transitioned, nil
}

// AICreditsExhausted reports whether the AI-credits flag is set and when it was
// first raised.
func (s *Store) AICreditsExhausted() (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.aiCreditsExhausted, s.aiCreditsExhaustedAt
}

// SetOllamaUpdateNotified records that the admin has already been emailed
// about latestVersion being newer than the installed Ollama. It returns
// notify=true only the first time a given latestVersion is recorded, so the
// periodic upstream-release check emails exactly once per newly-seen
// upstream version rather than on every poll until the operator rebuilds.
func (s *Store) SetOllamaUpdateNotified(latestVersion string) (notify bool, err error) {
	latestVersion = strings.TrimSpace(latestVersion)
	if latestVersion == "" {
		return false, nil
	}
	newlySeen := false
	err = s.update(func() error {
		if latestVersion == s.ollamaUpdateNotifiedVersion {
			return nil
		}
		s.ollamaUpdateNotifiedVersion = latestVersion
		newlySeen = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return newlySeen, nil
}

func (s *Store) loadDecisions() error {
	b, err := os.ReadFile(s.decisionsPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s.persistDecisionsLocked()
		}
		return err
	}
	var d []Decision
	if err := json.Unmarshal(b, &d); err != nil {
		return err
	}
	s.decisions = d
	return nil
}

func (s *Store) persistDecisionsLocked() error {
	b, err := json.MarshalIndent(s.decisions, "", "  ")
	if err != nil {
		return err
	}
	if err := fsutil.AtomicWriteFile(s.decisionsPath(), b, 0o600); err != nil {
		return fmt.Errorf("write decisions: %w", err)
	}
	return nil
}

// SetDesktopPairingCode stores a pairing code with 5-minute expiration
func (s *Store) SetDesktopPairingCode(code string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return s.update(func() error {
		expiresAt := time.Now().UTC().Add(ttl)
		s.desktopPairingCodes[strings.TrimSpace(code)] = expiresAt.Format(time.RFC3339)
		s.pairingCodesDirty = true
		return nil
	})
}

// ValidateDesktopPairingCode checks if a code is valid and not expired.
// Returns true if valid, false if expired or not found.
//
// This is a pure read: it refreshes from disk like every other reader here
// (so a code minted by the other process is visible), and it does NOT prune
// expired entries. An earlier version deleted the expired entry in memory
// without setting pairingCodesDirty or persisting, so the delete was silently
// reverted by the next refresh — housekeeping that only looked like it
// worked. Expired codes are pruned for real on load, in applyStateFile.
func (s *Store) ValidateDesktopPairingCode(code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshStateFromDiskLocked()

	expiresAtStr, ok := s.desktopPairingCodes[strings.TrimSpace(code)]
	if !ok {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		return false
	}
	return time.Now().UTC().Before(expiresAt)
}

// ConsumeDesktopPairingCode validates and removes a pairing code.
// Returns true if code was valid, false if expired or not found.
func (s *Store) ConsumeDesktopPairingCode(code string) (bool, error) {
	cleaned := strings.TrimSpace(code)
	consumed := false
	err := s.update(func() error {
		expiresAtStr, ok := s.desktopPairingCodes[cleaned]
		if !ok {
			return nil
		}
		// Whether the code was valid or merely unparseable/expired, it is
		// removed and the removal is persisted — consuming under the file
		// lock is what makes "redeemable exactly once" hold against a
		// concurrent redemption of the same code.
		delete(s.desktopPairingCodes, cleaned)
		s.pairingCodesDirty = true
		expiresAt, parseErr := time.Parse(time.RFC3339, expiresAtStr)
		consumed = parseErr == nil && time.Now().UTC().Before(expiresAt)
		return nil
	})
	if err != nil {
		return consumed, err
	}
	return consumed, nil
}

// CheckDesktopPairingRateLimit checks if a user can attempt pairing.
// Rate limit: max 5 failed attempts per hour.
// Returns (allowed bool, attemptsRemaining int, error)
func (s *Store) CheckDesktopPairingRateLimit() (bool, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshStateFromDiskLocked(); err != nil {
		return false, 0, err
	}

	now := time.Now().UTC()
	oneHourAgo := now.Add(-1 * time.Hour)

	// Count failed attempts in the last hour
	failedCount := 0
	for _, attempt := range s.desktopPairingAttempts {
		attemptAt, err := time.Parse(time.RFC3339, attempt.AttemptAt)
		if err != nil {
			continue
		}
		if !attempt.Success && attemptAt.After(oneHourAgo) {
			failedCount++
		}
	}

	const maxFailedAttempts = 5
	allowed := failedCount < maxFailedAttempts
	remaining := maxFailedAttempts - failedCount
	if remaining < 0 {
		remaining = 0
	}

	return allowed, remaining, nil
}

// RecordDesktopPairingAttempt records a pairing attempt for rate limiting.
func (s *Store) RecordDesktopPairingAttempt(code string, success bool) error {
	return s.update(func() error {
		s.desktopPairingAttempts = append(s.desktopPairingAttempts, PairingAttempt{
			Code:      strings.TrimSpace(code),
			AttemptAt: time.Now().UTC().Format(time.RFC3339),
			Success:   success,
		})
		// Keep only last 100 attempts to avoid unbounded growth
		if len(s.desktopPairingAttempts) > 100 {
			s.desktopPairingAttempts = s.desktopPairingAttempts[len(s.desktopPairingAttempts)-100:]
		}
		s.pairingAttemptsDirty = true
		return nil
	})
}
