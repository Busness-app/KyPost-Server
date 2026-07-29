package state

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kypost-server/backend/internal/fsutil"
)

// Store is one account's state, backed by SQLite.
//
// There is no in-memory copy of the data and no mutex: every method reads or
// writes the database directly, so two Stores over the same directory — which
// is the normal case, since the api and daemon are separate processes — always
// agree. That removes the whole class of "this accessor forgot to re-read from
// disk" bug the JSON version had, along with the dirty flags and the advisory
// file lock that tried to paper over it.
type Store struct {
	baseDir string
	db      *sql.DB
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
	// SecretHash is the hash of this device's own pairing secret, minted once
	// at registration — users.HashDeviceSecret format, or the older
	// users.HashPassword scrypt format for devices paired before that existed.
	// Verify only through users.VerifyDeviceSecret, which accepts both. The raw
	// secret is never stored, and this must never reach an API response — see
	// Redacted().
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

// New opens (creating if needed) the account's state database, applies the
// schema, and imports any pre-SQLite JSON files exactly once.
func New(baseDir string) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return nil, err
	}
	db, err := openDB(filepath.Join(baseDir, "state.db"))
	if err != nil {
		return nil, err
	}
	s := &Store{baseDir: baseDir, db: db}
	if err := migrateJSONIfPresent(db, s.path(), s.decisionsPath()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database handle. Callers that cache Stores must call it
// on eviction — api.Server.sweepIdleUserStores does — or the handle and its
// WAL leak for the process lifetime.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// path/decisionsPath name the legacy JSON files. They exist only so the
// migration knows where to look.
func (s *Store) path() string          { return filepath.Join(s.baseDir, "state.json") }
func (s *Store) decisionsPath() string { return filepath.Join(s.baseDir, "decisions.json") }

// tx runs fn inside a single write transaction, rolling back on error.
//
// This is what the file lock plus read-refresh-mutate-write dance was
// approximating. Here it is the storage engine's own guarantee: a
// read-modify-write inside one transaction cannot interleave with another
// process's, so the lost updates that dance narrowed but never closed are
// gone.
func (s *Store) tx(fn func(tx *sql.Tx) error) error {
	t, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(t); err != nil {
		_ = t.Rollback()
		return err
	}
	return t.Commit()
}

// ---- checkpoint / processed ------------------------------------------------

func (s *Store) Checkpoint() string {
	v, err := metaString(s.db, metaCheckpoint)
	if err != nil {
		slog.Error("state read failed", "field", "checkpoint", "dir", s.baseDir, "error", err.Error())
	}
	return v
}

func (s *Store) SetCheckpoint(value string) error {
	return setMeta(s.db, metaCheckpoint, value)
}

func (s *Store) Seen(id string) bool {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM processed WHERE message_id = ?`, id).Scan(&n); err != nil {
		slog.Error("state read failed", "field", "processed", "dir", s.baseDir, "error", err.Error())
		return false
	}
	return n > 0
}

// MarkProcessed records that a message has been classified. One row, not a
// rewrite of every message id ever seen.
func (s *Store) MarkProcessed(id string) error {
	_, err := s.db.Exec(
		`INSERT INTO processed(message_id, seen_at) VALUES(?, ?)
		 ON CONFLICT(message_id) DO UPDATE SET seen_at = excluded.seen_at`,
		id, time.Now().UTC().Unix())
	return err
}

func (s *Store) ProcessedSince(since time.Time) int {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM processed WHERE seen_at >= ?`, since.Unix()).Scan(&n); err != nil {
		slog.Error("state read failed", "field", "processed", "dir", s.baseDir, "error", err.Error())
		return 0
	}
	return n
}

// Cleanup drops processed ids and decisions older than keepDays.
//
// A decision whose at_utc does not parse has at_unix NULL and is kept, which
// is what the previous implementation did (it kept anything it could not
// parse rather than dropping it).
func (s *Store) Cleanup(keepDays int) error {
	cutoff := time.Now().Add(-time.Duration(keepDays) * 24 * time.Hour)
	return s.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM processed WHERE seen_at < ?`, cutoff.Unix()); err != nil {
			return err
		}
		_, err := tx.Exec(`DELETE FROM decisions WHERE at_unix IS NOT NULL AND at_unix < ?`, cutoff.Unix())
		return err
	})
}

// ---- decisions -------------------------------------------------------------

func insertDecision(e execer, d Decision) error {
	if d.AtUTC == "" {
		d.AtUTC = time.Now().UTC().Format(time.RFC3339)
	}
	var atUnix any
	if t, err := time.Parse(time.RFC3339, d.AtUTC); err == nil {
		atUnix = t.Unix()
	}
	_, err := e.Exec(
		`INSERT INTO decisions(message_id, sender, sent_to, subject, label, status, detail, at_utc, at_unix)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.MessageID, d.Sender, d.SentTo, d.Subject, d.Label, d.Status, d.Detail, d.AtUTC, atUnix)
	return err
}

// AddDecision appends one classification to the audit log — an INSERT, where
// the JSON version re-serialized and fsynced the entire history per message.
func (s *Store) AddDecision(d Decision) error {
	return insertDecision(s.db, d)
}

// Decisions returns the most recent decisions, newest first.
//
// Ordered by id, not at_utc: the previous implementation returned the tail of
// an append-ordered slice, so a row written later carrying an earlier
// timestamp still came first. Preserved deliberately.
func (s *Store) Decisions(limit int) []Decision {
	query := `SELECT message_id, sender, sent_to, subject, label, status, detail, at_utc
	          FROM decisions ORDER BY id DESC`
	args := []any{}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		slog.Error("state read failed", "field", "decisions", "dir", s.baseDir, "error", err.Error())
		return []Decision{}
	}
	defer rows.Close()
	out := []Decision{}
	for rows.Next() {
		var d Decision
		if err := rows.Scan(&d.MessageID, &d.Sender, &d.SentTo, &d.Subject, &d.Label, &d.Status, &d.Detail, &d.AtUTC); err != nil {
			slog.Error("state read failed", "field", "decisions", "dir", s.baseDir, "error", err.Error())
			return out
		}
		out = append(out, d)
	}
	return out
}

// ---- subscriber id / delivery mode ----------------------------------------

func (s *Store) SubscriberID() string {
	v, err := metaString(s.db, metaSubscriberID)
	if err != nil {
		slog.Error("state read failed", "field", "subscriberId", "dir", s.baseDir, "error", err.Error())
	}
	return v
}

func (s *Store) GetOrCreateSubscriberID() (string, error) {
	var id string
	err := s.tx(func(tx *sql.Tx) error {
		existing, err := metaString(tx, metaSubscriberID)
		if err != nil {
			return err
		}
		if existing != "" {
			id = existing
			return nil
		}
		fresh, err := fsutil.NewUUIDv4()
		if err != nil {
			return err
		}
		id = fresh
		return setMeta(tx, metaSubscriberID, fresh)
	})
	if err != nil {
		return "", err
	}
	return id, nil
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

func (s *Store) NativeDeliveryMode() string {
	v, err := metaString(s.db, metaDeliveryMode)
	if err != nil {
		slog.Error("state read failed", "field", "deliveryMode", "dir", s.baseDir, "error", err.Error())
	}
	return normalizeDeliveryMode(v)
}

func (s *Store) SetNativeDeliveryMode(mode string) error {
	return setMeta(s.db, metaDeliveryMode, normalizeDeliveryMode(mode))
}

// ---- pull notifications ----------------------------------------------------

// EnqueuePullNotification appends to the App Pull queue, assigning the next
// sequence number and trimming to maxPullNotifications, all in one
// transaction so two processes cannot mint the same seq.
func (s *Store) EnqueuePullNotification(n PullNotification) error {
	return s.tx(func(tx *sql.Tx) error {
		raw, err := metaString(tx, metaPullSeq)
		if err != nil {
			return err
		}
		// A missing or unparseable counter means "no notifications yet"; seq
		// stays 0 and the increment below starts the sequence at 1.
		var seq int64
		_, _ = fmt.Sscan(raw, &seq)
		seq++
		if strings.TrimSpace(n.CreatedAt) == "" {
			n.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		data, err := json.Marshal(n.Data)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(
			`INSERT INTO pull_notifications(seq, title, body, data, created_at) VALUES(?, ?, ?, ?, ?)`,
			seq, n.Title, n.Body, string(data), n.CreatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(
			`DELETE FROM pull_notifications WHERE seq <= (
			   SELECT MAX(seq) FROM pull_notifications
			 ) - ?`, maxPullNotifications); err != nil {
			return err
		}
		return setMeta(tx, metaPullSeq, fmt.Sprint(seq))
	})
}

func (s *Store) PullNotificationsAfter(after int64) ([]PullNotification, int64) {
	var cursor int64
	if raw, err := metaString(s.db, metaPullSeq); err == nil {
		// Same as EnqueuePullNotification: unparseable means no cursor yet.
		_, _ = fmt.Sscan(raw, &cursor)
	}
	rows, err := s.db.Query(
		`SELECT seq, title, body, data, created_at FROM pull_notifications WHERE seq > ? ORDER BY seq`, after)
	if err != nil {
		slog.Error("state read failed", "field", "pullNotifications", "dir", s.baseDir, "error", err.Error())
		return []PullNotification{}, cursor
	}
	defer rows.Close()
	out := []PullNotification{}
	for rows.Next() {
		var n PullNotification
		var data string
		if err := rows.Scan(&n.Seq, &n.Title, &n.Body, &data, &n.CreatedAt); err != nil {
			return out, cursor
		}
		if data != "" && data != "null" {
			_ = json.Unmarshal([]byte(data), &n.Data)
		}
		out = append(out, n)
	}
	return out, cursor
}

// ---- web push subscriptions ------------------------------------------------

func (s *Store) ListNotificationSubscriptions() []NotificationSubscription {
	rows, err := s.db.Query(
		`SELECT endpoint, auth, p256dh, user_agent, updated_at FROM notifications ORDER BY seq`)
	if err != nil {
		slog.Error("state read failed", "field", "notifications", "dir", s.baseDir, "error", err.Error())
		return []NotificationSubscription{}
	}
	defer rows.Close()
	out := []NotificationSubscription{}
	for rows.Next() {
		var n NotificationSubscription
		if err := rows.Scan(&n.Endpoint, &n.Auth, &n.P256DH, &n.UserAgent, &n.UpdatedAt); err != nil {
			return out
		}
		out = append(out, n)
	}
	return out
}

func (s *Store) UpsertNotificationSubscription(sub NotificationSubscription) error {
	return s.tx(func(tx *sql.Tx) error {
		var seq int64
		if err := tx.QueryRow(
			`SELECT COALESCE(MAX(seq), -1) + 1 FROM notifications`).Scan(&seq); err != nil {
			return err
		}
		_, err := tx.Exec(
			`INSERT INTO notifications(endpoint, auth, p256dh, user_agent, updated_at, seq)
			 VALUES(?, ?, ?, ?, ?, ?)
			 ON CONFLICT(endpoint) DO UPDATE SET
			   auth = excluded.auth, p256dh = excluded.p256dh,
			   user_agent = excluded.user_agent, updated_at = excluded.updated_at`,
			sub.Endpoint, sub.Auth, sub.P256DH, sub.UserAgent, sub.UpdatedAt, seq)
		return err
	})
}

func (s *Store) RemoveNotificationSubscription(endpoint string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM notifications WHERE endpoint = ?`, endpoint)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ---- native devices --------------------------------------------------------

const deviceColumns = `device_id, platform, push_token, device_name, app_version,
	user_agent, registered_at, updated_at, user_id, mfa_approver, transport, secret_hash`

func scanDevice(rows *sql.Rows) (NativeDevice, error) {
	var d NativeDevice
	var approver int
	err := rows.Scan(&d.DeviceID, &d.Platform, &d.PushToken, &d.DeviceName, &d.AppVersion,
		&d.UserAgent, &d.RegisteredAt, &d.UpdatedAt, &d.UserID, &approver, &d.Transport, &d.SecretHash)
	d.MFAApprover = approver == 1
	return d, err
}

func insertDevice(e execer, d NativeDevice, seq int) error {
	_, err := e.Exec(
		`INSERT INTO native_devices(`+deviceColumns+`, seq)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(device_id) DO UPDATE SET
		   platform = excluded.platform, push_token = excluded.push_token,
		   device_name = excluded.device_name, app_version = excluded.app_version,
		   user_agent = excluded.user_agent, registered_at = excluded.registered_at,
		   updated_at = excluded.updated_at, user_id = excluded.user_id,
		   mfa_approver = excluded.mfa_approver, transport = excluded.transport,
		   secret_hash = excluded.secret_hash`,
		d.DeviceID, d.Platform, d.PushToken, d.DeviceName, d.AppVersion, d.UserAgent,
		d.RegisteredAt, d.UpdatedAt, d.UserID, boolToInt(d.MFAApprover), d.Transport, d.SecretHash, seq)
	return err
}

func (s *Store) ListNativeDevices() []NativeDevice {
	rows, err := s.db.Query(`SELECT ` + deviceColumns + ` FROM native_devices ORDER BY seq`)
	if err != nil {
		slog.Error("state read failed", "field", "nativeDevices", "dir", s.baseDir, "error", err.Error())
		return []NativeDevice{}
	}
	defer rows.Close()
	out := []NativeDevice{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return out
		}
		out = append(out, d)
	}
	return out
}

func (s *Store) GetNativeDevice(deviceID string) (NativeDevice, bool) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return NativeDevice{}, false
	}
	rows, err := s.db.Query(`SELECT `+deviceColumns+` FROM native_devices WHERE device_id = ?`, deviceID)
	if err != nil {
		slog.Error("state read failed", "field", "nativeDevices", "dir", s.baseDir, "error", err.Error())
		return NativeDevice{}, false
	}
	defer rows.Close()
	if !rows.Next() {
		return NativeDevice{}, false
	}
	d, err := scanDevice(rows)
	if err != nil {
		return NativeDevice{}, false
	}
	return d, true
}

// UpsertNativeDevice registers or refreshes a device.
//
// Two matching rules, in order, both preserved from the JSON version:
//
//   - by device id: a re-registration must NOT undo an explicit MFAApprover
//     choice made through SetNativeDeviceMFAApprover, so the stored value wins
//     over whatever the caller passed.
//   - by push token + platform: the same physical device re-pairing without
//     its device id is one device, not two, so that row is updated in place.
func (s *Store) UpsertNativeDevice(device NativeDevice) error {
	return s.tx(func(tx *sql.Tx) error { return s.upsertNativeDeviceTx(tx, device) })
}

func (s *Store) upsertNativeDeviceTx(tx *sql.Tx, device NativeDevice) error {
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

	var existingSeq sql.NullInt64
	var existingRegistered string
	var existingApprover int
	err := tx.QueryRow(
		`SELECT seq, registered_at, mfa_approver FROM native_devices WHERE device_id = ?`,
		device.DeviceID).Scan(&existingSeq, &existingRegistered, &existingApprover)
	if err == nil {
		if existingRegistered != "" {
			device.RegisteredAt = existingRegistered
		}
		device.MFAApprover = existingApprover == 1
		return insertDevice(tx, device, int(existingSeq.Int64))
	}
	if err != sql.ErrNoRows {
		return err
	}

	if device.PushToken != "" {
		var matchID, matchRegistered string
		var matchSeq sql.NullInt64
		var matchApprover int
		err := tx.QueryRow(
			`SELECT device_id, registered_at, seq, mfa_approver FROM native_devices
			 WHERE push_token = ? AND platform = ? ORDER BY seq LIMIT 1`,
			device.PushToken, device.Platform).Scan(&matchID, &matchRegistered, &matchSeq, &matchApprover)
		if err == nil {
			if _, err := tx.Exec(`DELETE FROM native_devices WHERE device_id = ?`, matchID); err != nil {
				return err
			}
			device.DeviceID = matchID
			device.RegisteredAt = matchRegistered
			device.MFAApprover = matchApprover == 1
			return insertDevice(tx, device, int(matchSeq.Int64))
		}
		if err != sql.ErrNoRows {
			return err
		}
	}

	var nextSeq int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq), -1) + 1 FROM native_devices`).Scan(&nextSeq); err != nil {
		return err
	}
	return insertDevice(tx, device, nextSeq)
}

func (s *Store) RemoveNativeDevice(deviceID string) (bool, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return false, nil
	}
	res, err := s.db.Exec(`DELETE FROM native_devices WHERE device_id = ?`, deviceID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// SetNativeDeviceMFAApprover flips a device's MFAApprover flag. It returns
// updated=false (and no error) when no device matches deviceID.
func (s *Store) SetNativeDeviceMFAApprover(deviceID string, approver bool) (bool, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return false, nil
	}
	res, err := s.db.Exec(
		`UPDATE native_devices SET mfa_approver = ?, updated_at = ? WHERE device_id = ?`,
		boolToInt(approver), time.Now().UTC().Format(time.RFC3339), deviceID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ---- AI credits / ollama version ------------------------------------------

// SetAICreditsExhausted marks that the classifier reported the weekly chat
// limit. It returns true only on the false->true transition so callers notify
// exactly once until the flag is reset.
func (s *Store) SetAICreditsExhausted(atUTC string) (bool, error) {
	transitioned := false
	err := s.tx(func(tx *sql.Tx) error {
		cur, err := metaString(tx, metaAICreditsExhausted)
		if err != nil {
			return err
		}
		if cur == "1" {
			return nil
		}
		if strings.TrimSpace(atUTC) == "" {
			atUTC = time.Now().UTC().Format(time.RFC3339)
		}
		if err := setMeta(tx, metaAICreditsExhausted, "1"); err != nil {
			return err
		}
		transitioned = true
		return setMeta(tx, metaAICreditsAt, atUTC)
	})
	return transitioned, err
}

// ClearAICreditsExhausted resets the flag, returning true only on the
// true->false transition.
func (s *Store) ClearAICreditsExhausted() (bool, error) {
	transitioned := false
	err := s.tx(func(tx *sql.Tx) error {
		cur, err := metaString(tx, metaAICreditsExhausted)
		if err != nil {
			return err
		}
		if cur != "1" {
			return nil
		}
		if err := setMeta(tx, metaAICreditsExhausted, "0"); err != nil {
			return err
		}
		transitioned = true
		return setMeta(tx, metaAICreditsAt, "")
	})
	return transitioned, err
}

func (s *Store) AICreditsExhausted() (bool, string) {
	flag, err := metaString(s.db, metaAICreditsExhausted)
	if err != nil {
		slog.Error("state read failed", "field", "aiCredits", "dir", s.baseDir, "error", err.Error())
		return false, ""
	}
	at, _ := metaString(s.db, metaAICreditsAt)
	return flag == "1", at
}

// SetOllamaUpdateNotified records that the admin has already been told about
// latestVersion. Returns notify=true only the first time a given version is
// recorded, so the periodic check emails once per newly-seen release.
func (s *Store) SetOllamaUpdateNotified(latestVersion string) (notify bool, err error) {
	return s.setUpdateNotified(metaOllamaNotified, latestVersion)
}

// SetServerUpdateNotified is the same one-email-per-newly-seen-version latch
// for KyPost-Server's own releases. It is a separate key from the Ollama one
// so the two notifications never suppress each other.
func (s *Store) SetServerUpdateNotified(latestVersion string) (notify bool, err error) {
	return s.setUpdateNotified(metaServerNotified, latestVersion)
}

func (s *Store) setUpdateNotified(key, latestVersion string) (notify bool, err error) {
	latestVersion = strings.TrimSpace(latestVersion)
	if latestVersion == "" {
		return false, nil
	}
	newlySeen := false
	err = s.tx(func(tx *sql.Tx) error {
		cur, err := metaString(tx, key)
		if err != nil {
			return err
		}
		if cur == latestVersion {
			return nil
		}
		newlySeen = true
		return setMeta(tx, key, latestVersion)
	})
	return newlySeen, err
}

// ---- desktop pairing -------------------------------------------------------

// hashPairingCode returns a hex SHA-256 of a pairing code, for the audit log.
// Not a password hash and does not need to be: the input is 128 bits of
// crypto/rand, so there is nothing to brute force.
func hashPairingCode(code string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(sum[:])
}

// MaxDesktopPairingCodesPerHour bounds how many desktop pairing codes one
// account may mint per hour.
const MaxDesktopPairingCodesPerHour = 5

func (s *Store) SetDesktopPairingCode(code string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	expiresAt := time.Now().UTC().Add(ttl).Format(time.RFC3339)
	_, err := s.db.Exec(
		`INSERT INTO desktop_pairing_codes(code, expires_at) VALUES(?, ?)
		 ON CONFLICT(code) DO UPDATE SET expires_at = excluded.expires_at`,
		strings.TrimSpace(code), expiresAt)
	return err
}

// ValidateDesktopPairingCode reports whether a code exists and is unexpired.
// A pure read: it does not prune, since pruning here would be a write on a
// read path and ConsumeDesktopPairingCode is what removes codes.
func (s *Store) ValidateDesktopPairingCode(code string) bool {
	var expiresAtStr string
	err := s.db.QueryRow(
		`SELECT expires_at FROM desktop_pairing_codes WHERE code = ?`, strings.TrimSpace(code)).Scan(&expiresAtStr)
	if err != nil {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		return false
	}
	return time.Now().UTC().Before(expiresAt)
}

// ConsumeDesktopPairingCode validates and removes a code in one transaction,
// which is what makes "redeemable exactly once" hold against a concurrent
// redemption of the same code. A code that was present is deleted whether or
// not it had expired.
func (s *Store) ConsumeDesktopPairingCode(code string) (bool, error) {
	cleaned := strings.TrimSpace(code)
	consumed := false
	err := s.tx(func(tx *sql.Tx) error {
		var expiresAtStr string
		err := tx.QueryRow(`SELECT expires_at FROM desktop_pairing_codes WHERE code = ?`, cleaned).Scan(&expiresAtStr)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM desktop_pairing_codes WHERE code = ?`, cleaned); err != nil {
			return err
		}
		expiresAt, parseErr := time.Parse(time.RFC3339, expiresAtStr)
		consumed = parseErr == nil && time.Now().UTC().Before(expiresAt)
		return nil
	})
	return consumed, err
}

// ListDesktopPairingAttempts returns the attempt audit log, oldest first.
func (s *Store) ListDesktopPairingAttempts() []PairingAttempt {
	rows, err := s.db.Query(`SELECT code, attempt_at, success FROM desktop_pairing_attempts ORDER BY id`)
	if err != nil {
		slog.Error("state read failed", "field", "pairingAttempts", "dir", s.baseDir, "error", err.Error())
		return []PairingAttempt{}
	}
	defer rows.Close()
	out := []PairingAttempt{}
	for rows.Next() {
		var a PairingAttempt
		var success int
		if err := rows.Scan(&a.Code, &a.AttemptAt, &success); err != nil {
			return out
		}
		a.Success = success == 1
		out = append(out, a)
	}
	return out
}

// CheckDesktopPairingRateLimit reports whether this account may mint another
// pairing code, and how many it has left this hour.
//
// It counts EVERY attempt in the window, not just failures: the only caller
// records a success on issuance, so counting failures alone made the limit
// apply to nothing.
func (s *Store) CheckDesktopPairingRateLimit() (bool, int, error) {
	oneHourAgo := time.Now().UTC().Add(-time.Hour)
	rows, err := s.db.Query(`SELECT attempt_at FROM desktop_pairing_attempts`)
	if err != nil {
		return false, 0, err
	}
	defer rows.Close()
	recent := 0
	for rows.Next() {
		var at string
		if err := rows.Scan(&at); err != nil {
			return false, 0, err
		}
		t, err := time.Parse(time.RFC3339, at)
		if err != nil {
			continue
		}
		if t.After(oneHourAgo) {
			recent++
		}
	}
	remaining := MaxDesktopPairingCodesPerHour - recent
	if remaining < 0 {
		remaining = 0
	}
	return recent < MaxDesktopPairingCodesPerHour, remaining, nil
}

// RecordDesktopPairingAttempt appends one attempt to the audit log, trimmed to
// the newest 100.
//
// code is HASHED, never stored: it is a credential the moment a redeem handler
// exists, and this log is persisted.
func (s *Store) RecordDesktopPairingAttempt(code string, success bool) error {
	return s.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(
			`INSERT INTO desktop_pairing_attempts(code, attempt_at, success) VALUES(?, ?, ?)`,
			hashPairingCode(code), time.Now().UTC().Format(time.RFC3339), boolToInt(success)); err != nil {
			return err
		}
		_, err := tx.Exec(
			`DELETE FROM desktop_pairing_attempts WHERE id NOT IN (
			   SELECT id FROM desktop_pairing_attempts ORDER BY id DESC LIMIT 100)`)
		return err
	})
}
