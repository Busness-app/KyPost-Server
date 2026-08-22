package state

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"kypost-server/backend/internal/fsutil"
)

// Store is one account's state, backed by SQLite.
//
// There is no in-memory copy of the data and no mutex: every method reads or
// writes the database directly, so two Stores over the same directory — the
// normal case, since the api and daemon are separate processes — always agree.
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
	// EnrollmentPublicKey is this device's EC P-256 public key for encrypted-mail
	// enrollment, published by the device under its own pairing credential. A
	// public key is not a capability: it lets a browser seal TO this device and
	// confers nothing by itself, which is why a device may publish its own while
	// only a session may mint the sealing. Devices paired before this existed
	// decode as empty, meaning "not enrolled and cannot be" until they publish.
	EnrollmentPublicKey string `json:"enrollmentPublicKey,omitempty"`
	EnrollmentKeyAt     string `json:"enrollmentKeyAt,omitempty"`
	// EncryptionEnrolled is DEVICE-REPORTED: whether the device can still open
	// its local envelope. It is not a record of what the browser did, because
	// those diverge — reinstalling the app destroys the keystore key, as does a
	// biometric-enrollment change on some configurations. A marker that only ever
	// turned on would tell the user a device is protected when it can read
	// nothing, so the device restates it on every registration call.
	EncryptionEnrolled bool `json:"encryptionEnrolled"`
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
	// Close the handle when the last reference to this Store goes away.
	//
	// A Store is cached and handed out as a bare pointer (api.Server's per-user
	// store cache) and the cache evicts on an idle timer. Closing at eviction closes
	// a live *sql.DB out from under whoever is still holding it — a long attachment
	// stream, a slow IMAP-backed handler, a goroutine that outlived its request —
	// and every query they make afterwards fails with "database is closed". The
	// evictor has a timestamp, not a reference count.
	//
	// Reachability IS the reference count, and the runtime already tracks it.
	// Eviction now just drops the map entry; the fd and its WAL are released once
	// nothing can reach the Store. Close stays for callers that know they are the
	// last owner (tests, shutdown) and is idempotent, so the two cannot conflict.
	//
	// The cleanup captures db, never s: capturing the Store would keep it reachable
	// forever and the cleanup would never run.
	runtime.AddCleanup(s, func(db *sql.DB) { _ = db.Close() }, db)
	return s, nil
}

// Close releases the database handle.
//
// Optional: New registers a runtime cleanup that closes the handle once the
// Store becomes unreachable, so a cache that simply forgets a Store leaks
// nothing. Call this only where the caller genuinely owns the last reference and
// wants the fd back now. Safe to call twice, and safe while another goroutine
// still holds the Store — which is why the idle-store eviction does NOT call it.
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

// tx runs fn inside a single write transaction, rolling back on error. A
// read-modify-write inside one transaction cannot interleave with another
// process's, which is what the old file lock plus read-refresh-mutate-write
// dance only approximated.
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

// Checkpoint returns the last recorded poll checkpoint.
//
// The error is returned rather than logged-and-swallowed: returning "" on a read
// failure makes a broken database indistinguishable from a fresh one, and the
// caller's "no checkpoint yet" branch means "start from the beginning of the
// mailbox" — so a transient SQLITE_BUSY becomes a full re-scan, and a corrupt
// database a full re-scan on every single tick, forever.
func (s *Store) Checkpoint() (string, error) {
	v, err := metaString(s.db, metaCheckpoint)
	if err != nil {
		return "", fmt.Errorf("read checkpoint (%s): %w", s.baseDir, err)
	}
	return v, nil
}

func (s *Store) SetCheckpoint(value string) error {
	return setMeta(s.db, metaCheckpoint, value)
}

// PollTick is the outcome of one completed poll tick, persisted so the health
// page can answer "is mail actually being polled?".
//
// Nothing else could answer it. /api/health reports whether IMAP is reachable,
// which a daemon that has stopped ticking entirely still satisfies, and the
// per-tick counts existed only as a log line. The fields mirror that line.
type PollTick struct {
	AtUTC       string `json:"atUtc"`
	Fetched     int    `json:"fetched"`
	Processed   int    `json:"processed"`
	SkippedSeen int    `json:"skippedSeen"`
	Failed      int    `json:"failed"`
	// Deferred is how many messages this tick deliberately left for a later one
	// (transient classifier failure, spent rate budget, unreadable processed
	// set). Non-zero means the checkpoint is being held back on purpose.
	Deferred int `json:"deferred"`
	// RateLimited is the subset of Deferred that hit the per-user rate budget,
	// which is a configuration answer rather than a fault.
	RateLimited bool `json:"rateLimited"`
	// CheckpointHeld records that the checkpoint did NOT advance to the highest
	// UID fetched, because doing so would have retired the deferred messages.
	CheckpointHeld bool `json:"checkpointHeld"`
}

// RecordPollTick stores the outcome of a completed tick, and maintains the
// sticky "checkpoint held since" timestamp in the same transaction.
//
// Only COMPLETED ticks are recorded. A tick that aborts early (unreadable
// checkpoint, failed IMAP fetch) deliberately leaves the previous record in
// place, so the reported age grows — "last poll 40 minutes ago" is the signal,
// and overwriting it with a fresher timestamp for a tick that fetched nothing
// would hide exactly the outage worth seeing.
func (s *Store) RecordPollTick(t PollTick) error {
	if t.AtUTC == "" {
		t.AtUTC = time.Now().UTC().Format(time.RFC3339)
	}
	blob, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return s.tx(func(tx *sql.Tx) error {
		// Sticky: set on the first tick that holds the checkpoint, cleared as
		// soon as one doesn't. A single held tick is routine; one held for an
		// hour is a classifier that never came back.
		if t.CheckpointHeld {
			held, err := metaString(tx, metaCheckpointHeldSince)
			if err != nil {
				return err
			}
			if held == "" {
				if err := setMeta(tx, metaCheckpointHeldSince, t.AtUTC); err != nil {
					return err
				}
			}
		} else if err := setMeta(tx, metaCheckpointHeldSince, ""); err != nil {
			return err
		}
		return setMeta(tx, metaLastPollTick, string(blob))
	})
}

// LastPollTick returns the most recently recorded tick, whether one exists, and
// the sticky timestamp since which the checkpoint has been held back ("" when
// it is advancing normally).
func (s *Store) LastPollTick() (tick PollTick, ok bool, heldSince string, err error) {
	raw, err := metaString(s.db, metaLastPollTick)
	if err != nil {
		return PollTick{}, false, "", fmt.Errorf("read last poll tick (%s): %w", s.baseDir, err)
	}
	heldSince, err = metaString(s.db, metaCheckpointHeldSince)
	if err != nil {
		return PollTick{}, false, "", fmt.Errorf("read checkpoint held since (%s): %w", s.baseDir, err)
	}
	if strings.TrimSpace(raw) == "" {
		return PollTick{}, false, heldSince, nil
	}
	if err := json.Unmarshal([]byte(raw), &tick); err != nil {
		// A record this process cannot parse is not a reason to fail the whole
		// status page; report "never ticked" and let the age speak.
		return PollTick{}, false, heldSince, nil
	}
	return tick, true, heldSince, nil
}

// FailedDecisionsSince counts decisions recorded as failures since a cutoff.
//
// Meaningful only because a deferred failure is recorded once per message
// rather than once per attempt (see the poller's recordMessageFailure) — this
// counts affected messages, not retry attempts.
func (s *Store) FailedDecisionsSince(since time.Time) (int, error) {
	var n int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM decisions WHERE status = 'failed' AND at_unix IS NOT NULL AND at_unix >= ?`,
		since.Unix()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count failed decisions (%s): %w", s.baseDir, err)
	}
	return n, nil
}

// LastCleanup returns when Cleanup last completed, or "" if it never has.
func (s *Store) LastCleanup() string {
	v, _ := metaString(s.db, metaLastCleanup)
	return v
}

// DiskUsageBytes reports what this account's state costs on disk.
//
// The WAL is included because it is not a rounding error: it holds committed
// pages until a checkpoint folds them back, so a busy mailbox can carry tens of
// megabytes there that a plain stat of state.db does not see. A missing file
// contributes zero rather than failing — the -wal and -shm files exist only
// while the database is open.
func (s *Store) DiskUsageBytes() int64 {
	var total int64
	base := filepath.Join(s.baseDir, "state.db")
	for _, name := range []string{base, base + "-wal", base + "-shm"} {
		if info, err := os.Stat(name); err == nil {
			total += info.Size()
		}
	}
	return total
}

// Seen reports whether a message has already been classified.
//
// The error is returned rather than swallowed into false, because false means
// "not yet processed" and the caller acts on it by processing the message.
// SQLITE_BUSY past the busy_timeout is reachable here, since the api and daemon
// processes contend on this file, so swallowing it means reclassifying mail that
// was already done: duplicate IMAP keyword writes, duplicate Decision rows, and
// a push notification per already-read message on every paired device. "I don't
// know" is not "no".
func (s *Store) Seen(id string) (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM processed WHERE message_id = ?`, id).Scan(&n); err != nil {
		return false, fmt.Errorf("read processed (%s): %w", s.baseDir, err)
	}
	return n > 0, nil
}

func markProcessed(e execer, id string) error {
	_, err := e.Exec(
		`INSERT INTO processed(message_id, seen_at) VALUES(?, ?)
		 ON CONFLICT(message_id) DO UPDATE SET seen_at = excluded.seen_at`,
		id, time.Now().UTC().Unix())
	return err
}

// MarkProcessed records that a message has been classified. One row, not a
// rewrite of every message id ever seen.
//
// Prefer RecordProcessedDecision when the caller is also writing the decision
// that retires the message: the two together are one state change, and this
// entry point cannot enforce that.
func (s *Store) MarkProcessed(id string) error {
	return markProcessed(s.db, id)
}

// RecordProcessedDecision writes d to the audit log AND retires d.MessageID in
// ONE transaction.
//
// Every terminal path in the poller ends in exactly these two writes, and they
// used to be two separate statements — issued in opposite orders on different
// branches, with the errors dropped on some of them. Both orders lose:
//
//   - decision first, marker fails: the next tick reprocesses the message, so
//     the audit log grows a duplicate row and every paired device gets a second
//     notification for mail the user already has.
//   - marker first, decision fails: the message is retired with no record that
//     anything happened to it. It is never looked at again and the audit log,
//     which is the only account of what this server did to someone's mail,
//     silently omits it.
//
// SQLITE_BUSY past the busy_timeout is reachable here — the api and daemon
// processes contend on this file — so neither failure is hypothetical. One
// transaction makes "recorded and retired" the only two outcomes.
func (s *Store) RecordProcessedDecision(d Decision) error {
	return s.tx(func(tx *sql.Tx) error {
		if err := insertDecision(tx, d); err != nil {
			return err
		}
		if err := markProcessed(tx, d.MessageID); err != nil {
			return err
		}
		// Retiring a message ends any deferral of it, and this is the one place
		// every terminal path in the poller goes through — so the ledger cannot
		// drift from the processed set by a caller forgetting to clear it.
		_, err := tx.Exec(`DELETE FROM deferrals WHERE message_id = ?`, d.MessageID)
		return err
	})
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
		if _, err := tx.Exec(`DELETE FROM decisions WHERE at_unix IS NOT NULL AND at_unix < ?`, cutoff.Unix()); err != nil {
			return err
		}
		// Orphaned deferrals: a message the user deleted from the mailbox never
		// comes back, so nothing retries it, nothing retires it, and its row
		// would otherwise sit in the ledger forever inflating the deferred count
		// an operator is meant to read as "work still pending". The attempt cap
		// retires anything genuinely stuck long before this window.
		if _, err := tx.Exec(`DELETE FROM deferrals WHERE first_at < ?`, cutoff.Unix()); err != nil {
			return err
		}
		// Recorded in the same transaction as the deletes it describes, so the
		// timestamp can never claim a cleanup that rolled back.
		return setMeta(tx, metaLastCleanup, time.Now().UTC().Format(time.RFC3339))
	})
}

// ---- deferrals -------------------------------------------------------------

// RecordDeferral counts one more tick that left messageID unprocessed, and
// returns the running total INCLUDING this attempt.
//
// The caller uses the returned count to decide whether to keep deferring or
// give up: a deferral holds the poll checkpoint below the message, so a
// failure that never clears would hold it forever. See the deferrals table.
//
// The error is returned rather than swallowed because a caller that cannot
// count attempts cannot enforce the cap, and silently returning 1 forever is
// exactly the unbounded behaviour this exists to prevent.
func (s *Store) RecordDeferral(messageID string) (int, error) {
	now := time.Now().UTC().Unix()
	var attempts int
	err := s.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(
			`INSERT INTO deferrals(message_id, attempts, first_at, last_at) VALUES(?, 1, ?, ?)
			 ON CONFLICT(message_id) DO UPDATE SET
			   attempts = deferrals.attempts + 1,
			   last_at  = excluded.last_at`,
			messageID, now, now); err != nil {
			return err
		}
		// Read back inside the same transaction: two processes poll nothing in
		// parallel today, but "increment then read" across two statements is the
		// shape that stops being true quietly.
		return tx.QueryRow(`SELECT attempts FROM deferrals WHERE message_id = ?`, messageID).Scan(&attempts)
	})
	if err != nil {
		return 0, fmt.Errorf("record deferral (%s): %w", s.baseDir, err)
	}
	return attempts, nil
}

// ClearDeferral forgets a message's deferral history. Called when the message
// finally succeeds, and when it is retired — in both cases the row has no
// further meaning, and leaving it behind would make a message that failed once
// months ago start its next deferral part-way to the cap.
func (s *Store) ClearDeferral(messageID string) error {
	if _, err := s.db.Exec(`DELETE FROM deferrals WHERE message_id = ?`, messageID); err != nil {
		return fmt.Errorf("clear deferral (%s): %w", s.baseDir, err)
	}
	return nil
}

// DeferralAttempts reports how many ticks have already deferred messageID, and
// zero when it is not deferred.
func (s *Store) DeferralAttempts(messageID string) (int, error) {
	var attempts int
	err := s.db.QueryRow(`SELECT attempts FROM deferrals WHERE message_id = ?`, messageID).Scan(&attempts)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read deferral (%s): %w", s.baseDir, err)
	}
	return attempts, nil
}

// DeferralStats reports how many messages are currently deferred and when the
// oldest of them was first deferred (RFC3339, "" when none are).
//
// This is the operator-visible half of the retry contract: messages being
// retried is normal, and the same number stuck for six hours is not.
func (s *Store) DeferralStats() (count int, oldestUTC string, err error) {
	var oldest sql.NullInt64
	if err := s.db.QueryRow(`SELECT COUNT(*), MIN(first_at) FROM deferrals`).Scan(&count, &oldest); err != nil {
		return 0, "", fmt.Errorf("read deferral stats (%s): %w", s.baseDir, err)
	}
	if oldest.Valid {
		oldestUTC = time.Unix(oldest.Int64, 0).UTC().Format(time.RFC3339)
	}
	return count, oldestUTC, nil
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

// HasDecisionWithStatus reports whether a decision with this status has
// already been recorded for messageID.
//
// This is what keeps a RETRIED message from writing the same row twice. A
// message left unmarked on purpose (a transient classifier outage) comes back
// on every poll tick until it succeeds, so an unconditional AddDecision on the
// failure path would append one row — and fire one push notification — per
// tick, for as long as the outage lasts, for every affected message.
//
// The processed set cannot answer this: the whole point of the deferral is
// that the message is NOT in it.
func (s *Store) HasDecisionWithStatus(messageID, status string) (bool, error) {
	var n int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM decisions WHERE message_id = ? AND status = ?`,
		messageID, status).Scan(&n); err != nil {
		return false, fmt.Errorf("read decisions (%s): %w", s.baseDir, err)
	}
	return n > 0, nil
}

// Decisions returns the most recent decisions, newest first.
//
// Ordered by id, not at_utc: the previous implementation returned the tail of
// an append-ordered slice, so a row written later carrying an earlier
// timestamp still came first. Preserved deliberately.
func (s *Store) Decisions(limit int) []Decision {
	decisions, err := s.DecisionsStrict(limit)
	if err != nil {
		slog.Error("state read failed", "field", "decisions", "dir", s.baseDir, "error", err.Error())
		return []Decision{}
	}
	return decisions
}

func (s *Store) DecisionsStrict(limit int) ([]Decision, error) {
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
		return nil, err
	}
	defer rows.Close()
	out := []Decision{}
	for rows.Next() {
		var d Decision
		if err := rows.Scan(&d.MessageID, &d.Sender, &d.SentTo, &d.Subject, &d.Label, &d.Status, &d.Detail, &d.AtUTC); err != nil {
			slog.Error("state read failed", "field", "decisions", "dir", s.baseDir, "error", err.Error())
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
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

// RotateSubscriberID replaces this account's subscriber ID and returns the
// previous one, so the caller can evict it from any index that cached it.
//
// This is credential revocation, not housekeeping. A native pairing token is a
// stateless HMAC over {sub, exp, nonce, purpose} — nothing in it is tied to a
// session, a password or a device — so purging sessions, devices and the
// CardDAV credential did not reach a token that had already been minted. One
// held across an admin password reset still redeemed afterwards and minted a
// working device credential on an account the admin believed was secured.
//
// Rotating the subscriber ID invalidates every outstanding token at once: their
// Sub no longer resolves to any account. It is safe to do here precisely
// because revocation also deletes every paired device — the subscriber ID is a
// pairing-time value, and nothing that survives revocation refers to it.
func (s *Store) RotateSubscriberID() (previous string, err error) {
	err = s.tx(func(tx *sql.Tx) error {
		existing, err := metaString(tx, metaSubscriberID)
		if err != nil {
			return err
		}
		fresh, err := fsutil.NewUUIDv4()
		if err != nil {
			return err
		}
		previous = existing
		return setMeta(tx, metaSubscriberID, fresh)
	})
	if err != nil {
		return "", err
	}
	return previous, nil
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
	notifications, cursor, err := s.PullNotificationsAfterStrict(after)
	if err != nil {
		slog.Error("state read failed", "field", "pullNotifications", "dir", s.baseDir, "error", err.Error())
		return []PullNotification{}, cursor
	}
	return notifications, cursor
}

func (s *Store) PullNotificationsAfterStrict(after int64) ([]PullNotification, int64, error) {
	var cursor int64
	if raw, err := metaString(s.db, metaPullSeq); err == nil {
		// Same as EnqueuePullNotification: unparseable means no cursor yet.
		_, _ = fmt.Sscan(raw, &cursor)
	}
	rows, err := s.db.Query(
		`SELECT seq, title, body, data, created_at FROM pull_notifications WHERE seq > ? ORDER BY seq`, after)
	if err != nil {
		slog.Error("state read failed", "field", "pullNotifications", "dir", s.baseDir, "error", err.Error())
		return nil, cursor, err
	}
	defer rows.Close()
	out := []PullNotification{}
	for rows.Next() {
		var n PullNotification
		var data string
		if err := rows.Scan(&n.Seq, &n.Title, &n.Body, &data, &n.CreatedAt); err != nil {
			return nil, cursor, err
		}
		if data != "" && data != "null" {
			// A notification whose payload will not decode has lost the
			// routing metadata the device acts on. Returning it anyway is
			// worse than returning nothing: the handler reports success and
			// the client advances its cursor past a notification it never
			// actually received.
			if err := json.Unmarshal([]byte(data), &n.Data); err != nil {
				return nil, cursor, fmt.Errorf("decode pull notification %d: %w", n.Seq, err)
			}
		}
		out = append(out, n)
	}
	return out, cursor, rows.Err()
}

// ---- web push subscriptions ------------------------------------------------

func (s *Store) ListNotificationSubscriptions() []NotificationSubscription {
	subs, err := s.ListNotificationSubscriptionsStrict()
	if err != nil {
		slog.Error("state read failed", "field", "notifications", "dir", s.baseDir, "error", err.Error())
		return []NotificationSubscription{}
	}
	return subs
}

func (s *Store) ListNotificationSubscriptionsStrict() ([]NotificationSubscription, error) {
	rows, err := s.db.Query(
		`SELECT endpoint, auth, p256dh, user_agent, updated_at FROM notifications ORDER BY seq`)
	if err != nil {
		slog.Error("state read failed", "field", "notifications", "dir", s.baseDir, "error", err.Error())
		return nil, err
	}
	defer rows.Close()
	out := []NotificationSubscription{}
	for rows.Next() {
		var n NotificationSubscription
		if err := rows.Scan(&n.Endpoint, &n.Auth, &n.P256DH, &n.UserAgent, &n.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ErrRegistrationLimit is returned by the upserts below when a NEW registration
// would take the account past its cap. Refreshing a registration that already
// exists never returns it, so a device at the cap can still renew its token.
var ErrRegistrationLimit = errors.New("registration limit reached")

// MaxNotificationSubscriptions and MaxNativeDevices cap how many push
// destinations one account may register.
//
// Not a storage concern — a delivery one. Both fanouts are serial, each
// destination gets its own multi-second network timeout, and the whole thing
// runs inside the goroutine poller.tick's wg.Wait() awaits. So the number of
// rows here is a multiplier on how long one user's poll tick can take, and the
// tick does not finish until the slowest user does: an account that registered
// registrations without bound could hold up mail polling for everyone on the
// instance without ever doing anything an authenticated user is not allowed to
// do. The cap is what makes that multiplier finite.
//
// Sized for a person, not for a fleet: browsers, phones and tablets. Anyone
// legitimately past this has a deployment question, not a notification one.
const (
	MaxNotificationSubscriptions = 20
	MaxNativeDevices             = 20
)

// countRows reports how many rows table holds. Callers pass a *sql.Tx so the
// count and the insert it gates cannot interleave with another registration.
func countRows(q queryer, table string) (int, error) {
	var n int
	// table is a package-level constant string at every call site, never
	// request data.
	err := q.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n)
	return n, err
}

func (s *Store) UpsertNotificationSubscription(sub NotificationSubscription) error {
	return s.tx(func(tx *sql.Tx) error {
		// Counted inside the transaction that inserts, not by the handler
		// beforehand: a check followed by a separate write lets N concurrent
		// registrations all read "under the cap" and then all insert.
		var exists int
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM notifications WHERE endpoint = ?`, sub.Endpoint).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			n, err := countRows(tx, "notifications")
			if err != nil {
				return err
			}
			if n >= MaxNotificationSubscriptions {
				return ErrRegistrationLimit
			}
		}
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
	user_agent, registered_at, updated_at, user_id, mfa_approver, transport, secret_hash,
	enrollment_public_key, enrollment_key_at, encryption_enrolled`

func scanDevice(rows *sql.Rows) (NativeDevice, error) {
	var d NativeDevice
	var approver, enrolled int
	err := rows.Scan(&d.DeviceID, &d.Platform, &d.PushToken, &d.DeviceName, &d.AppVersion,
		&d.UserAgent, &d.RegisteredAt, &d.UpdatedAt, &d.UserID, &approver, &d.Transport, &d.SecretHash,
		&d.EnrollmentPublicKey, &d.EnrollmentKeyAt, &enrolled)
	d.MFAApprover = approver == 1
	d.EncryptionEnrolled = enrolled == 1
	return d, err
}

func insertDevice(e execer, d NativeDevice, seq int) error {
	_, err := e.Exec(
		`INSERT INTO native_devices(`+deviceColumns+`, seq)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(device_id) DO UPDATE SET
		   platform = excluded.platform, push_token = excluded.push_token,
		   device_name = excluded.device_name, app_version = excluded.app_version,
		   user_agent = excluded.user_agent, registered_at = excluded.registered_at,
		   updated_at = excluded.updated_at, user_id = excluded.user_id,
		   mfa_approver = excluded.mfa_approver, transport = excluded.transport,
		   secret_hash = excluded.secret_hash,
		   enrollment_public_key = excluded.enrollment_public_key,
		   enrollment_key_at = excluded.enrollment_key_at,
		   encryption_enrolled = excluded.encryption_enrolled`,
		d.DeviceID, d.Platform, d.PushToken, d.DeviceName, d.AppVersion, d.UserAgent,
		d.RegisteredAt, d.UpdatedAt, d.UserID, boolToInt(d.MFAApprover), d.Transport, d.SecretHash,
		d.EnrollmentPublicKey, d.EnrollmentKeyAt, boolToInt(d.EncryptionEnrolled), seq)
	return err
}

func (s *Store) ListNativeDevices() []NativeDevice {
	devices, err := s.ListNativeDevicesStrict()
	if err != nil {
		slog.Error("state read failed", "field", "nativeDevices", "dir", s.baseDir, "error", err.Error())
		return []NativeDevice{}
	}
	return devices
}

// ListNativeDevicesStrict distinguishes an empty device set from a failed read.
func (s *Store) ListNativeDevicesStrict() ([]NativeDevice, error) {
	rows, err := s.db.Query(`SELECT ` + deviceColumns + ` FROM native_devices ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NativeDevice{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
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

// UpsertNativeDevice registers or refreshes a device. Two matching rules, in
// order:
//
//   - by device id: a re-registration must NOT undo an explicit MFAApprover
//     choice made through SetNativeDeviceMFAApprover, so the stored value wins
//     over whatever the caller passed.
//   - by push token + platform: the same physical device re-pairing without its
//     device id is one device, not two, so that row is updated in place.
//
// Both matching branches rebuild the whole row from the caller's struct, so
// anything the device does not resend has to be carried forward explicitly —
// see enrollmentState, which does that for the enrollment columns exactly as
// the lines above do for MFAApprover.
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
	// Enrollment fields are never settable through this function, on ANY branch.
	//
	// applyTo carries them forward on the two branches that match an existing
	// row, but the new-device branch wrote whatever the caller passed — so the
	// constraint held by convention rather than by construction. No caller
	// currently sets them (the register request has no such field and the struct
	// literal omits them), but zeroing here makes the rule true rather than
	// merely observed, which is what the comment on enrollmentState claims.
	device.EnrollmentPublicKey = ""
	device.EnrollmentKeyAt = ""
	device.EncryptionEnrolled = false

	now := time.Now().UTC().Format(time.RFC3339)
	if strings.TrimSpace(device.RegisteredAt) == "" {
		device.RegisteredAt = now
	}
	device.UpdatedAt = now

	var existingSeq sql.NullInt64
	var existingRegistered string
	var existingApprover int
	var existing enrollmentState
	err := tx.QueryRow(
		`SELECT seq, registered_at, mfa_approver,
		        enrollment_public_key, enrollment_key_at, encryption_enrolled
		 FROM native_devices WHERE device_id = ?`,
		device.DeviceID).Scan(&existingSeq, &existingRegistered, &existingApprover,
		&existing.publicKey, &existing.keyAt, &existing.enrolled)
	if err == nil {
		if existingRegistered != "" {
			device.RegisteredAt = existingRegistered
		}
		device.MFAApprover = existingApprover == 1
		existing.applyTo(&device)
		return insertDevice(tx, device, int(existingSeq.Int64))
	}
	if err != sql.ErrNoRows {
		return err
	}

	if device.PushToken != "" {
		var matchID, matchRegistered, matchUserID string
		var matchSeq sql.NullInt64
		var matchApprover int
		var match enrollmentState
		err := tx.QueryRow(
			`SELECT device_id, registered_at, seq, mfa_approver, user_id,
			        enrollment_public_key, enrollment_key_at, encryption_enrolled
			 FROM native_devices
			 WHERE push_token = ? AND platform = ? ORDER BY seq LIMIT 1`,
			device.PushToken, device.Platform).Scan(&matchID, &matchRegistered, &matchSeq, &matchApprover, &matchUserID,
			&match.publicKey, &match.keyAt, &match.enrolled)
		if err == nil {
			if _, err := tx.Exec(`DELETE FROM native_devices WHERE device_id = ?`, matchID); err != nil {
				return err
			}
			device.DeviceID = matchID
			device.RegisteredAt = matchRegistered
			device.MFAApprover = matchApprover == 1
			// Carry the owner forward too. Every other field the merge preserves
			// is listed above; user_id was not, so a caller that omitted it
			// blanked the row's owner. Harmless today because the single caller
			// always sets it — the same unenforced-constraint shape as the
			// enrollment fields.
			if strings.TrimSpace(device.UserID) == "" {
				device.UserID = matchUserID
			}
			match.applyTo(&device)
			return insertDevice(tx, device, int(matchSeq.Int64))
		}
		if err != sql.ErrNoRows {
			return err
		}
	}

	// Neither match rule fired, so this is a genuinely new device and the only
	// branch the cap applies to — re-registering or refreshing an existing
	// device returned above and must keep working at the cap. Counted in this
	// transaction so concurrent registrations cannot both pass the check.
	n, err := countRows(tx, "native_devices")
	if err != nil {
		return err
	}
	if n >= MaxNativeDevices {
		return ErrRegistrationLimit
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

// enrollmentState is the enrollment half of an existing device row, read before
// a re-registration overwrites it.
//
// A device re-registers on every app start and whenever its push token rotates,
// and it does not resend its enrollment key when it does — that key is published
// once, through a different route. Without this carry-forward an ordinary token
// refresh would silently erase the key mid-ceremony, and the browser would then
// seal to a key that no longer exists.
type enrollmentState struct {
	publicKey string
	keyAt     string
	enrolled  int
}

func (e enrollmentState) applyTo(d *NativeDevice) {
	d.EnrollmentPublicKey = e.publicKey
	d.EnrollmentKeyAt = e.keyAt
	d.EncryptionEnrolled = e.enrolled == 1
}

// SetNativeDeviceEnrollmentKey records a device's enrollment public key and
// returns the updated record.
//
// Unlike SetNativeDeviceMFAApprover, an absent device is an error rather than a
// quiet updated=false. The two are called from different places for different
// reasons: the approver flag is flipped by a session acting on a device it just
// listed, where a race with removal is ordinary. This is called by the device
// itself, under its own pairing credential, so the row is guaranteed to exist —
// its absence means the credential outlived the record it names, and silently
// doing nothing there would report a successful publish for a key the server
// did not keep.
func (s *Store) SetNativeDeviceEnrollmentKey(deviceID, publicKey, at string) (NativeDevice, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return NativeDevice{}, fmt.Errorf("enrollment key: empty device id")
	}
	res, err := s.db.Exec(
		`UPDATE native_devices
		 SET enrollment_public_key = ?, enrollment_key_at = ?, updated_at = ?
		 WHERE device_id = ?`,
		publicKey, at, time.Now().UTC().Format(time.RFC3339), deviceID)
	if err != nil {
		return NativeDevice{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return NativeDevice{}, err
	}
	if n == 0 {
		return NativeDevice{}, fmt.Errorf("enrollment key: no such device %q", deviceID)
	}
	d, ok := s.GetNativeDevice(deviceID)
	if !ok {
		return NativeDevice{}, fmt.Errorf("enrollment key: device %q vanished after update", deviceID)
	}
	return d, nil
}

// SetNativeDeviceEncryptionEnrolled records the device's own answer to "can I
// still decrypt". Both directions must work — see EncryptionEnrolled. An absent
// device is an error, for the same reason as SetNativeDeviceEnrollmentKey.
func (s *Store) SetNativeDeviceEncryptionEnrolled(deviceID string, enrolled bool) error {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return fmt.Errorf("encryption enrolled: empty device id")
	}
	res, err := s.db.Exec(
		`UPDATE native_devices SET encryption_enrolled = ?, updated_at = ? WHERE device_id = ?`,
		boolToInt(enrolled), time.Now().UTC().Format(time.RFC3339), deviceID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("encryption enrolled: no such device %q", deviceID)
	}
	return nil
}

// ClearDeviceEnrollments resets the enrollment columns on every device in this
// user's store, returning how many rows changed.
//
// Called when the account's PGP identity is written or cleared. Every non-password
// envelope slot seals the OLD key, so users.Store clears PGPWrappedEnvelopes on
// each identity write — but the enrollment record lives here, in a different
// store that users.Store cannot reach, and was left behind. The result was a
// device reporting itself enrolled, with a stale published key, naming an
// envelope that no longer existed.
//
// That matters most in the flow it breaks: rotating the identity is the
// documented way to un-enroll a lost phone, because the server cannot reach the
// copy that phone re-sealed locally. Leaving the marker set meant the Security
// page went on showing that phone as protected right after the user acted to
// revoke it.
//
// The published key is cleared alongside the marker, not just the marker. It
// was published for a superseded identity, and forcing the device to re-publish
// makes re-enrollment start from device ground truth rather than from a server
// record nobody has re-verified.
//
// The pairing itself is untouched — push, sync and the approver flag all keep
// working. Rotation invalidates a sealing, not a device.
func (s *Store) ClearDeviceEnrollments() (int, error) {
	res, err := s.db.Exec(
		`UPDATE native_devices
		 SET enrollment_public_key = '', enrollment_key_at = '',
		     encryption_enrolled = 0, updated_at = ?
		 WHERE enrollment_public_key != '' OR enrollment_key_at != ''
		    OR encryption_enrolled != 0`,
		time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
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

// ---- daemon health --------------------------------------------------------

// SetDaemonHealth records the daemon process's latest health report, which the
// API process reads back through DaemonHealth to serve /api/health.
//
// The payload is opaque here on purpose: its shape and its staleness rule
// belong to internal/health (see health.DaemonReport), and this store has no
// business knowing what a classifier is. It is stored the same way the poll
// tick is — one JSON string under one meta key — because the writer is one
// process, the reader is another, and this database is already the thing they
// share.
func (s *Store) SetDaemonHealth(report string) error {
	return s.tx(func(tx *sql.Tx) error {
		return setMeta(tx, metaDaemonHealth, report)
	})
}

// DaemonHealth returns the last report the daemon wrote, or "" if it never has.
//
// A read failure is reported as "" rather than an error: the caller's answer to
// both is the same — no usable news from the daemon, which health.
// MergeDaemonReport treats as unhealthy — and an unreadable state database
// must not turn the health endpoint itself into a 500.
func (s *Store) DaemonHealth() string {
	raw, err := metaString(s.db, metaDaemonHealth)
	if err != nil {
		slog.Error("state read failed", "field", "daemonHealth", "dir", s.baseDir, "error", err.Error())
		return ""
	}
	return raw
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
