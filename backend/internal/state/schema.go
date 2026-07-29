package state

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// SQLite replaces the JSON files this package used to keep.
//
// The old shape was: read the whole file, mutate in memory, re-serialize the
// whole file, fsync it, rename it — under an flock, because the api and daemon
// processes both write. That made MarkProcessed and AddDecision, which run
// once per classified message, rewrite the entire processed set and the entire
// decision history every time. It also needed every reader to re-read from
// disk to see the other process's writes, an invariant that had to be
// remembered at each of a dozen accessors and was twice forgotten.
//
// SQLite removes all of that: writes touch a row, readers see committed data,
// and WAL plus busy_timeout gives real multi-process concurrency instead of a
// hand-rolled advisory lock. fsutil.WithFileLock is no longer used here.
//
// The driver is modernc.org/sqlite (pure Go, no cgo) — the Docker build has no
// C toolchain in the final stage and cross-compiles, so a cgo driver would
// break the image.
const (
	// busyTimeoutMS is how long a writer waits for another process's write
	// transaction before returning SQLITE_BUSY. The api and daemon contend on
	// the same file; a poll tick classifying a message must not fail because
	// the api happened to be registering a device.
	busyTimeoutMS = 5000
)

// dsn builds the connection string. WAL is what lets a reader proceed while a
// writer holds the write lock, which is the normal state here with two
// processes. foreign_keys is on for correctness even though the current schema
// declares none — a later table that does declare one should not have to
// remember to turn it on.
// _txlock=immediate is load-bearing, not tuning.
//
// database/sql's Begin issues a plain BEGIN, which SQLite starts DEFERRED: the
// transaction opens as a reader and only tries to take the write lock at the
// first write. If another connection already holds it, that upgrade fails with
// SQLITE_BUSY_SNAPSHOT (517) — and busy_timeout deliberately does NOT retry an
// upgrade, because the reader's snapshot may already be stale. The result is a
// hard error under exactly the api-and-daemon contention this store exists to
// survive.
//
// BEGIN IMMEDIATE takes the write lock up front, so contention becomes a wait
// that busy_timeout handles instead of an error. Pinned by
// TestConcurrentPairingCodeConsumedOnce.
func dsn(path string) string {
	return fmt.Sprintf(
		"file:%s?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(%d)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)",
		path, busyTimeoutMS,
	)
}

// schema is applied on every open. Every statement is IF NOT EXISTS, so this
// doubles as the migration path for a new table.
const schema = `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

-- Message IDs already classified. seen_at is unix seconds rather than RFC3339
-- so Cleanup and ProcessedSince are index range scans instead of a full parse
-- of every row.
CREATE TABLE IF NOT EXISTS processed (
	message_id TEXT PRIMARY KEY,
	seen_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS processed_seen_at ON processed(seen_at);

-- The classification audit log. id preserves append order, which is what
-- Decisions orders by: the JSON version returned the tail of an append-ordered
-- slice, so a row written later with an earlier at_utc still sorted first, and
-- that behaviour is preserved here.
--
-- at_utc is stored verbatim (it is returned to callers as-is) alongside
-- at_unix, which is NULL when at_utc does not parse. Cleanup filters on
-- at_unix IS NOT NULL AND at_unix < cutoff, so an unparseable timestamp
-- survives cleanup exactly as it did before.
CREATE TABLE IF NOT EXISTS decisions (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	message_id TEXT NOT NULL DEFAULT '',
	sender     TEXT NOT NULL DEFAULT '',
	sent_to    TEXT NOT NULL DEFAULT '',
	subject    TEXT NOT NULL DEFAULT '',
	label      TEXT NOT NULL DEFAULT '',
	status     TEXT NOT NULL DEFAULT '',
	detail     TEXT NOT NULL DEFAULT '',
	at_utc     TEXT NOT NULL DEFAULT '',
	at_unix    INTEGER
);
CREATE INDEX IF NOT EXISTS decisions_at_unix ON decisions(at_unix);

CREATE TABLE IF NOT EXISTS notifications (
	endpoint   TEXT PRIMARY KEY,
	auth       TEXT NOT NULL DEFAULT '',
	p256dh     TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL DEFAULT '',
	seq        INTEGER NOT NULL
);

-- seq preserves the insertion order ListNativeDevices used to return, since it
-- read back an appended slice.
CREATE TABLE IF NOT EXISTS native_devices (
	device_id     TEXT PRIMARY KEY,
	platform      TEXT NOT NULL DEFAULT '',
	push_token    TEXT NOT NULL DEFAULT '',
	device_name   TEXT NOT NULL DEFAULT '',
	app_version   TEXT NOT NULL DEFAULT '',
	user_agent    TEXT NOT NULL DEFAULT '',
	registered_at TEXT NOT NULL DEFAULT '',
	updated_at    TEXT NOT NULL DEFAULT '',
	user_id       TEXT NOT NULL DEFAULT '',
	mfa_approver  INTEGER NOT NULL DEFAULT 0,
	transport     TEXT NOT NULL DEFAULT '',
	secret_hash   TEXT NOT NULL DEFAULT '',
	seq           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS native_devices_push ON native_devices(push_token, platform);

CREATE TABLE IF NOT EXISTS pull_notifications (
	seq        INTEGER PRIMARY KEY,
	title      TEXT NOT NULL DEFAULT '',
	body       TEXT NOT NULL DEFAULT '',
	data       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS desktop_pairing_codes (
	code       TEXT PRIMARY KEY,
	expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS desktop_pairing_attempts (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	code       TEXT NOT NULL DEFAULT '',
	attempt_at TEXT NOT NULL DEFAULT '',
	success    INTEGER NOT NULL DEFAULT 0
);
`

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}
	// One connection. SQLite serializes writers anyway, and a single conn
	// removes any chance of two pooled connections interleaving inside what a
	// caller believes is one transaction.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply state schema: %w", err)
	}
	return db, nil
}

// metaString reads a meta key, returning "" when absent.
func metaString(q queryer, key string) (string, error) {
	var v string
	err := q.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

func setMeta(e execer, key, value string) error {
	_, err := e.Exec(
		`INSERT INTO meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// queryer/execer let the helpers above run against either the *sql.DB or an
// open *sql.Tx, so a mutation and its reads stay in one transaction.
type queryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

const (
	metaCheckpoint         = "checkpoint"
	metaSubscriberID       = "subscriber_id"
	metaDeliveryMode       = "native_delivery_mode"
	metaPullSeq            = "pull_seq"
	metaAICreditsExhausted = "ai_credits_exhausted"
	metaAICreditsAt        = "ai_credits_exhausted_at"
	metaOllamaNotified     = "ollama_update_notified_version"
	metaServerNotified     = "server_update_notified_version"
)
