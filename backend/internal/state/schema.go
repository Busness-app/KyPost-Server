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
-- HasDecisionWithStatus runs on the poll path for every message whose
-- processing failed, on every tick it keeps failing. Without this it is a full
-- scan of up to 30 days of audit rows each time.
CREATE INDEX IF NOT EXISTS decisions_message_id ON decisions(message_id);

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
	seq           INTEGER NOT NULL,
	-- Enrollment columns. New databases get them here; existing ones get them
	-- from additiveColumns below, which is the path that actually matters.
	enrollment_public_key TEXT NOT NULL DEFAULT '',
	enrollment_key_at     TEXT NOT NULL DEFAULT '',
	encryption_enrolled   INTEGER NOT NULL DEFAULT 0,
	-- WebPush (RFC 8291) subscription keys, UnifiedPush only. Same story as the
	-- enrollment columns above: additiveColumns is the path that matters.
	p256dh    TEXT NOT NULL DEFAULT '',
	auth      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS native_devices_push ON native_devices(push_token, platform);

CREATE TABLE IF NOT EXISTS pull_notifications (
	seq        INTEGER PRIMARY KEY,
	title      TEXT NOT NULL DEFAULT '',
	body       TEXT NOT NULL DEFAULT '',
	data       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT ''
);

-- Messages the poller deliberately left unprocessed so a later tick can retry
-- them, and how many ticks have already tried.
--
-- Deferring holds the poll checkpoint below the message (see
-- imapadapter.ClampCheckpoint), so a failure that never clears would hold it
-- forever and re-fetch a growing batch on every tick. This table is what makes
-- the deferral bounded: the poller retires a message once attempts reaches its
-- cap, and deletes the row the moment the message succeeds or is retired.
--
-- first_at is kept alongside last_at because "deferred 40 times" and "deferred
-- since 06:00" answer different operator questions, and the second one is what
-- /api/health reports.
CREATE TABLE IF NOT EXISTS deferrals (
	message_id TEXT PRIMARY KEY,
	attempts   INTEGER NOT NULL DEFAULT 0,
	first_at   INTEGER NOT NULL,
	last_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS deferrals_first_at ON deferrals(first_at);
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
	if err := applyAdditiveColumns(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// additiveColumns are columns added to a table after that table shipped.
//
// The schema const is CREATE TABLE IF NOT EXISTS, which makes it a migration
// path for a whole new TABLE and for nothing else: an existing install already
// has native_devices, so the IF NOT EXISTS fires, the new columns are never
// created, and every query naming them fails with "no such column" — which on
// this table means mail sync, contacts sync, App Pull and push MFA all break at
// once on upgrade. Columns therefore have to be added separately, here.
//
// SQLite has no ADD COLUMN IF NOT EXISTS, so each is applied only when
// pragma_table_info shows it missing. Every column must carry a non-NULL
// DEFAULT: SQLite rejects adding a NOT NULL column without one, and the default
// is also what an existing row decodes as — "" and 0 mean "not enrolled", which
// is the truth for a device paired before enrollment existed.
var additiveColumns = []struct{ table, column, ddl string }{
	{"native_devices", "enrollment_public_key", "TEXT NOT NULL DEFAULT ''"},
	{"native_devices", "enrollment_key_at", "TEXT NOT NULL DEFAULT ''"},
	{"native_devices", "encryption_enrolled", "INTEGER NOT NULL DEFAULT 0"},
	// A UnifiedPush device paired before the WebPush key exchange existed
	// decodes as "" — which is the truth: it sent no keys, so it keeps
	// receiving the unencrypted payload its client build can read.
	{"native_devices", "p256dh", "TEXT NOT NULL DEFAULT ''"},
	{"native_devices", "auth", "TEXT NOT NULL DEFAULT ''"},
}

func applyAdditiveColumns(db *sql.DB) error {
	// One transaction around probe-and-add, because the api and daemon
	// processes both open every state.db at startup.
	//
	// Probing with pragma_table_info and then ALTERing in a separate implicit
	// transaction is a check-then-act across processes: on the first boot after
	// an upgrade both see the column missing, one adds it, and the other fails
	// with "duplicate column name". That is a SQL LOGIC error, not SQLITE_BUSY,
	// so neither busy_timeout nor _txlock=immediate helps — it propagates out of
	// state.New to log.Fatal and takes the losing process down. supervisord
	// restarts it and the retry succeeds, so it self-heals, but a startup crash
	// per install is avoidable for one Begin.
	//
	// dsn() sets _txlock=immediate, so this Begin takes the write lock up front;
	// the second process then blocks on it and afterwards reads a pragma that
	// already shows the column present.
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin additive column migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, c := range additiveColumns {
		var n int
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`,
			c.table, c.column).Scan(&n); err != nil {
			return fmt.Errorf("inspect %s.%s: %w", c.table, c.column, err)
		}
		if n > 0 {
			continue
		}
		// Table and column names are constants in this file, never user input.
		if _, err := tx.Exec(fmt.Sprintf(
			`ALTER TABLE %s ADD COLUMN %s %s`, c.table, c.column, c.ddl)); err != nil {
			return fmt.Errorf("add column %s.%s: %w", c.table, c.column, err)
		}
	}
	return tx.Commit()
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
	// Poll observability. The health check watches IMAP reachability, not the
	// poller, so a daemon that has stopped ticking looks identical to a healthy
	// one from /api/health — these are what tell the two apart.
	metaLastPollTick        = "last_poll_tick"
	metaCheckpointHeldSince = "checkpoint_held_since"
	metaLastCleanup         = "last_cleanup_at"
	// The daemon's own subsystem health, written here because the API process
	// cannot see the daemon process's in-memory health.Service. See
	// health/daemon.go.
	metaDaemonHealth = "daemon_health"
)
