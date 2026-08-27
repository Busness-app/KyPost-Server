package state

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// migrateJSONIfPresent imports a pre-SQLite state.json/decisions.json pair into
// an empty database.
//
// It runs once, on the first open after upgrade, and only when the database has
// no rows to lose. Everything lands inside ONE transaction, so a crash halfway
// leaves the database empty and the JSON files untouched — the next start
// simply tries again. Nothing is deleted: the originals are renamed to
// .migrated rather than removed, because the cost of keeping them is a few
// kilobytes and the cost of being wrong is an account's entire history.
func migrateJSONIfPresent(db *sql.DB, statePath, decisionsPath string) error {
	migrated, err := metaString(db, "json_migrated_at")
	if err != nil {
		return err
	}
	if migrated != "" {
		return nil
	}

	stateRaw, stateErr := os.ReadFile(statePath)
	decisionsRaw, decisionsErr := os.ReadFile(decisionsPath)
	haveState := stateErr == nil
	haveDecisions := decisionsErr == nil
	if !haveState && !haveDecisions {
		// Fresh install. Stamp it so this check is one meta read on every
		// subsequent open rather than two failed stats.
		return setMeta(db, "json_migrated_at", time.Now().UTC().Format(time.RFC3339))
	}
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", statePath, stateErr)
	}
	if decisionsErr != nil && !errors.Is(decisionsErr, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", decisionsPath, decisionsErr)
	}

	var sf stateFile
	if haveState {
		if err := json.Unmarshal(stateRaw, &sf); err != nil {
			// Refuse rather than silently starting empty: an operator whose
			// state.json stopped parsing needs to know, not to discover their
			// device pairings and audit history quietly gone.
			return fmt.Errorf("parse %s for migration (move it aside to start fresh): %w", statePath, err)
		}
	}
	var decisions []Decision
	if haveDecisions {
		if err := json.Unmarshal(decisionsRaw, &decisions); err != nil {
			return fmt.Errorf("parse %s for migration (move it aside to start fresh): %w", decisionsPath, err)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := importStateFile(tx, sf); err != nil {
		return err
	}
	for _, d := range decisions {
		if err := insertDecision(tx, d); err != nil {
			return err
		}
	}
	if err := setMeta(tx, "json_migrated_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit state migration: %w", err)
	}

	// Only after the commit succeeded. Renaming first would risk losing the
	// originals to a failed commit.
	for _, p := range []string{statePath, decisionsPath} {
		if _, err := os.Stat(p); err == nil {
			_ = os.Rename(p, p+".migrated")
		}
	}
	return nil
}

func importStateFile(tx *sql.Tx, sf stateFile) error {
	for key, value := range map[string]string{
		metaCheckpoint:     sf.LastCheckpoint,
		metaSubscriberID:   sf.SubscriberID,
		metaDeliveryMode:   normalizeDeliveryMode(sf.NativeDeliveryMode),
		metaAICreditsAt:    sf.AICreditsExhaustedAt,
		metaOllamaNotified: sf.OllamaUpdateNotifiedVersion,
	} {
		if value == "" {
			continue
		}
		if err := setMeta(tx, key, value); err != nil {
			return err
		}
	}
	if sf.AICreditsExhausted {
		if err := setMeta(tx, metaAICreditsExhausted, "1"); err != nil {
			return err
		}
	}
	if sf.PullSeq > 0 {
		if err := setMeta(tx, metaPullSeq, fmt.Sprint(sf.PullSeq)); err != nil {
			return err
		}
	}

	for id, ts := range sf.Processed {
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			// Matches the old applyStateFile, which skipped unparseable
			// entries rather than failing the load.
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO processed(message_id, seen_at) VALUES(?, ?)
			 ON CONFLICT(message_id) DO UPDATE SET seen_at = excluded.seen_at`,
			id, t.Unix()); err != nil {
			return err
		}
	}

	for i, n := range sf.Notifications {
		if _, err := tx.Exec(
			`INSERT INTO notifications(endpoint, auth, p256dh, user_agent, updated_at, seq)
			 VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(endpoint) DO NOTHING`,
			n.Endpoint, n.Auth, n.P256DH, n.UserAgent, n.UpdatedAt, i); err != nil {
			return err
		}
	}

	for i, d := range sf.NativeDevices {
		if err := insertDevice(tx, d, i); err != nil {
			return err
		}
	}

	for _, n := range sf.PullNotifications {
		data, err := json.Marshal(n.Data)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(
			`INSERT INTO pull_notifications(seq, title, body, data, created_at)
			 VALUES(?, ?, ?, ?, ?) ON CONFLICT(seq) DO NOTHING`,
			n.Seq, n.Title, n.Body, string(data), n.CreatedAt); err != nil {
			return err
		}
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
