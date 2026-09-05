# Backup

## Purpose

KyPost's adapter over ky-primitives/recoveryclient v0.5.1: configuration, account/key collection, SQLite snapshots, drills and local audit storage.

## Ownership

This package owns payload selection and verification. API/CLI callers own credential checks and durable intent/completion audit. The library owns sealing, pairing transport, key pinning, retention, schedules and restore.

## Local Contracts

- Service name is `KyPost`. The token sealer uses the existing TOTP master key with HKDF label `kypost:setting:kyrecovery_token`; load it at operation time, never generate a replacement.
- Settings and flat `backup_audit` rows use the install-wide state.db. Pair, pin and unpair settings commit transactionally.
- Nonblocking `backup-operation.lock` coordinates API, CLI and daemon operations across processes. Busy operations return ErrInProgress. Keep lock files on stable inodes.
- Collect config/private/state, snapshot each state.db with the library's SQLiteSnapshot, and refuse missing dependent keys or unsupported files. IMAP mail and rebuildable cache are excluded; encrypted pending pickup messages are included. The public recipe carries rules, never user-specific paths.
- Local destination is outside all data roots or exactly STATE_DIR/backups. The dedicated destination, runtime supervisor files, lock files, migrated files and backup scratch are excluded. Other nonregular files are refused.
- Individual secret overrides must resolve to their default SECRET_DIR locations. Configured VAPID keys and existing tuning overrides must be inside collected roots. A missing optional TUNING_FILE is allowed only inside CONFIG_DIR, SECRET_DIR or STATE_DIR, matching the default container fallback; external overrides are refused even when missing, and required keys remain mandatory. Operator environment and external TLS mounts are restored separately; see docs/RESTORE.md.
- Drills serialize with all backup operations, use an opened authenticated manifest, validate its recipe and required files, verify SQLite integrity and decrypt stored IMAP credentials. Client-wrapped PGP stays opaque.
- Restore is CLI-only, shares on stdin. No running service holds the suite recovery private key.

## Work Guidance

- Use library helpers for transport and capsule behavior; adapt product storage rather than copying library implementations.
- Record an intent before mutations and a completion afterward. If completion auditing fails, state that the action may have happened.

## Verification

- `GOTOOLCHAIN=go1.26.6 go test -race ./internal/backup ./internal/state ./internal/config`
- `go test ./internal/api -run TestBackup` covers admin/CSRF/credential gates and audit outages.
- `TestNothingInTheServerDecrypts` scans backend source with guardtest, allowing only app.runRestore.

## Child DOX Index

None.
