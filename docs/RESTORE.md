# Sealed backup and restore

Configure backups on **Server → Backup**. Pair with KyRecovery using its one-time
six-digit code, or paste the suite public key and k-of-n from its ceremony page.
Compare the key fingerprint out of band. The pin is write-once; unpair removes the
URL and token but keeps the key, receipts and local copies. A KyRecovery admin must
separately revoke the token. Products cannot download from KyRecovery.

Set `KYPOST_BACKUP_DIR=/kypost/state/backups` for local copies on the existing volume,
or mount a separate writable host directory outside the data roots. Backups on the
same disk do not protect against disk loss. Retention defaults to seven own-prefix
capsules; other applications' files are left alone. The interval defaults to 24h;
the UI overrides it without restart (0 off, otherwise 15 minutes–366 days).

A backup seals once, then attempts local delivery and the paired KyRecovery deposit.
Inspect the result and receipt; a remote failure can leave a successful local copy,
and a local failure does not cancel the remote attempt. Uploads are bounded to 16
minutes. Browser disconnects do not cancel uploads; deployment shutdown allows them
to drain. Reverse proxies may need a matching response timeout. The process lock
rejects competing operations rather than queueing them behind an upload.

For a LAN destination, explicitly set `KYPOST_BACKUP_ALLOW_PRIVATE_RECOVERY=true`.
HTTPS remains mandatory; redirects, loopback and link-local destinations are refused.
The setting admits private/CGNAT destinations and is recorded on pairing audit rows.
If a private hostname needs a LAN resolver:

```sh
KYPOST_DNS=192.168.1.1 docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml up -d --build
```

This resolver also sees IMAP, SMTP and WKD lookups. Verify container DNS with
`docker inspect KyPost-Server --format '{{.HostConfig.Dns}}'`.

## What a capsule carries

- Configuration and accounts, including opaque client-wrapped PGP keys.
- Deployment secrets in SECRET_DIR, including totp-secret.key, which seals the
  KyRecovery token under a distinct derivation label. Never replace this key.
- Install-wide and per-user state.db snapshots including committed WAL rows,
  address books and other persistent state. Native-device secrets are in the
  per-user databases. Pending encrypted pickup messages are included.

IMAP mail, rebuildable mailcache.json, Ollama model blobs, logs and runtime files
are excluded. Each database has a consistent snapshot; separate databases and JSON
files are collected sequentially, not as a transaction across the whole deployment.
For a quiescent recovery point, stop services and use the CLI export.

The collector refuses missing keys needed by stored encrypted data, symlinks,
unsupported special files, files over 64 MiB or a total payload over 256 MiB.
Secret-file overrides must use their canonical SECRET_DIR locations; VAPID and
TUNING_FILE must be inside collected roots. Restore into the original configured
root paths or update embedded paths before starting.

Keep a separate protected copy of the operator's `.env`, compose overrides and
external TLS files. Environment-only credentials (for example PAIRING_SECRET,
relay keys and CAPTCHA credentials), DNS/network settings, and TLS mounts are not
captured. Restore them before startup. Client-protected PGP still requires its
owner's password/recovery material; a capsule does not bypass that protection.

## Restore into an empty staging directory

1. Stop the deployment and retain its existing volumes. Take a separate copy before
   replacing anything. Download the capsule using a KyRecovery operator session, or
   use a local `.kycap`. Record its expected capsule ID, digest, time and key ID from
   the receipt; successful decryption alone does not prove freshness.
2. Run the same or a newer compatible KyPost binary against an empty staging path:

   ```sh
   mkdir -m 700 recovered
   kypost-server restore backup.kycap "$PWD/recovered"
   ```

   Enter at least k custodian shares on stdin, one per line, then EOF (Ctrl-D).
   Never put shares in argv, chat or shared notes. Docker has no ENTRYPOINT; name
   the executable explicitly, use `-i` for stdin and mount a writable staging root:

   ```sh
   docker run --rm -i --user "$(id -u):$(id -g)" \
     -v "$PWD:/restore" ghcr.io/busness-app/kypost-server:stable \
     /usr/local/bin/kypost-server restore /restore/backup.kycap /restore/recovered
   ```

3. Compare the authenticated manifest summary with the receipt. Refuse stale,
   foreign-service, wrong-key or corrupted capsules. A nonempty target is refused.
4. With services still stopped, copy `recovered/config/`, `recovered/private/` and
   `recovered/state/` into the corresponding retained/mounted volumes. Preserve
   owner-only permissions and set ownership for the runtime account. Restore `.env`
   and external dependencies. Recreate the container without deleting volumes.
5. Confirm readiness, the same recovery-key fingerprint and a new successful
   backup. Run `backup-drill` and inspect its SQLite, account and credential checks.
   Sessions are memory-only, so users sign in again. Test mailbox access and native
   devices; their persisted registrations were restored.

If compromise prompted the restore, revoke affected native devices and re-pair them
through Security, revoke old KyRecovery tokens at KyRecovery and pair again to the
same key. For a file-backed pairing secret, stop services and remove
`/kypost/private/pairing.key` to generate a replacement on the next start; an explicit
PAIRING_SECRET must instead be rotated in `.env`. Rotate externally issued relay
credentials at their provider and update the matching environment/file. Never
regenerate imap-config.key or totp-secret.key: doing so strands encrypted data.

## Verification commands

```sh
kypost-server backup-drill
kypost-server export-capsule fresh.kycap
kypost-server deposit
```

Export refuses to overwrite an existing file. A drill creates a throwaway recovery
key internally, checks the actual opened manifest and wipes its scratch directory.
It tests the payload and recipe, not the real custodian cards. Automated synthetic
restore coverage lives in `backend/internal/backup/backup_test.go` and
`backend/internal/app/backup_test.go`; actual deployment pairing
and a real-card restore remain separate operator proofs.
