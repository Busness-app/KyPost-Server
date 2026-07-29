# Scripts

## Purpose

Container initialization, process orchestration, and Ollama model management.

## Ownership

All files under `scripts/`.

## Local Contracts

### Startup Sequence

`entrypoint.sh` (runs `bootstrap.sh` synchronously, then chowns, then execs) → `supervisord` → `api`, `daemon`, `ollama`, `ollama-model` (parallel, priority 10)

- `entrypoint.sh`: creates required directories, runs `bootstrap.sh` inline (as root, before the privilege-dropping `chown`), chowns `/kypost` to `kypost`, then execs `supervisord`. Running `bootstrap.sh` as a blocking step here — rather than as its own supervisord program — makes "credentials exist before any service starts" a hard guarantee instead of one relying on supervisord's priority-based ordering.
- `bootstrap.sh`: execs `kypost-server --mode bootstrap-admin` (implemented in `backend/internal/app/bootstrap.go`). On a fresh install — neither `users.json` nor `admin.env` present — it writes scrypt-hashed admin credentials to `admin.env`, which the backend imports into `users.json` on first start; a no-op when either file exists, so it is safe across restarts. A generated password is written to `first-run-password.txt` (mode `600`) in `CONFIG_DIR`, never to stdout; a password supplied via `BOOTSTRAP_ADMIN_PASS` writes no file. The hashing lives in the Go binary rather than inline `node -e`, which is what let the runtime image drop from `node:slim` to `debian:stable-slim` — no runtime script here may reintroduce a `node` dependency.
- `start-ollama.sh`: launches Ollama daemon on port 11434
- `pull-ollama-model.sh`: pulls the model named by `OLLAMA_MODEL` (docker-compose default: `nemotron-3-nano:4b`); requires Ollama daemon to be running first

### Supervisord Programs (from `supervisord.conf` at repo root)

| Program | Type | Priority |
|---------|------|----------|
| api | daemon | 10 |
| daemon | daemon | 10 |
| ollama | daemon | 10 |
| ollama-model | one-shot | 10 |

## Work Guidance

- `bootstrap.sh` must keep running before the `chown -R kypost:kypost /kypost` step in `entrypoint.sh` — it writes as root, and that chown is what hands the resulting files (`admin.env` and `first-run-password.txt` included) to `kypost`
- No runtime script may depend on `node`. The runtime image is `debian:stable-slim` and has no JavaScript interpreter; the frontend is static files built in an earlier stage
- Never echo a generated credential to stdout from these scripts — that is the container log stream
- `pull-ollama-model.sh` is idempotent; safe to re-run

## Verification

- `go test ./internal/app/ -run BootstrapAdmin` covers the seeding contract: a usable admin account, `600` on both secret files, idempotency across restarts, and the `users.json`-already-exists upgrade path
- On a fresh install `bootstrap.sh` must produce a valid `admin.env` with a non-empty scrypt hash owned by `kypost`; on an install with `users.json` or `admin.env` present it must leave both untouched

## Child DOX Index

No child AGENTS.md files.
