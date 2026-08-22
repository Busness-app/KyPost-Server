# Scripts

## Purpose

Container initialization, process orchestration, Ollama model management, and host-side image updates.

## Ownership

All files under `scripts/`.

## Local Contracts

### Startup Sequence

`entrypoint.sh` (runs `bootstrap.sh` synchronously, then chowns, then execs) → `supervisord` → `api`, `daemon`, `ollama`, `ollama-model` (parallel, priority 10)

- `entrypoint.sh`: creates required directories, runs `bootstrap.sh` inline (as root, before the privilege-dropping `chown`), chowns `/kypost` to `kypost`, then execs `supervisord`. Running `bootstrap.sh` as a blocking step here — rather than as its own supervisord program — makes "credentials exist before any service starts" a hard guarantee instead of one relying on supervisord's priority-based ordering.
- `bootstrap.sh`: execs `kypost-server --mode bootstrap-admin` (implemented in `backend/internal/app/bootstrap.go`). On a fresh install — neither `users.json` nor `admin.env` present — it writes scrypt-hashed admin credentials to `admin.env`, which the backend imports into `users.json` on first start; a no-op when either file exists, so it is safe across restarts. A generated password is written to `first-run-password.txt` (mode `600`) in `CONFIG_DIR`, never to stdout; a password supplied via `BOOTSTRAP_ADMIN_PASS` writes no file. The hashing lives in the Go binary rather than inline `node -e`, which is what let the runtime image drop from `node:slim` to `debian:stable-slim` — no runtime script here may reintroduce a `node` dependency.
- `crash-exit.sh`: supervisord event listener on `PROCESS_STATE_FATAL`. Sends `SIGTERM` to PID 1 so the container exits and `restart: unless-stopped` restarts it. It is the second half of the bounded-`startretries` design and is not optional: supervisord's default behaviour on FATAL is to keep running in front of a dead service, which leaves PID 1 healthy and the container "running" while nothing is served, and Docker restart policies react only to a container exiting. It speaks the supervisor event protocol on stdin/stdout, so it must print nothing to stdout but `READY` and `RESULT`.
- `start-ollama.sh`: launches Ollama daemon on port 11434
- `pull-ollama-model.sh`: pulls the model named by `OLLAMA_MODEL` (docker-compose default: `nemotron-3-nano:4b`); requires Ollama daemon to be running first. It runs **once** per container start (`autorestart=false`), so it owns its own retries: it exits nonzero if the Ollama API never answers within 120s, and retries the pull up to 5 times with linear backoff. Do not remove either — without them a slow first start or a brief registry outage left the container up and healthy with no model, permanently, and a supervisord retry instead of an in-script one would take the whole container down for something that does not need it. Classification being down is reported as `classifierFailing` in `GET /api/health`, not as an unhealthy container.
- `update-host.sh`: runs only on the Docker host. It resolves the official image to a digest, verifies its GitHub attestation, locks, waits for health, and recreates the prior digest if the new container fails. It never enters the image or receives the Docker socket.
- `test-relays.sh`: the canonical Cloudflare Worker relay test command, run by CI and by `npm test` in both Worker packages. It discovers `*.test.mts` under `push-relay-shared/`, `worker/src/`, and `worker-apns/src/` rather than naming files, so a new test cannot be added and silently not run; it prunes `node_modules` (which is why `node --test <dir>` is not used) and fails when it finds nothing.
- `install-auto-update.sh`: explicitly enables lingering, then installs a daily per-user systemd timer that calls `update-host.sh --auto`; it is opt-in and runs as the user already authorized to operate Docker, never as root from a mutable checkout.

### Supervisord Programs (from `supervisord.conf` at repo root)

| Program | Type | Priority |
|---------|------|----------|
| api | daemon | 10 |
| daemon | daemon | 10 |
| ollama | daemon | 10 |
| ollama-model | one-shot | 10 |
| crashexit | event listener (`PROCESS_STATE_FATAL`) | n/a |

`startretries` is 20 on the three long-running programs. Not 3 (supervisord's default, which gives up silently) and not a very large number: supervisord does **not** back off between restart attempts, so a program that exits immediately restarts as fast as the machine allows, forever, on a box that is also running an LLM. 20 covers the transient case — a dependency not ready yet — and `crashexit` handles what comes after.

## Work Guidance

- `bootstrap.sh` must keep running before the `chown -R kypost:kypost /kypost` step in `entrypoint.sh` — it writes as root, and that chown is what hands the resulting files (`admin.env` and `first-run-password.txt` included) to `kypost`
- No runtime script may depend on `node`. The runtime image is `debian:stable-slim` and has no JavaScript interpreter; the frontend is static files built in an earlier stage
- Never echo a generated credential to stdout from these scripts — that is the container log stream
- `pull-ollama-model.sh` is idempotent; safe to re-run
- `update-host.sh` must remain host-only. Do not mount `/var/run/docker.sock` into KyPost or turn the web UI into an update trigger; that would give a mail-facing process host control.
- Do not raise `startretries` to "fix" a crash loop, and do not remove `crashexit`. Each alone reintroduces one of the two failure modes it exists to close: an invisible hot loop, or an invisible death. A program that genuinely cannot start should take the container down where an operator and an orchestrator can both see it

## Verification

- `go test ./internal/app/ -run BootstrapAdmin` covers the seeding contract: a usable admin account, `600` on both secret files, idempotency across restarts, and the `users.json`-already-exists upgrade path
- `sh -n scripts/crash-exit.sh` parses; `docker compose config -q` fails without `KYPOST_BIND` and succeeds with it
- `bash -n scripts/update-host.sh scripts/install-auto-update.sh` parses and `bash scripts/update-host.test.sh` covers no-op and health-failure rollback without Docker; do not run the installer in CI because it enables user lingering via `loginctl` and installs live units under `${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user`
- `bash scripts/test-relays.sh` runs every relay test; it must report a nonzero file count, since finding nothing is a failure, not a pass
- On a fresh install `bootstrap.sh` must produce a valid `admin.env` with a non-empty scrypt hash owned by `kypost`; on an install with `users.json` or `admin.env` present it must leave both untouched

## Child DOX Index

No child AGENTS.md files.
