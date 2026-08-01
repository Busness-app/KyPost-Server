# Every base image is pinned by DIGEST, not just by tag.
#
# The Ollama tarball below is pinned to a published SHA-256 with a paragraph
# explaining why unpinned build inputs are unacceptable. That argument does not
# stop at the one dependency it was written about: a tag is a mutable pointer,
# `debian:stable-slim` moves on every point release, and even `golang:1.26.5`
# is republished when its own base is rebuilt. Two builds of the same commit
# shipped different userlands, which is exactly the property the Ollama pin
# exists to prevent.
#
# Tag and digest are both written out. The tag is what a human reads; the digest
# is what Docker resolves. They must be bumped together — a digest that no longer
# matches its tag is a silent lie about what is being built, so re-resolve with:
#
#   docker buildx imagetools inspect golang:<tag> --format '{{.Manifest.Digest}}'
FROM golang:1.26.5@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS backend-builder
WORKDIR /app
COPY backend/go.mod backend/go.sum* ./backend/
RUN cd backend && go mod download
COPY backend ./backend
# -trimpath, in a file whose first fifteen lines are about reproducible builds.
# Without it the absolute build path is baked into the binary, so two builds of
# the same commit from different checkout directories differ — the exact property
# the digest pins above exist to remove. CGO is off because every dependency is
# pure Go (modernc.org/sqlite, not mattn/go-sqlite3), which keeps the build from
# silently acquiring a link against the builder stage's glibc.
RUN cd backend && CGO_ENABLED=0 go build -trimpath -o /app/bin/kypost-server ./cmd/main.go

FROM node:26.5.0-slim@sha256:715e55e4b84e4bb0ff48e49b398a848f08e55daed8eb6a0ea1839ae53bc57583 AS frontend-builder
WORKDIR /frontend
# `npm ci` and a required, non-globbed lockfile. `npm install` re-resolves
# every caret range at build time, so two builds of the same commit can ship
# different code — and one of those ranges is dompurify, the only thing between
# a hostile email and the session cookie.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend .
RUN npm run build

# Nothing in the runtime path is JavaScript: the frontend is static files from
# the stage above, and the admin-password hashing that once needed `node` is now
# `kypost-server --mode bootstrap-admin`. Keep it that way — a Node runtime here
# is a CVE stream to track for no runtime benefit. See scripts/AGENTS.md.
FROM debian:stable-slim@sha256:328d16499860ae6cb9b345e2e4cebca08c2a36e4f7278482c7bd1f39d71e5bfd
# liblzma5 and tar are named explicitly so apt re-resolves them to the latest
# available, picking up Debian security fixes published after this base tag.
#
# This `apt-get update` is the one remaining floating input, and it is a
# deliberate exception: pinning package versions here would freeze the runtime
# on the CVEs the digest above was built with, and this image parses hostile
# MIME, vCards and OpenPGP packets for a living. The digest fixes the base; apt
# is what keeps it patched. Rebuild to pick up fixes.
RUN apt-get update \
	&& apt-get install -y --no-install-recommends supervisor tzdata curl ca-certificates zstd liblzma5 tar util-linux \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd -m -s /bin/bash kypost

# Pinned release tarball verified against its published SHA-256. Never replace
# this with `curl https://ollama.com/install.sh | sh`: that is unpinned remote
# code execution at build time from a host this project does not control, and it
# makes builds non-reproducible.
#
# Bumped by .github/workflows/ollama-bump.yml, which only advances to a release
# that has been public for at least 3 days. That workflow locates these two
# lines by anchored regex — `^ARG OLLAMA_VERSION=` and `^ARG OLLAMA_SHA256=` —
# and asserts exactly one match each, so keep them at column 0 and keep them
# unique. Where they sit in the stage does not matter to it; this does:
#
# This block belongs ABOVE the COPY instructions, not below them. It produces a
# 1.68 GB layer, and Docker invalidates every layer after a changed one — so
# with it underneath, any frontend or backend edit rebuilt Ollama and made
# buildx re-upload the whole 1.68 GB to the Actions cache on `cache-to`. That
# turned a 2-6 minute ci-docker into a 16 minute one on the first PR that
# touched the frontend. Nothing here depends on the COPYs; the apt step above
# is what supplies curl, ca-certificates, zstd and tar.
ARG OLLAMA_VERSION=0.32.5
ARG OLLAMA_SHA256=f7d6bdbcf71b83aa8670c4e7dc4b6936c0952fcf8b114eaf6a11cbadb9684214
RUN curl -fsSL -o /tmp/ollama.tar.zst \
	"https://github.com/ollama/ollama/releases/download/v${OLLAMA_VERSION}/ollama-linux-amd64.tar.zst" \
	&& echo "${OLLAMA_SHA256}  /tmp/ollama.tar.zst" | sha256sum -c - \
	&& tar -C /usr/local -xaf /tmp/ollama.tar.zst \
	&& rm /tmp/ollama.tar.zst \
	&& ollama --version

WORKDIR /opt/kypost
COPY --from=backend-builder /app/bin/kypost-server /usr/local/bin/kypost-server
COPY --from=frontend-builder /frontend/dist /opt/kypost/frontend
COPY TUNING.md /opt/kypost/TUNING.md
COPY supervisord.conf /etc/supervisord.conf
COPY scripts /opt/kypost/scripts

RUN chmod +x /opt/kypost/scripts/*.sh

ENV CONFIG_DIR=/kypost/config
ENV SECRET_DIR=/kypost/private
ENV LOG_DIR=/kypost/logs
ENV STATE_DIR=/kypost/state
ENV WEB_PORT=5866
ENV TZ=America/New_York
ENV OLLAMA_BASE_URL=http://127.0.0.1:11434
ENV OLLAMA_MODEL=nemotron-3-nano:4b
ENV OLLAMA_MODELS=/kypost/ollama-models
# No `ENV PAIRING_SECRET=` here. An empty ENV is set-to-empty, not unset.
# The one consumer today (resolvePairingSecret) trims before testing, so this
# was never live — but it baked a value into the image that reads as "set" to
# any presence check (`os.LookupEnv`, `[ -n "${VAR+x}" ]`), and the next
# reader added has no reason to expect that. docker-compose.yml still passes
# the variable through when the operator actually supplies one.

RUN mkdir -p /kypost/config /kypost/private /kypost/logs /kypost/state \
	&& mkdir -p /kypost/ollama-models \
	&& chown -R kypost:kypost /kypost /opt/kypost

VOLUME ["/kypost/config", "/kypost/private", "/kypost/logs", "/kypost/state"]
EXPOSE 5866

# Without this, "the container is running" was the only liveness signal — and it
# is a bad one. The endpoint is unauthenticated and returns 503 (not 200) when the
# health service reports unhealthy, so this tracks the application's own view of
# itself rather than just TCP liveness.
#
# This makes an unhealthy container visible (in `docker compose ps`, and to any
# orchestrator that polls it). It does not restart anything: Docker Engine's
# restart policies react to a container exiting, and health status only drives
# replacement under Swarm.
#
# Self-healing comes from supervisord plus Docker's restart policy, not from
# this probe: a supervised program that exhausts its (bounded) startretries goes
# FATAL, the crashexit event listener takes PID 1 down, the container exits, and
# `restart: unless-stopped` restarts it with backoff. See supervisord.conf.
#
# start-period is generous because first boot pulls the Ollama model.
#
# Tries http first, then https, because TLS_CERT_FILE/TLS_KEY_FILE can turn this
# listener into HTTPS (see backend/internal/api/tls.go) and a fixed scheme here
# would then fail every probe forever — marking a perfectly healthy container
# unhealthy, which is the exact false signal this check was added to remove. -k
# on the https attempt is correct and not a shortcut: the probe is a loopback
# call to the same process, and the certificate is issued for the public
# hostname, not for 127.0.0.1, so verification could never succeed.
HEALTHCHECK --interval=30s --timeout=5s --start-period=180s --retries=3 \
	CMD curl -fsS "http://127.0.0.1:${WEB_PORT}/api/health" \
	|| curl -fsSk "https://127.0.0.1:${WEB_PORT}/api/health" \
	|| exit 1

# No `USER kypost` on purpose: entrypoint.sh must start as root to chown the
# mounted volumes, then drops to kypost via setpriv before exec'ing supervisord,
# so PID 1 and every service still run unprivileged.
CMD ["/opt/kypost/scripts/entrypoint.sh"]
