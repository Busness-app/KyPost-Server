FROM golang:1.26.5 AS backend-builder
WORKDIR /app
COPY backend/go.mod backend/go.sum* ./backend/
RUN cd backend && go mod download
COPY backend ./backend
RUN cd backend && go build -o /app/bin/kypost-server ./cmd/main.go

FROM node:26.5.0-slim AS frontend-builder
WORKDIR /frontend
# `npm ci` (not `npm install`) and a required, non-globbed lockfile: the
# lockfile is the point. `npm install` re-resolves every caret range at build
# time, so two builds of the same commit could ship different code — and one
# of those ranges is dompurify, which is the only thing standing between a
# hostile email and the session cookie.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend .
RUN npm run build

FROM node:26.5.0-slim
# liblzma5 and tar are explicitly upgraded (not just pulled from the base
# image as-is) to pick up any Debian security fixes published after this
# base image tag was built — apt-get install re-resolves already-installed
# packages to the latest version available from the configured repos.
RUN apt-get update \
	&& apt-get install -y --no-install-recommends supervisor tzdata curl ca-certificates zstd liblzma5 tar util-linux \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd -m -s /bin/bash kypost

# npm itself is never invoked at runtime here (only the `node` interpreter
# is, via scripts/bootstrap.sh), but the base image ships npm with its own
# bundled, independently-versioned undici copy that lags well behind
# Node's own runtime undici — upgrade it explicitly rather than leave an
# unused CLI tool sitting in the image with a vulnerable dependency.
RUN npm install -g npm@12.0.1

WORKDIR /opt/kypost
COPY --from=backend-builder /app/bin/kypost-server /usr/local/bin/kypost-server
COPY --from=frontend-builder /frontend/dist /opt/kypost/frontend
COPY TUNING.md /opt/kypost/TUNING.md
COPY supervisord.conf /etc/supervisord.conf
COPY scripts /opt/kypost/scripts

RUN chmod +x /opt/kypost/scripts/*.sh

# Ollama is installed from a pinned release tarball verified against its
# published SHA-256, not by piping a remote install script into a shell.
# `curl https://ollama.com/install.sh | sh` is arbitrary remote code
# execution at build time from a URL this project does not control, with no
# version pin: every rebuild installed a different Ollama, so builds were
# not reproducible and a compromise of that host was a compromise of this
# image.
#
# OLLAMA_VERSION/OLLAMA_SHA256 are bumped by .github/workflows/ollama-bump.yml,
# which only advances to a release that has been public for at least 3 days.
ARG OLLAMA_VERSION=0.32.1
ARG OLLAMA_SHA256=83b1f22841eb7f6c4900c6797f960ebaa09466874442ea5b8ae3da6980d3914c
RUN curl -fsSL -o /tmp/ollama.tar.zst \
	"https://github.com/ollama/ollama/releases/download/v${OLLAMA_VERSION}/ollama-linux-amd64.tar.zst" \
	&& echo "${OLLAMA_SHA256}  /tmp/ollama.tar.zst" | sha256sum -c - \
	&& tar -C /usr/local -xaf /tmp/ollama.tar.zst \
	&& rm /tmp/ollama.tar.zst \
	&& ollama --version

ENV CONFIG_DIR=/kypost/config
ENV SECRET_DIR=/kypost/private
ENV LOG_DIR=/kypost/logs
ENV STATE_DIR=/kypost/state
ENV WEB_PORT=5866
ENV TZ=America/New_York
ENV OLLAMA_BASE_URL=http://127.0.0.1:11434
ENV OLLAMA_MODEL=nemotron-3-nano:4b
ENV OLLAMA_MODELS=/kypost/ollama-models
ENV PAIRING_SECRET=

RUN mkdir -p /kypost/config /kypost/private /kypost/logs /kypost/state \
	&& mkdir -p /kypost/ollama-models \
	&& chown -R kypost:kypost /kypost /opt/kypost

VOLUME ["/kypost/config", "/kypost/private", "/kypost/logs", "/kypost/state"]
EXPOSE 5866

# There is deliberately no `USER kypost` here. entrypoint.sh must start as
# root to chown the mounted volumes (which arrive owned by whoever created
# them on the host); it drops to kypost via setpriv before exec'ing
# supervisord, so PID 1 and every service run unprivileged.
CMD ["/opt/kypost/scripts/entrypoint.sh"]
