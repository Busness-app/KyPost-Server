#!/bin/sh
set -eu

base_url="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
model="${OLLAMA_MODEL:-nemotron-3-nano:4b}"
models_dir="${OLLAMA_MODELS:-/llama_lab/ollama-models}"

hostport="${base_url#http://}"
hostport="${hostport#https://}"
export OLLAMA_HOST="$hostport"
export OLLAMA_MODELS="$models_dir"

mkdir -p "$models_dir"
if ! touch "$models_dir/.write-test" 2>/dev/null; then
  echo "ERROR: Ollama models dir is not writable: $models_dir"
  exit 1
fi
rm -f "$models_dir/.write-test"

# This program runs ONCE per container start (supervisord: autorestart=false),
# so every transient failure below has to be handled here or not at all. It
# used to fall out of the wait loop without checking whether the API had ever
# answered and then run a single `ollama pull`: a slow first start or a minute
# of registry trouble left the container up, healthy, and permanently without
# the model it is supposed to classify with, until a human restarted it.
echo "Waiting for Ollama API at $base_url"
ready=""
for _ in $(seq 1 60); do
  if ollama list >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [ -z "$ready" ]; then
  echo "ERROR: Ollama API did not answer at $base_url within 120s; not pulling $model." >&2
  echo "       Check the ollama program's log, then restart the container to retry." >&2
  exit 1
fi

echo "Pulling model: $model"
echo "Using Ollama models dir: $OLLAMA_MODELS"
attempt=1
max_attempts=5
while :; do
  if ollama pull "$model"; then
    echo "Ollama model ready: $model"
    exit 0
  fi
  if [ "$attempt" -ge "$max_attempts" ]; then
    break
  fi
  # Linear backoff: 15s, 30s, 45s, 60s — 2.5 minutes of registry trouble
  # absorbed without a hot loop against a service that is already unhappy.
  delay=$((attempt * 15))
  echo "pull failed (attempt $attempt/$max_attempts); retrying in ${delay}s" >&2
  sleep "$delay"
  attempt=$((attempt + 1))
done

# Nonzero, and loudly. Classification stays broken until the model is present;
# the server reports that as classifierFailing in GET /api/health rather than as
# an unhealthy container, because restarting the container does not install a
# model the registry would not serve.
echo "ERROR: could not pull $model after $max_attempts attempts. Mail will be delivered" >&2
echo "       but not classified. Restart the container to retry once the cause is fixed." >&2
exit 1
