#!/bin/sh
set -eu

base_url="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
model="${OLLAMA_MODEL:-nemotron-3-nano:4b}"
models_dir="${OLLAMA_MODELS:-/llama_lab/ollama-models}"

hostport="${base_url#http://}"
hostport="${hostport#https://}"
export OLLAMA_HOST="$hostport"
export OLLAMA_MODELS="$models_dir"

# This program runs until the model is installed, then exits 0 and stays exited.
#
# It used to give up — after five pull attempts, or after 120s of the Ollama API
# not answering, or immediately if the models directory was unwritable — and
# exit 1. Under supervisord's autorestart=false that exit was terminal: the
# program went EXITED rather than FATAL, so the crashexit listener never fired,
# nothing restarted it, and a container that met any of those conditions at boot
# ran forever without the model it is supposed to classify with. The only
# recovery was a human noticing and restarting the container, and until
# classifier health reached /api/health (see health/daemon.go) there was nothing
# for them to notice.
#
# So nothing here gives up. One outer loop covers all three conditions, because
# all three are the same kind of problem: a cause that may be fixed later, by
# somebody who is not going to restart this container to prove it. Fast retries
# absorb a blip; then it settles onto a capped interval and picks the model up
# whenever the cause clears.
#
# Retrying in-process rather than by exiting for supervisord to restart is
# deliberate: this program's startsecs is 0 (it must be able to exit 0 in
# milliseconds when the model is already there), so an exit-and-restart cycle
# has no floor on it and a fast failure — the unwritable directory — would spin
# as fast as the machine allows. A sleep in a loop has a floor by construction.
attempt=1
# Backoff schedule: 15s, 30s, 45s, 60s while the failure might be a blip, then
# every max_delay seconds indefinitely. Capped rather than growing without
# bound, so a cause fixed at 3am is picked up within fifteen minutes instead of
# whenever an ever-doubling delay happens to come round.
max_fast_attempts=5
max_delay=900

# retry_delay prints the reason (loudly for the fast attempts, then once at the
# transition, then silently) and sleeps. Silence afterwards is deliberate: an
# operator needs to see that the pull is failing, not one line every fifteen
# minutes for the life of the container.
retry_delay() {
  reason="$1"
  if [ "$attempt" -lt "$max_fast_attempts" ]; then
    delay=$((attempt * 15))
  else
    delay="$max_delay"
  fi
  if [ "$attempt" -lt "$max_fast_attempts" ]; then
    echo "$reason (attempt $attempt); retrying in ${delay}s" >&2
  elif [ "$attempt" -eq "$max_fast_attempts" ]; then
    echo "ERROR: $reason, after $max_fast_attempts attempts. Mail is delivered but" >&2
    echo "       not classified until this succeeds. Retrying every ${max_delay}s; the" >&2
    echo "       server reports this as classifierFailing in GET /api/health." >&2
  fi
  sleep "$delay"
  attempt=$((attempt + 1))
}

while :; do
  mkdir -p "$models_dir" 2>/dev/null || true
  if ! touch "$models_dir/.write-test" 2>/dev/null; then
    retry_delay "Ollama models dir is not writable: $models_dir"
    continue
  fi
  rm -f "$models_dir/.write-test"

  # Ollama is a sibling supervised program and races this one at boot, so "not
  # answering yet" is the normal first state rather than a fault.
  if ! ollama list >/dev/null 2>&1; then
    retry_delay "Ollama API is not answering at $base_url"
    continue
  fi

  # Already installed: nothing to do. Cheap, and it makes every restart after
  # the first instant instead of a network round trip to the registry.
  if ollama list 2>/dev/null | awk '{print $1}' | grep -qx "$model"; then
    echo "Ollama model ready: $model"
    exit 0
  fi

  echo "Pulling model: $model"
  echo "Using Ollama models dir: $OLLAMA_MODELS"
  if ollama pull "$model"; then
    echo "Ollama model ready: $model"
    exit 0
  fi
  retry_delay "could not pull $model"
done
