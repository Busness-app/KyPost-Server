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

echo "Waiting for Ollama API at $base_url"
for i in $(seq 1 60); do
  if ollama list >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "Pulling model: $model"
echo "Using Ollama models dir: $OLLAMA_MODELS"
ollama pull "$model"

echo "Ollama model ready: $model"
