#!/usr/bin/env bash
# Update KyPost from the host. This must never run in the container: Docker
# daemon access belongs to the operator, not to a web-facing mail application.
set -euo pipefail

readonly official_image="ghcr.io/yoshiofthewire/kypost-server"

mode="manual"
if [[ "${1:-}" == "--auto" ]]; then
  mode="automatic"
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--auto]" >&2
  exit 64
fi

if [[ "$mode" == "automatic" && "${KYPOST_AUTO_UPDATE:-}" != "true" ]]; then
  exit 0
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="${KYPOST_COMPOSE_DIR:-$(cd -- "$script_dir/.." && pwd)}"
wait_timeout="${KYPOST_UPDATE_WAIT_TIMEOUT:-300}"
if ! [[ "$wait_timeout" =~ ^[0-9]+$ ]] || ((wait_timeout == 0)); then
  echo "KYPOST_UPDATE_WAIT_TIMEOUT must be a positive number of seconds" >&2
  exit 64
fi

task_id="kypost-update-$(date -u +%Y%m%dT%H%M%SZ)-$$"
log() {
  printf '%s actor=%s task_id=%s correlation_id=%s action=%s target=kypost-server severity=%s result=%s\n' \
    "$(date -u +%FT%TZ)" "$(id -un)" "$task_id" "$task_id" "$1" "$2" "$3" >&2
}

command -v docker >/dev/null || { echo "docker is required on the host" >&2; exit 69; }
command -v flock >/dev/null || { echo "flock is required on the host" >&2; exit 69; }
# Both are Docker plugins rather than separate binaries, so `command -v docker`
# says nothing about whether they are present. Check them here instead of
# failing several steps later inside a Compose or registry call.
docker compose version >/dev/null 2>&1 || { echo "docker compose (Compose v2) is required on the host" >&2; exit 69; }
docker buildx version >/dev/null 2>&1 || { echo "docker buildx is required to resolve the image digest" >&2; exit 69; }
cd -- "$repo_dir"
exec 9>"$repo_dir/.kypost-update.lock"
if ! flock -n 9; then
  log skipped info already-running
  exit 0
fi

mapfile -t images < <(docker compose config --images)
if [[ ${#images[@]} -ne 1 || -z "${images[0]}" ]]; then
  echo "expected exactly one Compose image; check docker-compose.yml" >&2
  exit 65
fi
image="${images[0]}"
image_repo="${image%:*}"
if [[ "$image_repo" != "$official_image" ]]; then
  echo "this updater only supports the official image: $official_image" >&2
  exit 65
fi
previous_id="$(docker compose images -q kypost-server | head -n 1)"
previous_image=""
if [[ -n "$previous_id" ]]; then
  previous_image="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$previous_id" | grep -m1 "^${official_image}@sha256:" || true)"
  if [[ -z "$previous_image" ]]; then
    echo "current image has no immutable official digest, so there is no rollback target; update this install with 'git pull --ff-only && docker compose up --build -d' and use published images afterwards" >&2
    exit 65
  fi
fi

candidate_digest="$(docker buildx imagetools inspect "$image" --format '{{.Manifest.Digest}}')"
if ! [[ "$candidate_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "registry returned an invalid image digest" >&2
  exit 65
fi
candidate_image="${official_image}@${candidate_digest}"
if [[ "${KYPOST_UPDATE_ALLOW_UNVERIFIED_IMAGE:-}" != "true" ]]; then
  command -v gh >/dev/null || { echo "gh is required to verify the published image attestation" >&2; exit 69; }
  log verify info started
  gh attestation verify "oci://${candidate_image}" --owner Yoshiofthewire \
    --repo Yoshiofthewire/KyPost-Server \
    --signer-workflow Yoshiofthewire/KyPost-Server/.github/workflows/release-image.yml
else
  log verify warning bypassed
fi

log pull info started
docker pull "$candidate_image"
candidate_id="$(docker image inspect --format '{{.Id}}' "$candidate_image")"
if [[ -n "$previous_id" && "$candidate_id" == "$previous_id" ]]; then
  log update info already-current
  exit 0
fi

update_override="$(mktemp "$repo_dir/.kypost-update.XXXXXX.yml")"
trap 'rm -f "$update_override"' EXIT
printf 'services:\n  kypost-server:\n    image: %s\n' "$candidate_image" >"$update_override"
compose=(docker compose -f "$repo_dir/docker-compose.yml" -f "$update_override")

log update info started
if "${compose[@]}" up -d --no-build --wait --wait-timeout "$wait_timeout" kypost-server; then
  log update info healthy
  exit 0
fi

if [[ -z "$previous_id" ]]; then
  log rollback error unavailable-no-previous-image
  exit 1
fi

log rollback warning started
printf 'services:\n  kypost-server:\n    image: %s\n' "$previous_image" >"$update_override"
if "${compose[@]}" up -d --no-build --force-recreate --wait --wait-timeout "$wait_timeout" kypost-server; then
  log rollback warning healthy
else
  log rollback error failed
fi
exit 1
