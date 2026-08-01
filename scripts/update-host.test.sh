#!/usr/bin/env bash
# Small host-updater self-check: no Docker daemon, registry, or systemd needed.
set -euo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
mkdir -p "$tmp_dir/bin"

cat >"$tmp_dir/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state="${FAKE_DOCKER_STATE:?}"
if [[ "$1 ${2:-} ${3:-}" == "compose config --images" ]]; then
  echo "ghcr.io/yoshiofthewire/kypost-server:stable"
elif [[ "$1 ${2:-} ${3:-}" == "compose images -q" ]]; then
  echo "sha256:previous"
elif [[ "$1 ${2:-}" == "buildx imagetools" ]]; then
  echo "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
elif [[ "$1" == "pull" ]]; then
  :
elif [[ "$1 ${2:-}" == "image inspect" && "$*" == *"RepoDigests"* ]]; then
  echo "ghcr.io/yoshiofthewire/kypost-server@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
elif [[ "$1 ${2:-}" == "image inspect" ]]; then
  if [[ "${FAKE_DOCKER_MODE:-}" == "noop" ]]; then echo "sha256:previous"; else echo "sha256:candidate"; fi
elif [[ "$1" == "compose" && " $* " == *" up "* ]]; then
  count=0
  [[ -f "$state" ]] && count="$(cat "$state")"
  count=$((count + 1))
  printf '%s' "$count" >"$state"
  if [[ "${FAKE_DOCKER_MODE:-}" == "rollback" && "$count" == 1 ]]; then exit 1; fi
else
  echo "unexpected docker invocation: $*" >&2
  exit 1
fi
EOF
chmod +x "$tmp_dir/bin/docker"

cat >"$tmp_dir/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1 ${2:-}" == "attestation verify" ]] || exit 1
EOF
chmod +x "$tmp_dir/bin/gh"

run_case() {
  local mode="$1" output status
  : >"$tmp_dir/$mode-count"
  set +e
  output="$(FAKE_DOCKER_MODE="$mode" FAKE_DOCKER_STATE="$tmp_dir/$mode-count" KYPOST_COMPOSE_DIR="$tmp_dir" PATH="$tmp_dir/bin:$PATH" "$root_dir/scripts/update-host.sh" 2>&1)"
  status=$?
  set -e
  case "$mode" in
    noop)
      [[ "$status" == 0 ]] || { echo "no-op updater exit = $status" >&2; exit 1; }
      grep -q 'action=verify .*result=started' <<<"$output"
      grep -q 'action=update .*result=already-current' <<<"$output"
      [[ ! -s "$tmp_dir/$mode-count" ]] || { echo "no-op started Compose" >&2; exit 1; }
      ;;
    rollback)
      [[ "$status" == 1 ]] || { echo "failed update exit = $status" >&2; exit 1; }
      grep -q 'action=rollback .*result=healthy' <<<"$output"
      [[ "$(cat "$tmp_dir/$mode-count")" == 2 ]] || { echo "rollback did not recreate twice" >&2; exit 1; }
      ;;
  esac
}

run_case noop
run_case rollback
echo "update-host self-check passed"
