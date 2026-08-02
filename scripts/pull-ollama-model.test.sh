#!/usr/bin/env bash
# Self-check for the model installer: no Ollama, no registry, no network.
#
# The behaviour under test is what the installer does when things go WRONG,
# because the previous version's answer was "give up and exit 1" — which under
# supervisord's autorestart=false meant EXITED, no crashexit, no retry, and a
# container running permanently without the model it classifies with.
set -euo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root_dir/scripts/pull-ollama-model.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
mkdir -p "$tmp_dir/bin"

# Fake ollama. FAKE_OLLAMA_MODE selects the failure being exercised, and each
# call appends to a count file so a test can prove a retry actually happened.
cat >"$tmp_dir/bin/ollama" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mode="${FAKE_OLLAMA_MODE:?}"
counts="${FAKE_OLLAMA_COUNTS:?}"
echo "$1" >>"$counts"

pulls() { grep -c '^pull$' "$counts" || true; }
lists() { grep -c '^list$' "$counts" || true; }

case "$1" in
  list)
    case "$mode" in
      installed)   echo "NAME  ID  SIZE"; echo "test-model:1b  abc  1GB" ;;
      down)        exit 1 ;;
      # Answers only after two failures, standing in for Ollama still starting.
      slow-start)  [[ "$(lists)" -ge 3 ]] || exit 1; echo "NAME  ID  SIZE" ;;
      *)           echo "NAME  ID  SIZE" ;;
    esac
    ;;
  pull)
    case "$mode" in
      # Fails twice, then succeeds: the transient-registry case.
      flaky)  [[ "$(pulls)" -ge 3 ]] || exit 1 ;;
      never)  exit 1 ;;
    esac
    ;;
esac
EOF
chmod +x "$tmp_dir/bin/ollama"

# sleep is stubbed out so the real backoff schedule does not make this test take
# two and a half minutes. It records what it was asked to wait, which is how the
# backoff itself is asserted.
cat >"$tmp_dir/bin/sleep" <<'EOF'
#!/usr/bin/env bash
echo "$1" >>"${FAKE_SLEEPS:?}"
EOF
chmod +x "$tmp_dir/bin/sleep"

run_installer() {
  local mode="$1" models_dir="$2" timeout_s="${3:-20}"
  : >"$tmp_dir/counts"
  : >"$tmp_dir/sleeps"
  set +e
  PATH="$tmp_dir/bin:$PATH" \
    FAKE_OLLAMA_MODE="$mode" \
    FAKE_OLLAMA_COUNTS="$tmp_dir/counts" \
    FAKE_SLEEPS="$tmp_dir/sleeps" \
    OLLAMA_MODEL="test-model:1b" \
    OLLAMA_MODELS="$models_dir" \
    timeout "$timeout_s" sh "$script" >"$tmp_dir/out" 2>&1
  status=$?
  set -e
}

fail() {
  echo "FAIL: $1" >&2
  echo "--- installer output ---" >&2
  cat "$tmp_dir/out" >&2
  exit 1
}

# An already-installed model exits 0 immediately and pulls nothing. This is the
# path taken on every container restart after the first, and it must stay fast:
# supervisord runs this program with startsecs=0 precisely so an instant success
# is not mistaken for a failed start.
run_installer installed "$tmp_dir/models-installed"
[[ "$status" == 0 ]] || fail "an installed model exited $status"
grep -q '^pull$' "$tmp_dir/counts" && fail "pulled a model that was already installed"
grep -q "Ollama model ready" "$tmp_dir/out" || fail "did not report the model ready"

# A registry that fails twice and then works must end with the model installed,
# not with an exit code. The old version survived this one — it is here so the
# retry rewrite cannot regress it.
run_installer flaky "$tmp_dir/models-flaky"
[[ "$status" == 0 ]] || fail "a recoverable pull failure exited $status"
[[ "$(grep -c '^pull$' "$tmp_dir/counts")" == 3 ]] || fail "expected 3 pull attempts, got $(grep -c '^pull$' "$tmp_dir/counts")"
# 15s then 30s: the fast schedule, absorbing a blip without hammering a service
# that is already unhappy.
[[ "$(tr '\n' ' ' <"$tmp_dir/sleeps")" == "15 30 " ]] || fail "unexpected backoff: $(tr '\n' ' ' <"$tmp_dir/sleeps")"

# Ollama not answering yet is the normal state at boot, not a fault: this one
# used to exit 1 after 120s and never try again.
run_installer slow-start "$tmp_dir/models-slow"
[[ "$status" == 0 ]] || fail "a slow Ollama start exited $status"

# The two conditions that used to be terminal. Neither may exit: the installer
# has to still be running, so that a cause fixed later is picked up without a
# human restarting the container. 124 is timeout(1) killing it, which is the
# pass condition here.
run_installer never "$tmp_dir/models-never" 5
[[ "$status" == 124 ]] || fail "a failing registry exited $status instead of continuing to retry"
grep -q "classifierFailing" "$tmp_dir/out" || fail "did not tell the operator where this surfaces"
# Settles onto the capped interval rather than growing without bound.
grep -qx "900" "$tmp_dir/sleeps" || fail "never reached the capped retry interval"

readonly_dir="$tmp_dir/models-readonly"
mkdir -p "$readonly_dir"
chmod 500 "$readonly_dir"
run_installer installed "$readonly_dir" 5
chmod 700 "$readonly_dir"
[[ "$status" == 124 ]] || fail "an unwritable models dir exited $status instead of continuing to retry"
grep -q "not writable" "$tmp_dir/out" || fail "did not say the models dir was unwritable"

echo "pull-ollama-model self-check passed"
