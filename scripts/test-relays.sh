#!/usr/bin/env bash
# Canonical relay test command: the Workers and the code they share.
#
# There is no test framework and no install step here — node's own runner and
# type stripping are enough. What this script exists for is discovery. CI used
# to list the eight test files by hand, which meant a new test file ran only if
# whoever added it also remembered to edit the workflow; a forgotten one is
# indistinguishable from a passing one.
#
# `node --test <dir>` is not usable directly because these directories have
# checked-in node_modules and the runner walks into them. Pruning that here is
# the whole difference.
set -euo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mapfile -t tests < <(
  find push-relay-shared worker/src worker-apns/src \
    -type d -name node_modules -prune -o \
    -type f -name '*.test.mts' -print | sort
)

if [[ ${#tests[@]} -eq 0 ]]; then
  echo "no relay tests found; this script is no longer looking in the right place" >&2
  exit 1
fi

printf 'running %d relay test files\n' "${#tests[@]}"
exec node --test "${tests[@]}"
