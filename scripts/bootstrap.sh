#!/bin/sh
set -eu

mkdir -p "${CONFIG_DIR:-/kypost/config}" "${LOG_DIR:-/kypost/logs}" "${STATE_DIR:-/kypost/state}"

# Seeds first-run admin credentials if this install has no account store yet;
# a no-op on every start after the first.
#
# One call into the server binary, rather than the scrypt hashing this used to
# do inline via `node -e`. That inline version was the only thing in the
# runtime path needing a JavaScript interpreter, and it forced the whole image
# to be node:slim — a full Node runtime plus npm, and their CVE stream, carried
# to compute a hash the Go binary already computes with the same algorithm and
# the same parameters (users.HashPassword). See app.BootstrapAdmin, which also
# explains why the generated password now goes to a file instead of stdout.
exec /usr/local/bin/kypost-server --mode bootstrap-admin
