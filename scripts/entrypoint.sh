#!/bin/sh
set -eu

# All four data dirs, plus the model cache. The image creates these, but a
# volume or bind mount can be mounted over any of them, and `set -e` means a
# chown against a missing path below would abort the boot.
mkdir -p /kypost/config /kypost/private /kypost/logs /kypost/state /kypost/ollama-models

# Runs synchronously (as root, before the chown below) so admin.env exists
# before any service starts — a hard guarantee that supervisord's
# priority-based program ordering could only approximate.
/bin/sh /opt/kypost/scripts/bootstrap.sh

# Mounted volumes arrive owned by whoever created them on the host, so this
# has to run as root. It is the only reason this script starts privileged,
# and it is why the image has no `USER kypost` line.
#
# Scoped to the four data volumes, NOT to /kypost as a whole. /kypost also
# contains ollama-models, which docker-compose.yml maps to a host bind mount
# (OLLAMA_MODELS_HOST_DIR, ./share/ollama/models by default) holding tens of
# gigabytes of model blobs. `chown -R /kypost` walked all of it on every single
# container start — minutes of I/O before the API could bind, repeated on every
# restart, and it rewrote ownership on the host's own files, breaking any
# ollama running there under a different UID.
chown -R kypost:kypost /kypost/config /kypost/private /kypost/logs /kypost/state

# The models directory only needs to be traversable and writable at the top
# level for Ollama to pull into it; a non-recursive chown is O(1) regardless of
# how much is already cached there. If the host bind mount is read-only or
# owned by another user this is allowed to fail: a pre-populated, read-only
# model cache is a legitimate setup, and Ollama only needs to read it.
chown kypost:kypost /kypost/ollama-models 2>/dev/null \
	|| echo "note: could not chown /kypost/ollama-models; continuing (read-only or externally owned mount)"

# Drop to the unprivileged user for everything from here on, explicitly,
# rather than relying on supervisord's own `user=` option to do it. Two
# reasons: PID 1 itself is then unprivileged (so a container escape does not
# start from root), and the drop no longer depends on a setting in a config
# file that someone could edit without realizing it was load-bearing.
exec setpriv --reuid=kypost --regid=kypost --init-groups \
	supervisord -c /etc/supervisord.conf