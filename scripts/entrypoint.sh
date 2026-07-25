#!/bin/sh
set -eu

mkdir -p /kypost/config /kypost/logs /kypost/state

# Runs synchronously (as root, before the chown below) so admin.env exists
# before any service starts — a hard guarantee that supervisord's
# priority-based program ordering could only approximate.
/bin/sh /opt/kypost/scripts/bootstrap.sh

# Mounted volumes arrive owned by whoever created them on the host, so this
# has to run as root. It is the only reason this script starts privileged,
# and it is why the image has no `USER kypost` line.
chown -R kypost:kypost /kypost

# Drop to the unprivileged user for everything from here on, explicitly,
# rather than relying on supervisord's own `user=` option to do it. Two
# reasons: PID 1 itself is then unprivileged (so a container escape does not
# start from root), and the drop no longer depends on a setting in a config
# file that someone could edit without realizing it was load-bearing.
exec setpriv --reuid=kypost --regid=kypost --init-groups \
	supervisord -c /etc/supervisord.conf