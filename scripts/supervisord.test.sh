#!/usr/bin/env bash
# Self-check for supervisord.conf: it parses, and no two supervised streams
# share a log file.
#
# supervisord opens and rotates each program's stream independently, so two
# programs pointed at one path rename each other's file out from under a still
# open handle — the lines written after that go to an inode nobody reads and
# are discarded at the next rotation. [program:ollama] and [program:ollama-model]
# shared one, which lost exactly the model-pull retry diagnostics an operator
# opens when the classifier model never installs.
set -euo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$root_dir/supervisord.conf" <<'PY'
import collections, configparser, sys

path = sys.argv[1]
cfg = configparser.ConfigParser(strict=True, inline_comment_prefixes=(";",))
cfg.read(path)

owners = collections.defaultdict(list)
for section in cfg.sections():
    for key in ("logfile", "stdout_logfile", "stderr_logfile"):
        value = cfg[section].get(key)
        if value and value not in ("AUTO", "NONE"):
            owners[value].append(f"[{section}] {key}")

shared = {p: o for p, o in owners.items() if len(o) > 1}
if shared:
    for p, o in sorted(shared.items()):
        print(f"shared log file {p}: {', '.join(o)}", file=sys.stderr)
    sys.exit(1)

print(f"ok: {len(cfg.sections())} sections, {len(owners)} distinct log files")
PY
