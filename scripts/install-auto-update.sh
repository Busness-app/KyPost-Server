#!/usr/bin/env bash
# Install a daily per-user systemd timer for update-host.sh. The user must
# already be allowed to operate Docker; do not turn a mutable checkout into a
# root system service.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "$script_dir/.." && pwd)"
if [[ "$repo_dir" =~ [[:space:]] ]]; then
  echo "the checkout path must not contain whitespace for the systemd unit" >&2
  exit 64
fi
command -v systemctl >/dev/null || { echo "systemd is required for automatic updates" >&2; exit 69; }
command -v loginctl >/dev/null || { echo "loginctl is required to keep the user timer alive after logout" >&2; exit 69; }
if ! loginctl enable-linger "$(id -un)"; then
  echo "could not enable user lingering; run: sudo loginctl enable-linger $(id -un)" >&2
  exit 77
fi

unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$unit_dir"
tmp_service="$(mktemp)"
tmp_timer="$(mktemp)"
trap 'rm -f "$tmp_service" "$tmp_timer"' EXIT
printf '[Unit]\nDescription=Update KyPost container image\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=oneshot\nEnvironment=KYPOST_AUTO_UPDATE=true\nWorkingDirectory=%s\nExecStart=%s/scripts/update-host.sh --auto\n' "$repo_dir" "$repo_dir" >"$tmp_service"
printf '[Unit]\nDescription=Daily KyPost update check\n\n[Timer]\nOnCalendar=*-*-* 03:15:00\nRandomizedDelaySec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n' >"$tmp_timer"

install -m 0644 "$tmp_service" "$unit_dir/kypost-update.service"
install -m 0644 "$tmp_timer" "$unit_dir/kypost-update.timer"
systemctl --user daemon-reload
systemctl --user enable --now kypost-update.timer
echo "Automatic KyPost updates are enabled. Check them with: systemctl --user status kypost-update.timer"
