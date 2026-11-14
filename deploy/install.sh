#!/usr/bin/env bash
# Install warden as a systemd service. Run from the repo root after `make`.
set -euo pipefail
[ "$(id -u)" = 0 ] || exec sudo "$0" "$@"
install -m 0755 bin/warden /usr/local/bin/warden
install -d -m 0750 /etc/warden /var/log/warden
if [ ! -f /etc/warden/warden.yaml ]; then
  /usr/local/bin/warden defaults > /etc/warden/warden.yaml
  chmod 0640 /etc/warden/warden.yaml
fi
install -m 0644 README.md /etc/warden/README.md
install -m 0644 deploy/warden.service /etc/systemd/system/warden.service
systemctl daemon-reload
systemctl enable --now warden
/usr/local/bin/warden caps
echo "warden installed. alerts: journalctl -u warden -f   |   /var/log/warden/alerts.jsonl"
