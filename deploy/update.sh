#!/usr/bin/env bash
#
# Pull the latest images and restart the long-running services.
#
# This is the manual equivalent of the GitHub Actions deploy job, and the thing
# Watchtower would eventually automate. Safe to run at any time: it does not
# touch a scan session that is currently in flight, because the scanner and
# validator run as one-shot containers rather than as managed services.
#
# Usage:
#   ./deploy/update.sh            # on the host
#   ssh deploy@host /opt/proxy-scanner/update.sh
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/proxy-scanner}"

cd "${INSTALL_DIR}"

echo "=== Pulling images"
# --profile scan is required, or Compose silently skips the profile-gated
# scanner and validator services and they go stale on the host.
docker compose --profile scan pull

echo "=== Restarting API and revalidator"
docker compose up -d --remove-orphans api revalidator

echo "=== Pruning old images"
docker image prune -f

echo
echo "=== Current state"
docker compose ps
systemctl list-timers --all 'proxy-scanner*' --no-pager || true

# The next scan session picks up the new image on its own, since each session
# starts a fresh container from :latest.
if systemctl is-active --quiet proxy-scanner-scan.service; then
    echo
    echo "NOTE: a scan session is running right now. It keeps using the image it"
    echo "      started with; the new one takes effect on the next session."
fi
