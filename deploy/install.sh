#!/usr/bin/env bash
#
# Install the proxy scanner onto a Debian host that already has Docker.
#
# What it does:
#   * copies docker-compose.yml to /opt/proxy-scanner (backing up any differing copy)
#   * seeds /opt/proxy-scanner/.env from deploy/env.example, never overwriting it
#   * installs the systemd units and timers, only creating ones that don't exist
#   * enables the timers and starts the API + revalidator
#
# What it deliberately does NOT do: install Docker, create users, add SSH keys,
# or touch firewall rules.
#
# Usage, from a checkout of this repo on the target host:
#   sudo ./deploy/install.sh
#   sudo ./deploy/install.sh --force     # also overwrite systemd units that differ
#   sudo ./deploy/install.sh --no-pull   # skip the image pull
#
# Idempotent — re-run it after pulling a newer checkout.
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/proxy-scanner}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORCE=""
PULL=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)   FORCE=1 ;;
        --no-pull) PULL=0 ;;
        # Print the header comment block, stopping at the first line of code so
        # this cannot drift as the file changes.
        -h|--help) awk 'NR>1 && !/^#/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"; exit 0 ;;
        *)         printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

log()  { printf '\n=== %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root (try: sudo $0)"
[[ -f "${REPO_ROOT}/docker-compose.yml" ]] || die "no docker-compose.yml at ${REPO_ROOT}"

# ---------------------------------------------------------------------------
# Prerequisites — check, don't install.
# ---------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
docker compose version >/dev/null 2>&1 || die "the 'docker compose' plugin is missing (install docker-compose-plugin)"
command -v systemctl >/dev/null 2>&1 || die "systemctl not found; this host is not running systemd"

# OnSuccess= in proxy-scanner-scan.service needs systemd 249+. Debian 12 ships
# 252, so this only trips on something unexpectedly old.
SYSTEMD_VER="$(systemctl --version | awk 'NR==1{print $2}')"
if [[ "${SYSTEMD_VER}" =~ ^[0-9]+$ ]] && (( SYSTEMD_VER < 249 )); then
    printf 'WARNING: systemd %s is older than 249; OnSuccess= will be ignored and\n' "${SYSTEMD_VER}" >&2
    printf '         the validator will only run from its own timer.\n' >&2
fi

# ---------------------------------------------------------------------------
# /opt/proxy-scanner
# ---------------------------------------------------------------------------
log "Installing compose file to ${INSTALL_DIR}"
install -d -m 0755 "${INSTALL_DIR}"

if [[ -f "${INSTALL_DIR}/docker-compose.yml" ]] \
   && ! cmp -s "${REPO_ROOT}/docker-compose.yml" "${INSTALL_DIR}/docker-compose.yml"; then
    backup="${INSTALL_DIR}/docker-compose.yml.bak"
    cp -p "${INSTALL_DIR}/docker-compose.yml" "${backup}"
    info "previous copy differed; backed it up to ${backup}"
fi
install -m 0644 "${REPO_ROOT}/docker-compose.yml" "${INSTALL_DIR}/docker-compose.yml"
info "docker-compose.yml"

# Copy update.sh alongside it so the host can pull new images without needing a
# checkout at all.
install -m 0755 "${REPO_ROOT}/deploy/update.sh" "${INSTALL_DIR}/update.sh"
info "update.sh"

if [[ -f "${INSTALL_DIR}/.env" ]]; then
    info ".env already present — left untouched"
else
    # 0600 root:root: this file can hold API_TOKEN. The systemd units all run as
    # root so they can read it, but it does mean interactive `docker compose`
    # commands in this directory need sudo — Compose parses .env before it talks
    # to the daemon, so docker group membership alone is not enough.
    install -m 0600 "${REPO_ROOT}/deploy/env.example" "${INSTALL_DIR}/.env"
    info ".env seeded from deploy/env.example (review it)"
    NEEDS_ENV=1
fi

# Fail early on a malformed compose file rather than at first timer firing.
# --profile scan is required or Compose silently ignores the scanner and
# validator services, which are profile-gated.
(cd "${INSTALL_DIR}" && docker compose --profile scan config --quiet) \
    || die "docker-compose.yml at ${INSTALL_DIR} is not valid"
info "compose file validates"

# ---------------------------------------------------------------------------
# systemd units — create missing ones; leave existing ones alone unless --force.
# ---------------------------------------------------------------------------
log "Installing systemd units"
UNITS_CHANGED=0
for src in "${REPO_ROOT}"/deploy/systemd/*.service "${REPO_ROOT}"/deploy/systemd/*.timer; do
    name="$(basename "${src}")"
    dst="/etc/systemd/system/${name}"

    if [[ ! -e "${dst}" ]]; then
        install -m 0644 "${src}" "${dst}"
        info "created  ${name}"
        UNITS_CHANGED=1
    elif cmp -s "${src}" "${dst}"; then
        info "current  ${name}"
    elif [[ -n "${FORCE}" ]]; then
        cp -p "${dst}" "${dst}.bak"
        install -m 0644 "${src}" "${dst}"
        info "updated  ${name} (previous saved to ${name}.bak)"
        UNITS_CHANGED=1
    else
        info "DIFFERS  ${name} — kept as-is; re-run with --force to update"
        diff -u "${dst}" "${src}" | sed 's/^/             /' || true
    fi
done

if (( UNITS_CHANGED )); then
    systemctl daemon-reload
    info "daemon-reload done"
fi

# Cap journal growth. The units log to the journal, so there is no logrotate
# config to install.
if ! grep -qE '^\s*SystemMaxUse=' /etc/systemd/journald.conf 2>/dev/null; then
    log "Capping journald at 500M"
    printf '\n# Added by proxy-scanner install.sh\nSystemMaxUse=500M\n' >> /etc/systemd/journald.conf
    systemctl restart systemd-journald
fi

# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------
if (( PULL )); then
    log "Pulling images"
    if ! (cd "${INSTALL_DIR}" && docker compose --profile scan pull); then
        cat >&2 <<'MSG'

ERROR: image pull failed.

If this was a 403/unauthorized on a specific package, that package is private on
GHCR. Either make it public (GitHub -> Packages -> the package -> Package
settings -> Change visibility) or authenticate on this host:

    echo "$GHCR_PAT" | docker login ghcr.io -u <github-username> --password-stdin

using a personal access token with read:packages.
MSG
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Enable
# ---------------------------------------------------------------------------
log "Enabling services and timers"
systemctl enable --now proxy-scanner.service
systemctl enable --now proxy-scanner-scan.timer
systemctl enable --now proxy-scanner-validate.timer

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log "Installed"
systemctl list-timers --all 'proxy-scanner*' --no-pager || true
(cd "${INSTALL_DIR}" && docker compose ps) || true

DEFAULT_IF="$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')"

echo
echo "Notes:"
if [[ -n "${NEEDS_ENV:-}" ]]; then
    echo "  * Review ${INSTALL_DIR}/.env, then: systemctl restart proxy-scanner.service"
    echo "    API_BIND_ADDR defaults to 127.0.0.1, so the API is loopback-only for now."
fi
echo "  * masscan will auto-detect its interface; the default route is via '${DEFAULT_IF:-unknown}'."
echo "    Set SCAN_ADAPTER in .env only if that is wrong."
echo "  * Recommended before the first real sweep: stop the kernel from answering"
echo "    masscan's source ports, so it does not RST the hosts you are probing."
echo "    Reserve the range FIRST or you will break outbound connections on this"
echo "    host — the default ephemeral range (32768-60999) overlaps it:"
echo "      sysctl -w net.ipv4.ip_local_reserved_ports=40000-56383"
echo "      nft add table inet masscan"
echo "      nft add chain inet masscan input '{ type filter hook input priority -10; policy accept; }'"
echo "      nft add rule inet masscan input ct state established,related accept"
echo "      nft add rule inet masscan input tcp dport 40000-56383 counter drop"
echo "    Remove with: nft delete table inet masscan"
echo "    See deploy/README.md for the persistent version and the reasoning."
echo "  * Start a scan session now:  systemctl start proxy-scanner-scan.service"
echo "  * Follow it:                 journalctl -fu proxy-scanner-scan.service"
