#!/bin/bash

set -euo pipefail

INSTALL_DIR_DEFAULT="/opt/unix-monitor"
CRON_MARKER="unix-monitor.py - do not edit this line manually"

if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    GREEN='' YELLOW='' RED='' BOLD='' NC=''
fi

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*"; }

echo ""
echo -e "${BOLD}Unix Monitor — Uninstaller${NC}"
echo "-------------------------------------"
echo ""

if [ "${EUID}" -ne 0 ]; then
    err "Please run as root (sudo)."
    exit 1
fi

echo -n "Install directory [${INSTALL_DIR_DEFAULT}]: "
read -r INPUT_DIR || true
INSTALL_DIR="${INPUT_DIR:-$INSTALL_DIR_DEFAULT}"

echo ""
warn "This will remove unix-monitor services, timers, install files, runtime state, and cron entries."
echo -n "Continue? (y/N): "
read -r CONFIRM || true
if [[ ! "${CONFIRM:-n}" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

UNITS=(
  "unix-monitor-ui.service"
  "unix-monitor-scheduler.timer"
  "unix-monitor-scheduler.service"
  "unix-monitor-smart-helper.timer"
  "unix-monitor-smart-helper.service"
  "unix-monitor-backup-helper.timer"
  "unix-monitor-backup-helper.service"
  "unix-monitor-system-log-helper.timer"
  "unix-monitor-system-log-helper.service"
)

for unit in "${UNITS[@]}"; do
    systemctl disable --now "${unit}" >/dev/null 2>&1 || true
done
info "Stopped and disabled systemd units/timers (if present)."

for unit in "${UNITS[@]}"; do
    rm -f "/etc/systemd/system/${unit}"
done
systemctl daemon-reload || true
info "Removed unix-monitor unit files."

if [ -d "${INSTALL_DIR}" ]; then
    rm -rf "${INSTALL_DIR}"
    info "Removed install directory: ${INSTALL_DIR}"
else
    warn "Install directory not found: ${INSTALL_DIR}"
fi

rm -rf "/var/lib/unix-monitor"
info "Removed runtime state: /var/lib/unix-monitor"

if [ -n "${SUDO_USER:-}" ]; then
    USER_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6 || true)"
    if [ -n "${USER_HOME}" ] && [ -d "${USER_HOME}" ]; then
        rm -rf "${USER_HOME}/.config/unix-monitor"
        info "Removed user config: ${USER_HOME}/.config/unix-monitor"
    fi
fi

if crontab -l >/dev/null 2>&1; then
    crontab -l | sed "/${CRON_MARKER//\//\\/}/d" | crontab - || true
    info "Removed cron entries with unix-monitor marker."
fi

echo ""
info "Uninstall complete."
echo "-------------------------------------"
