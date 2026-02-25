#!/bin/bash

set -euo pipefail

REPO="gsiscotty/Uptime.Kuma.Monitor.Tools"
BRANCH="main"
SCRIPT_NAME="unix-monitor.py"
SCRIPT_REMOTE_PATH="addons/unix-monitor/${SCRIPT_NAME}"
SCRIPT_RAW_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/${SCRIPT_REMOTE_PATH}"
UNINSTALL_NAME="uninstall.sh"
UNINSTALL_REMOTE_PATH="addons/unix-monitor/${UNINSTALL_NAME}"
UNINSTALL_RAW_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/${UNINSTALL_REMOTE_PATH}"
DEFAULT_INSTALL_DIR="/opt/unix-monitor"
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=8

SYSTEMD_SERVICE_UI="unix-monitor-ui.service"
SYSTEMD_SERVICE_SCHED="unix-monitor-scheduler.service"
SYSTEMD_TIMER_SCHED="unix-monitor-scheduler.timer"
SYSTEMD_SERVICE_SMART_HELPER="unix-monitor-smart-helper.service"
SYSTEMD_TIMER_SMART_HELPER="unix-monitor-smart-helper.timer"
SYSTEMD_SERVICE_BACKUP_HELPER="unix-monitor-backup-helper.service"
SYSTEMD_TIMER_BACKUP_HELPER="unix-monitor-backup-helper.timer"
SYSTEMD_SERVICE_SYSLOG_HELPER="unix-monitor-system-log-helper.service"
SYSTEMD_TIMER_SYSLOG_HELPER="unix-monitor-system-log-helper.timer"

read_input() {
    read -r "$@" </dev/tty
}

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

SYSTEM_LABEL="$(uname -s 2>/dev/null || echo Unix)"
APP_LABEL="${SYSTEM_LABEL} Kuma Monitor Addon"

install_python() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "${ID:-}${ID_LIKE:-}" in
            *debian*|*ubuntu*) sudo apt-get update -qq && sudo apt-get install -y -qq python3 ;;
            *) return 1 ;;
        esac
    else
        return 1
    fi
}

apt_pkg_installed() {
    local pkg="$1"
    dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q "install ok installed"
}

apt_pkg_version() {
    local pkg="$1"
    dpkg-query -W -f='${Version}' "${pkg}" 2>/dev/null || echo "unknown"
}

install_apt_packages() {
    local failed=0
    local pkg
    for pkg in "$@"; do
        if apt_pkg_installed "${pkg}"; then
            info "${pkg}: already installed ($(apt_pkg_version "${pkg}"))"
            continue
        fi
        warn "${pkg}: installing..."
        if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkg}" >/dev/null; then
            info "${pkg}: installed ($(apt_pkg_version "${pkg}"))"
        else
            err "${pkg}: install failed"
            failed=1
        fi
    done
    return "${failed}"
}

install_smartmontools() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "${ID:-}${ID_LIKE:-}" in
            *debian*|*ubuntu*)
                info "Refreshing apt package index..."
                sudo apt-get update -qq || true
                install_apt_packages smartmontools
                ;;
            *) return 1 ;;
        esac
    else
        return 1
    fi
}

install_python_deps() {
    if ! command -v python3 >/dev/null 2>&1; then
        return 1
    fi

    deps_ok() {
        python3 - <<'PY' >/dev/null 2>&1
import importlib.util, sys
mods = ["pyotp", "qrcode", "werkzeug", "cryptography", "PIL"]
missing = [m for m in mods if importlib.util.find_spec(m) is None]
sys.exit(0 if not missing else 1)
PY
    }

    if deps_ok; then
        return 0
    fi

    # 1) Prefer distro packages on Debian/Ubuntu
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "${ID:-}${ID_LIKE:-}" in
            *debian*|*ubuntu*)
                info "Refreshing apt package index for Python dependencies..."
                sudo apt-get update -qq || true
                local apt_pkgs=(
                    python3-pyotp
                    python3-qrcode
                    python3-pil
                    python3-werkzeug
                    python3-cryptography
                    python3-pip
                )
                install_apt_packages "${apt_pkgs[@]}" || true
                if deps_ok; then
                    info "Python UI/auth dependency check: OK (apt path)"
                    return 0
                fi
                ;;
        esac
    fi

    # 2) Fallback to pip (system-wide), including externally-managed Python setups
    if ! python3 -m pip --version >/dev/null 2>&1; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            case "${ID:-}${ID_LIKE:-}" in
                *debian*|*ubuntu*) sudo apt-get install -y -qq python3-pip >/dev/null 2>&1 || true ;;
            esac
        fi
    fi

    # Try with --break-system-packages first; fallback without for older pip.
    warn "Falling back to pip for missing Python dependencies..."
    sudo python3 -m pip install --upgrade pip --break-system-packages >/dev/null 2>&1 || sudo python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
    sudo python3 -m pip install pyotp qrcode pillow werkzeug cryptography --break-system-packages >/dev/null 2>&1 || sudo python3 -m pip install pyotp qrcode pillow werkzeug cryptography >/dev/null 2>&1 || true

    if deps_ok; then
        info "Python UI/auth dependency check: OK (pip fallback path)"
        return 0
    fi
    return 1
}

cleanup_systemd_units() {
    local units=(
        "${SYSTEMD_SERVICE_UI}"
        "${SYSTEMD_SERVICE_SCHED}"
        "${SYSTEMD_TIMER_SCHED}"
        "${SYSTEMD_SERVICE_SMART_HELPER}"
        "${SYSTEMD_TIMER_SMART_HELPER}"
        "${SYSTEMD_SERVICE_BACKUP_HELPER}"
        "${SYSTEMD_TIMER_BACKUP_HELPER}"
        "${SYSTEMD_SERVICE_SYSLOG_HELPER}"
        "${SYSTEMD_TIMER_SYSLOG_HELPER}"
    )
    local unit
    for unit in "${units[@]}"; do
        sudo systemctl disable --now "${unit}" >/dev/null 2>&1 || true
        sudo rm -f "/etc/systemd/system/${unit}"
    done
    sudo systemctl daemon-reload >/dev/null 2>&1 || true
}

safe_rm_rf() {
    local target="$1"
    if [ -z "${target}" ] || [ "${target}" = "/" ]; then
        err "Refusing to remove unsafe path: '${target}'"
        return 1
    fi
    sudo rm -rf "${target}"
}

json_get() {
    local file="$1"
    local key="$2"
    local default="$3"
    python3 - <<'PY' "${file}" "${key}" "${default}"
import json, sys
path, key, default = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
    val = data.get(key, default)
except Exception:
    val = default
if isinstance(val, bool):
    print("true" if val else "false")
else:
    print(str(val))
PY
}

json_set_number() {
    local file="$1"
    local key="$2"
    local value="$3"
    python3 - <<'PY' "${file}" "${key}" "${value}"
import json, sys
path, key, value = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(path, encoding='utf-8') as f:
    data = json.load(f)
data[key] = value
with open(path, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)
PY
}

normalize_interval() {
    local raw="${1:-}"
    if ! [[ "${raw}" =~ ^[0-9]+$ ]]; then
        echo "1"
        return
    fi
    if [ "${raw}" -lt 1 ]; then
        echo "1"
        return
    fi
    if [ "${raw}" -gt 1440 ]; then
        echo "1440"
        return
    fi
    echo "${raw}"
}

echo ""
echo -e "${BOLD}${APP_LABEL} — Installer${NC}"
echo "mount + unix storage checks + peer master/agent mode"
echo "------------------------------------------------------"
echo ""

if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 not found."
    echo -e "Install python3 now? (y/N): \c"
    read_input INSTALL_PY || true
    if [[ "${INSTALL_PY:-n}" =~ ^[Yy]$ ]]; then
        if ! install_python; then
            err "Automatic python3 install failed."
            exit 1
        fi
    else
        err "python3 is required."
        exit 1
    fi
fi

PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [ "${PY_MAJOR}" -lt ${MIN_PYTHON_MAJOR} ] || { [ "${PY_MAJOR}" -eq ${MIN_PYTHON_MAJOR} ] && [ "${PY_MINOR}" -lt ${MIN_PYTHON_MINOR} ]; }; then
    err "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ required."
    exit 1
fi
info "Python $(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")') found"

if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER="wget"
else
    err "curl or wget required."
    exit 1
fi

echo -e "Install directory [${BOLD}${DEFAULT_INSTALL_DIR}${NC}]: \c"
read_input CUSTOM_DIR || true
INSTALL_DIR="${CUSTOM_DIR:-${DEFAULT_INSTALL_DIR}}"

if [ ! -d "${INSTALL_DIR}" ]; then
    warn "Directory ${INSTALL_DIR} does not exist."
    echo -e "Create it? (y/N): \c"
    read_input CREATE || true
    if [[ "${CREATE:-n}" =~ ^[Yy]$ ]]; then
        if [ -w "$(dirname "${INSTALL_DIR}")" ]; then
            mkdir -p "${INSTALL_DIR}"
        else
            sudo mkdir -p "${INSTALL_DIR}"
            sudo chown "$(id -u):$(id -g)" "${INSTALL_DIR}"
        fi
    else
        err "Aborted."
        exit 1
    fi
fi

if [ ! -w "${INSTALL_DIR}" ]; then
    err "No write permission to ${INSTALL_DIR}"
    exit 1
fi

REINSTALL_MODE="fresh"
EXISTING_INSTALL=0
if [ -f "${INSTALL_DIR}/${SCRIPT_NAME}" ] || [ -f "${INSTALL_DIR}/unix-monitor.json" ] || [ -d "/var/lib/unix-monitor" ]; then
    EXISTING_INSTALL=1
fi

if [ "${EXISTING_INSTALL}" -eq 1 ]; then
    echo ""
    warn "Existing unix-monitor installation detected."
    echo "  1) Reinstall and update, keep user data (recommended)"
    echo "  2) Full reinstall, keep nothing (delete config/state)"
    echo "  3) Cancel"
    echo -e "Choose reinstall mode [1]: \c"
    read_input REINSTALL_CHOICE || true
    REINSTALL_CHOICE="${REINSTALL_CHOICE:-1}"

    case "${REINSTALL_CHOICE}" in
        1)
            REINSTALL_MODE="preserve"
            info "Reinstall mode: keep user data + update binaries/services."
            ;;
        2)
            REINSTALL_MODE="fresh"
            warn "Reinstall mode: full reinstall, user data will be removed."
            ;;
        *)
            err "Cancelled by user."
            exit 1
            ;;
    esac

    info "Stopping/removing existing unix-monitor systemd units..."
    cleanup_systemd_units

    if [ "${REINSTALL_MODE}" = "fresh" ]; then
        warn "Removing existing install directory and runtime state..."
        safe_rm_rf "${INSTALL_DIR}" || exit 1
        safe_rm_rf "/var/lib/unix-monitor" || exit 1
        if [ -n "${SUDO_USER:-}" ]; then
            USER_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6 || true)"
            if [ -n "${USER_HOME}" ] && [ -d "${USER_HOME}" ]; then
                safe_rm_rf "${USER_HOME}/.config/unix-monitor" || true
            fi
        fi
        mkdir -p "${INSTALL_DIR}"
    fi
fi

TARGET="${INSTALL_DIR}/${SCRIPT_NAME}"
UNINSTALL_TARGET="${INSTALL_DIR}/${UNINSTALL_NAME}"

info "Downloading ${SCRIPT_NAME}..."
if [ "${DOWNLOADER}" = "curl" ]; then
    curl -fsSL "${SCRIPT_RAW_URL}" -o "${TARGET}"
else
    wget -qO "${TARGET}" "${SCRIPT_RAW_URL}"
fi

info "Downloading ${UNINSTALL_NAME}..."
if [ "${DOWNLOADER}" = "curl" ]; then
    curl -fsSL "${UNINSTALL_RAW_URL}" -o "${UNINSTALL_TARGET}"
else
    wget -qO "${UNINSTALL_TARGET}" "${UNINSTALL_RAW_URL}"
fi

if [ ! -s "${TARGET}" ] || [ ! -s "${UNINSTALL_TARGET}" ]; then
    err "Download failed."
    exit 1
fi
FIRST_LINE="$(sed -n '1p' "${TARGET}")"
if [[ "${FIRST_LINE}" != "#!/usr/bin/env python3"* ]]; then
    err "Downloaded launcher is not the expected script."
    rm -f "${TARGET}" "${UNINSTALL_TARGET}"
    exit 1
fi
UNINSTALL_FIRST_LINE="$(sed -n '1p' "${UNINSTALL_TARGET}")"
if [[ "${UNINSTALL_FIRST_LINE}" != "#!/bin/bash"* ]]; then
    err "Downloaded uninstaller is not the expected script."
    rm -f "${TARGET}" "${UNINSTALL_TARGET}"
    exit 1
fi
chmod 700 "${TARGET}" "${UNINSTALL_TARGET}"
info "Installed to ${INSTALL_DIR}"

echo -e "Install smartctl dependency (smartmontools)? (Y/n): \c"
read_input INSTALL_SMART || true
if [[ ! "${INSTALL_SMART:-Y}" =~ ^[Nn]$ ]]; then
    if install_smartmontools; then
        info "smartmontools installed."
    else
        warn "Could not auto-install smartmontools. Install manually for SMART checks."
    fi
fi

echo -e "Install Python UI/auth dependencies (pyotp, qrcode, pillow, werkzeug, cryptography)? (Y/n): \c"
read_input INSTALL_PY_DEPS || true
if [[ ! "${INSTALL_PY_DEPS:-Y}" =~ ^[Nn]$ ]]; then
    if install_python_deps; then
        info "Python dependencies installed."
    else
        warn "Could not install all Python dependencies automatically (apt + pip fallback attempted)."
        warn "Manual fallback:"
        warn "  sudo apt install python3-pyotp python3-qrcode python3-pil python3-werkzeug python3-cryptography"
        warn "  or: sudo python3 -m pip install pyotp qrcode pillow werkzeug cryptography --break-system-packages"
    fi
fi

echo ""
echo -e "${BOLD}Setup choice:${NC}"
CONFIG_PATH="${INSTALL_DIR}/unix-monitor.json"
WEB_ENABLED="true"
PEER_ROLE="standalone"
MASTER_URL=""
PEER_TOKEN=""
SCHED_BACKEND="systemd"
SCHED_INTERVAL_MIN="1"
UPDATE_INTERVAL_ONLY=0

if [ "${REINSTALL_MODE}" = "preserve" ] && [ -f "${CONFIG_PATH}" ]; then
    info "Preserving existing unix-monitor user data and configuration."
    WEB_ENABLED="$(json_get "${CONFIG_PATH}" "web_enabled" "true")"
    PEER_ROLE="$(json_get "${CONFIG_PATH}" "peer_role" "standalone")"
    MASTER_URL="$(json_get "${CONFIG_PATH}" "peer_master_url" "")"
    PEER_TOKEN="$(json_get "${CONFIG_PATH}" "peering_token" "")"
    SCHED_BACKEND="$(json_get "${CONFIG_PATH}" "scheduler_backend" "systemd")"
    SCHED_INTERVAL_MIN="$(normalize_interval "$(json_get "${CONFIG_PATH}" "cron_interval_minutes" "5")")"
    if [ "${SCHED_BACKEND}" != "cron" ]; then
        SCHED_BACKEND="systemd"
    fi
    echo -e "Scheduler interval in minutes [${SCHED_INTERVAL_MIN}]: \c"
    read_input KEEP_INTERVAL || true
    if [ -n "${KEEP_INTERVAL:-}" ]; then
        SCHED_INTERVAL_MIN="$(normalize_interval "${KEEP_INTERVAL}")"
        UPDATE_INTERVAL_ONLY=1
    fi
else
    echo "  1) Webserver mode (UI + local management, master/agent capable)"
    echo "  2) No webserver mode (agent-only menu; master connection required)"
    echo -e "Choose mode [1]: \c"
    read_input MODE_CHOICE || true
    MODE_CHOICE="${MODE_CHOICE:-1}"

    if [ "${MODE_CHOICE}" = "2" ]; then
        WEB_ENABLED="false"
        PEER_ROLE="agent"
        echo ""
        warn "NO-WEBSERVER MODE SELECTED"
        warn "Functionality is reduced to menu-based monitor creation in agent mode only."
        warn "A master connection is required. Local UI is disabled."
        echo -e "Master URL (e.g. http://master-host:8787): \c"
        read_input MASTER_URL || true
        echo -e "Shared peering token: \c"
        read_input PEER_TOKEN || true
        if [ -z "${MASTER_URL}" ] || [ -z "${PEER_TOKEN}" ]; then
            err "Master URL and peering token are required in no-webserver mode."
            exit 1
        fi
    fi

    echo ""
    echo "Scheduler backend:"
    echo "  1) systemd (recommended)"
    echo "  2) cron fallback"
    echo -e "Choose scheduler [1]: \c"
    read_input SCHED_CHOICE || true
    SCHED_CHOICE="${SCHED_CHOICE:-1}"
    if [ "${SCHED_CHOICE}" = "2" ]; then
        SCHED_BACKEND="cron"
        SCHED_INTERVAL_MIN="5"
    else
        SCHED_BACKEND="systemd"
        SCHED_INTERVAL_MIN="1"
    fi
    echo -e "Scheduler interval in minutes [${SCHED_INTERVAL_MIN}]: \c"
    read_input SCHED_INTERVAL_INPUT || true
    if [ -n "${SCHED_INTERVAL_INPUT:-}" ]; then
        SCHED_INTERVAL_MIN="$(normalize_interval "${SCHED_INTERVAL_INPUT}")"
    fi

    cat > "${CONFIG_PATH}" <<EOF
{
  "instance_name": "$(hostname)",
  "monitors": [],
  "debug": false,
  "cron_enabled": false,
  "cron_interval_minutes": ${SCHED_INTERVAL_MIN},
  "peer_role": "${PEER_ROLE}",
  "peer_master_url": "${MASTER_URL}",
  "peering_token": "${PEER_TOKEN}",
  "peer_port": 8787,
  "web_enabled": ${WEB_ENABLED},
  "ui_host": "0.0.0.0",
  "ui_port": 8787,
  "scheduler_backend": "${SCHED_BACKEND}",
  "agent_only_notice_ack": true
}
EOF
    chmod 600 "${CONFIG_PATH}"
    info "Created config: ${CONFIG_PATH}"
fi

if [ "${UPDATE_INTERVAL_ONLY}" -eq 1 ] && [ -f "${CONFIG_PATH}" ]; then
    json_set_number "${CONFIG_PATH}" "cron_interval_minutes" "${SCHED_INTERVAL_MIN}"
    info "Updated preserved scheduler interval: ${SCHED_INTERVAL_MIN} minute(s)"
fi

if [ "${SCHED_BACKEND}" = "systemd" ] && command -v systemctl >/dev/null 2>&1; then
    info "Installing systemd units (requires sudo)..."
    UI_UNIT_PATH="/etc/systemd/system/${SYSTEMD_SERVICE_UI}"
    SCHED_UNIT_PATH="/etc/systemd/system/${SYSTEMD_SERVICE_SCHED}"
    TIMER_PATH="/etc/systemd/system/${SYSTEMD_TIMER_SCHED}"
    SMART_HELPER_SERVICE_PATH="/etc/systemd/system/${SYSTEMD_SERVICE_SMART_HELPER}"
    SMART_HELPER_TIMER_PATH="/etc/systemd/system/${SYSTEMD_TIMER_SMART_HELPER}"
    BACKUP_HELPER_SERVICE_PATH="/etc/systemd/system/${SYSTEMD_SERVICE_BACKUP_HELPER}"
    BACKUP_HELPER_TIMER_PATH="/etc/systemd/system/${SYSTEMD_TIMER_BACKUP_HELPER}"
    SYSLOG_HELPER_SERVICE_PATH="/etc/systemd/system/${SYSTEMD_SERVICE_SYSLOG_HELPER}"
    SYSLOG_HELPER_TIMER_PATH="/etc/systemd/system/${SYSTEMD_TIMER_SYSLOG_HELPER}"

    if [ "${WEB_ENABLED}" = "true" ]; then
        sudo tee "${UI_UNIT_PATH}" >/dev/null <<EOF
[Unit]
Description=${APP_LABEL} UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=$(command -v python3) ${TARGET} --ui --host 0.0.0.0 --port 8787
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    fi

    sudo tee "${SCHED_UNIT_PATH}" >/dev/null <<EOF
[Unit]
Description=${APP_LABEL} Scheduled Check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${INSTALL_DIR}
ExecStart=$(command -v python3) ${TARGET} --run-scheduled
EOF

    sudo tee "${SMART_HELPER_SERVICE_PATH}" >/dev/null <<EOF
[Unit]
Description=${APP_LABEL} SMART Helper Cache Refresh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${INSTALL_DIR}
ExecStart=$(command -v python3) ${TARGET} --run-smart-helper
EOF

    sudo tee "${SMART_HELPER_TIMER_PATH}" >/dev/null <<EOF
[Unit]
Description=Run ${APP_LABEL} SMART helper every 5 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo tee "${BACKUP_HELPER_SERVICE_PATH}" >/dev/null <<EOF
[Unit]
Description=${APP_LABEL} Backup Helper Cache Refresh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${INSTALL_DIR}
ExecStart=$(command -v python3) ${TARGET} --run-backup-helper
EOF

    sudo tee "${BACKUP_HELPER_TIMER_PATH}" >/dev/null <<EOF
[Unit]
Description=Run ${APP_LABEL} backup helper every 5 minutes

[Timer]
OnBootSec=4min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo tee "${SYSLOG_HELPER_SERVICE_PATH}" >/dev/null <<EOF
[Unit]
Description=${APP_LABEL} System Log Helper Cache Refresh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${INSTALL_DIR}
ExecStart=$(command -v python3) ${TARGET} --run-system-log-helper
EOF

    sudo tee "${SYSLOG_HELPER_TIMER_PATH}" >/dev/null <<EOF
[Unit]
Description=Run ${APP_LABEL} system-log helper every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo tee "${TIMER_PATH}" >/dev/null <<EOF
[Unit]
Description=Run ${APP_LABEL} checks every ${SCHED_INTERVAL_MIN} minute(s)

[Timer]
OnBootSec=2min
OnUnitActiveSec=${SCHED_INTERVAL_MIN}min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo systemctl daemon-reload
    if [ "${WEB_ENABLED}" = "true" ]; then
        sudo systemctl enable --now "${SYSTEMD_SERVICE_UI}"
    fi
    sudo systemctl enable --now "${SYSTEMD_TIMER_SCHED}"
    sudo systemctl enable --now "${SYSTEMD_TIMER_SMART_HELPER}"
    sudo systemctl enable --now "${SYSTEMD_TIMER_BACKUP_HELPER}"
    sudo systemctl enable --now "${SYSTEMD_TIMER_SYSLOG_HELPER}"
    info "systemd services enabled."
elif [ "${SCHED_BACKEND}" = "cron" ]; then
    info "Config set to cron fallback. Enable cron schedule from script menu."
fi

echo ""
echo "------------------------------------------------------"
echo -e "${GREEN}${BOLD}Installation complete.${NC}"
echo ""
if [ "${WEB_ENABLED}" = "true" ]; then
    echo "Webserver mode:"
    echo "  - UI command: cd ${INSTALL_DIR} && python3 ${SCRIPT_NAME} --ui --host 0.0.0.0 --port 8787"
    echo "  - Open: http://<unix-host>:8787"
    echo "  - Peering role can be changed in UI or config."
else
    echo "No-webserver mode:"
    echo "  - Agent-only functionality is active."
    echo "  - Local monitor setup is menu-based only."
    echo "  - A master connection is mandatory."
    echo "  - Start menu: cd ${INSTALL_DIR} && python3 ${SCRIPT_NAME} --agent-menu"
fi
echo ""
echo "Scheduler backend: ${SCHED_BACKEND}"
echo "Scheduler interval: ${SCHED_INTERVAL_MIN} minute(s)"
echo "Manual one-shot check: python3 ${TARGET} --run-scheduled"
echo "Uninstall later: sudo ${UNINSTALL_TARGET}"
echo "------------------------------------------------------"
