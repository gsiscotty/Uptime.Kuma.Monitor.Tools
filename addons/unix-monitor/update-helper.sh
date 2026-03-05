#!/bin/bash
# Unix Monitor — Self-update helper
# Backup, download, validate, replace. Restore on failure. Keeps config/state.
set -euo pipefail

INSTALL_DIR="${1:-}"
MODE="${2:-update}"
if [ -z "${INSTALL_DIR}" ] || [ ! -d "${INSTALL_DIR}" ]; then
    echo "Usage: $0 <install-dir> [update|rollback]"
    exit 1
fi

SCRIPT="${INSTALL_DIR}/unix-monitor.py"
BACKUP="${SCRIPT}.prev"

# Rollback: restore from backup
if [ "${MODE}" = "rollback" ]; then
    if [ ! -f "${BACKUP}" ]; then
        echo "ERROR: No backup found at ${BACKUP}"
        exit 1
    fi
    cp -a "${BACKUP}" "${SCRIPT}"
    chmod 700 "${SCRIPT}"
    echo "Restored from backup"
    for unit in unix-monitor-ui.service unix-monitor-scheduler.timer unix-monitor-smart-helper.timer unix-monitor-backup-helper.timer unix-monitor-system-log-helper.timer; do
        command -v systemctl >/dev/null 2>&1 && systemctl restart "${unit}" 2>/dev/null || true
    done
    echo "Rollback complete."
    exit 0
fi

REPO="gsiscotty/Uptime.Kuma.Monitor.Tools"
SCRIPT_NAME="unix-monitor.py"
INFO_REMOTE_PATH="addons/synology-monitor/community-package/package/INFO"

# Resolve download ref: use latest release tag so updates match what the UI checks against.
# Set UNIX_MONITOR_USE_MAIN=1 to force main branch (e.g. for testing unreleased changes).
REF="main"
if [ "${UNIX_MONITOR_USE_MAIN:-0}" != "1" ] && command -v curl >/dev/null 2>&1; then
    TAG=$(curl -sfL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep -o '"tag_name":[[:space:]]*"[^"]*"' | sed 's/"tag_name":[[:space:]]*"\([^"]*\)"/\1/')
    if [ -n "${TAG}" ]; then
        REF="${TAG}"
    fi
fi

URL="https://raw.githubusercontent.com/${REPO}/${REF}/addons/unix-monitor/${SCRIPT_NAME}"
NEW="${SCRIPT}.new"

fetch_public_version_for_ref() {
    local ref="$1"
    local url="https://raw.githubusercontent.com/${REPO}/${ref}/${INFO_REMOTE_PATH}"
    local content=""
    if command -v curl >/dev/null 2>&1; then
        content="$(curl -fsSL "${url}" 2>/dev/null || true)"
    elif command -v wget >/dev/null 2>&1; then
        content="$(wget -qO- "${url}" 2>/dev/null || true)"
    fi
    printf '%s\n' "${content}" | sed -n 's/^version="\([^"]*\)".*/\1/p' | head -n 1
}

detect_local_version() {
    sed -n 's/^VERSION = "\([^"]*\)".*/\1/p' "${SCRIPT}" | head -n 1
}

version_cmp() {
    local a="${1:-0}"
    local b="${2:-0}"
    python3 - "${a}" "${b}" <<'PY'
import re, sys
def to_parts(v):
    nums = [int(x) for x in re.findall(r"\d+", v or "")]
    return nums or [0]
a = to_parts(sys.argv[1])
b = to_parts(sys.argv[2])
n = max(len(a), len(b))
a += [0] * (n - len(a))
b += [0] * (n - len(b))
print(-1 if a < b else (1 if a > b else 0))
PY
}

CHANNEL="latest"
if [ "${REF}" = "main" ]; then
    CHANNEL="main"
fi
LOCAL_VERSION="$(detect_local_version || true)"
PUBLIC_VERSION="$(fetch_public_version_for_ref "${REF}" || true)"
echo "Update source: ${CHANNEL} (${REF})"
echo "Local version: ${LOCAL_VERSION:-unknown}"
echo "Public (${CHANNEL}) version: ${PUBLIC_VERSION:-unknown}"
if [ -n "${LOCAL_VERSION}" ] && [ -n "${PUBLIC_VERSION}" ]; then
    CMP_RESULT="$(version_cmp "${LOCAL_VERSION}" "${PUBLIC_VERSION}")"
    if [ "${CMP_RESULT}" -ge 0 ] && [ "${UNIX_MONITOR_FORCE_UPDATE:-0}" != "1" ]; then
        echo "No update needed (local is up to date). Set UNIX_MONITOR_FORCE_UPDATE=1 to force."
        exit 0
    fi
fi
if [ -t 0 ] && [ "${UNIX_MONITOR_ASSUME_YES:-0}" != "1" ]; then
    printf "Proceed with update from %s? (y/N): " "${CHANNEL}"
    read -r CONFIRM
    if [[ ! "${CONFIRM:-N}" =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        exit 0
    fi
fi

# 1) Backup current
if [ ! -f "${SCRIPT}" ]; then
    echo "ERROR: No script at ${SCRIPT}"
    exit 1
fi
cp -a "${SCRIPT}" "${BACKUP}"
echo "Backed up to ${BACKUP}"

# 2) Download (fall back to main if release tag lacks unix-monitor addon)
do_download() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${URL}" -o "${NEW}"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "${NEW}" "${URL}"
    else
        echo "ERROR: curl or wget required"
        rm -f "${NEW}"
        exit 1
    fi
}

if ! do_download; then
    if [ "${REF}" != "main" ]; then
        echo "Release ${REF} missing unix-monitor addon, falling back to main branch."
        REF="main"
        URL="https://raw.githubusercontent.com/${REPO}/${REF}/addons/unix-monitor/${SCRIPT_NAME}"
        do_download
    else
        echo "ERROR: Download failed"
        rm -f "${NEW}"
        exit 1
    fi
fi

if [ ! -s "${NEW}" ]; then
    echo "ERROR: Download failed (empty file)"
    rm -f "${NEW}"
    exit 1
fi

# 3) Validate (syntax check)
if ! python3 -m py_compile "${NEW}" 2>/dev/null; then
    echo "ERROR: Downloaded script failed validation (syntax error)"
    rm -f "${NEW}"
    exit 1
fi

# 4) Replace
if ! mv -f "${NEW}" "${SCRIPT}"; then
    echo "ERROR: Replace failed, backup intact at ${BACKUP}"
    rm -f "${NEW}"
    exit 1
fi

chmod 700 "${SCRIPT}"
echo "Updated ${SCRIPT}"

# 5) Restart services (unless --no-restart for UI-triggered update)
if [ "${3:-}" != "no-restart" ]; then
    for unit in unix-monitor-ui.service unix-monitor-scheduler.timer unix-monitor-smart-helper.timer unix-monitor-backup-helper.timer unix-monitor-system-log-helper.timer; do
        if command -v systemctl >/dev/null 2>&1; then
            systemctl restart "${unit}" 2>/dev/null || true
        fi
    done
fi

echo "Update complete. Config and data preserved."
