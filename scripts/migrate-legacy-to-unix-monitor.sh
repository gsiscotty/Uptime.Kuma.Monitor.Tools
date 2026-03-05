#!/bin/bash
#
# Migrate from deprecated mount-monitor or unix-storage-monitor to unix-monitor.
# Preserves user data (monitors, Kuma URLs), cleans up old addon.
#
# Usage: bash migrate-legacy-to-unix-monitor.sh mount-monitor|unix-storage-monitor
# Called by deprecated addon install scripts.
#

set -euo pipefail

REPO="gsiscotty/Uptime.Kuma.Monitor.Tools"
BRANCH="main"
UNIX_MONITOR_INSTALL_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/addons/unix-monitor/install.sh"

SOURCE="${1:-}"
if [ -z "${SOURCE}" ]; then
    echo "Usage: $0 mount-monitor|unix-storage-monitor"
    exit 1
fi
if [ "${SOURCE}" != "mount-monitor" ] && [ "${SOURCE}" != "unix-storage-monitor" ]; then
    echo "Unknown source: ${SOURCE}"
    exit 1
fi

# Config paths (same logic as the addons)
find_old_config() {
    if [ "${SOURCE}" = "mount-monitor" ]; then
        for p in "/opt/mount-monitor/mount-monitor.json" \
                 "${HOME}/.config/mount-monitor.json"; do
            [ -f "${p}" ] && echo "${p}" && return
        done
    else
        for p in "/opt/unix-storage-monitor/unix-storage-monitor.json" \
                 "${HOME}/.config/unix-storage-monitor.json"; do
            [ -f "${p}" ] && echo "${p}" && return
        done
    fi
    return 1
}

OLD_CONFIG=""
OLD_CONFIG=$(find_old_config) || true
if [ -z "${OLD_CONFIG}" ] || [ ! -f "${OLD_CONFIG}" ]; then
    echo "No existing ${SOURCE} config found. Nothing to migrate."
    echo "Install unix-monitor directly:"
    echo "  curl -sL ${UNIX_MONITOR_INSTALL_URL} | sudo bash"
    exit 0
fi

echo "Found ${SOURCE} config at ${OLD_CONFIG}"
echo "Converting monitors to unix-monitor format..."

MIGRATE_FILE=$(mktemp)
trap 'rm -f "${MIGRATE_FILE}"' EXIT

python3 - "${OLD_CONFIG}" "${SOURCE}" "${MIGRATE_FILE}" <<'PY'
import json
import sys
from pathlib import Path

old_path = Path(sys.argv[1])
source = sys.argv[2]
out_path = Path(sys.argv[3])

cfg = json.loads(old_path.read_text(encoding="utf-8"))
old_monitors = cfg.get("monitors", [])
cron_enabled = bool(cfg.get("cron_enabled", False))
cron_interval = int(cfg.get("cron_interval_minutes", 5) or 5)
cron_interval = max(1, min(1440, cron_interval))

new_monitors = []
for m in old_monitors:
    name = str(m.get("name", "") or "migrated").strip() or "migrated"
    kuma_url = str(m.get("kuma_url", "") or "").strip()
    if not kuma_url:
        continue

    if source == "mount-monitor":
        mounts_data = m.get("mounts", [])
        if not mounts_data:
            continue
        new_monitors.append({
            "name": name,
            "check_mode": "mount",
            "kuma_url": kuma_url,
            "mounts": [
                {"device": x.get("device", "?"), "mount_point": x.get("mount_point", ""), "fstype": x.get("fstype", "?")}
                for x in mounts_data
            ],
            "devices": [],
            "interval": cron_interval,
            "cron_enabled": cron_enabled,
        })
    else:
        mode = str(m.get("check_mode", "both")).lower()
        devices = [str(x) for x in m.get("devices", [])]
        if mode == "both":
            mode = "storage"
        if mode in ("smart", "storage"):
            new_monitors.append({
                "name": name,
                "check_mode": mode,
                "kuma_url": kuma_url,
                "devices": devices if mode == "smart" else [],
                "mounts": [],
                "interval": cron_interval,
                "cron_enabled": cron_enabled,
            })

out_path.write_text(json.dumps({"monitors": new_monitors, "cron_interval_minutes": cron_interval, "cron_enabled": cron_enabled}), encoding="utf-8")
print(f"Converted {len(old_monitors)} monitor(s) -> {len(new_monitors)} unix-monitor monitor(s)")
PY

if [ ! -s "${MIGRATE_FILE}" ]; then
    echo "No monitors to migrate."
    exit 0
fi

# Remove old cron entries before installing unix-monitor
if [ "${SOURCE}" = "mount-monitor" ]; then
    CRON_MARKER="# mount-monitor.py - do not edit this line manually"
elif [ "${SOURCE}" = "unix-storage-monitor" ]; then
    CRON_MARKER="# unix-storage-monitor.py - do not edit this line manually"
fi
if command -v crontab >/dev/null 2>&1; then
    (crontab -l 2>/dev/null | grep -v "${CRON_MARKER}" || true) | crontab - 2>/dev/null || true
    echo "Removed old cron entries."
fi

echo ""
echo "Downloading and running unix-monitor installer..."
echo "Your monitors will be migrated automatically."
echo ""

if command -v curl >/dev/null 2>&1; then
    sudo MIGRATE_MONITORS="${MIGRATE_FILE}" MIGRATE_FROM_LEGACY="${SOURCE}" \
        bash -c "curl -fsSL '${UNIX_MONITOR_INSTALL_URL}' | bash"
elif command -v wget >/dev/null 2>&1; then
    sudo MIGRATE_MONITORS="${MIGRATE_FILE}" MIGRATE_FROM_LEGACY="${SOURCE}" \
        bash -c "wget -qO- '${UNIX_MONITOR_INSTALL_URL}' | bash"
else
    echo "curl or wget required."
    exit 1
fi

# Clean up old install directories (optional - leave a note)
for old_dir in "/opt/mount-monitor" "/opt/unix-storage-monitor"; do
    if [ -d "${old_dir}" ] && [ -w "$(dirname "${old_dir}")" ]; then
        if [ "${SOURCE}" = "mount-monitor" ] && [ "${old_dir}" = "/opt/mount-monitor" ]; then
            echo "Migrated to unix-monitor. Remove old dir: sudo rm -rf ${old_dir}" || true
        elif [ "${SOURCE}" = "unix-storage-monitor" ] && [ "${old_dir}" = "/opt/unix-storage-monitor" ]; then
            echo "Migrated to unix-monitor. Remove old dir: sudo rm -rf ${old_dir}" || true
        fi
    fi
done

echo ""
echo "Migration complete. Your monitors are now in unix-monitor."
echo "Open http://<host>:8787 to manage them."
