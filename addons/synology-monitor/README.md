# EasySystems GmbH - Kuma Monitor Addon

Monitors Synology NAS health and reports to Uptime Kuma.

This addon provides:
- disk SMART health (`smartctl`)
- NVMe SMART critical warnings (`nvme smart-log`)
- storage pool/volume/RAID status (`synospace --enum`)
- guided elevated-access setup in the UI
- diagnostics views for technicians
- per-monitor actions and status feedback

**Author:** Konrad von Burg  
**Version:** 1.0.0  
**Platform:** Synology DSM (Linux)  
**Python:** 3.8+
**Website:** https://www.easysystems.ch/de  
**Copyright:** Copyright (c) 2026 EasySystems GmbH. All rights reserved.

---

## Quick Install

```bash
curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/synology-monitor/install.sh | bash
```

Or:

```bash
wget -qO- https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/synology-monitor/install.sh | bash
```

---

## What it checks

### SMART check
- Synology-style disk detection:
  - `/dev/sata*` first
  - fallback `/dev/sd[a-z]`
  - also `/dev/sg*`
- Runs `smartctl -H` per selected/auto device
- Detects missing `/dev/sdX` and `/dev/sgN` sequence gaps (legacy Synology behavior)
- Optional NVMe check via `nvme smart-log` (`critical_warning`)
- Requires root permissions

### Storage check
- Runs `synospace --enum`
- Warning when pools/volumes are repairing or parity checking
- Warning for RAID rebuild in progress (includes reported progress)
- Down when RAID status is degraded

### Combined mode
- Runs both SMART and storage checks
- Final status = worst severity (`up` < `warning` < `down`)

---

## Menu

```
1) Add monitor (SMART / Storage / Both)
2) Run check (all configured monitors)
3) List configured monitors
4) Remove monitor
5) Schedule automatic checks (cron)
6) Test push (send test message to Kuma)
7) Toggle debug mode
8) Exit
```

Back navigation and explicit save/apply behavior matches the other addons.

---

## Setup

1. Create a **Push** monitor in Uptime Kuma and copy:
   `https://kuma.example.com/api/push/<token>`
2. Start setup UI:
   ```bash
   python3 synology-monitor.py --ui --host 0.0.0.0 --port 8787
   ```
3. Open `http://<synology-ip>:8787`.
4. Select mode (`smart`, `storage`, or `both`), save, then run connection test.
5. Optional: set cron interval to any value you need in the UI.

---

## CLI

```bash
python3 synology-monitor.py
python3 synology-monitor.py --run
python3 synology-monitor.py --run -d
```

## Basic Setup UI

Run a tiny local web UI for first-time setup:

```bash
sudo python3 synology-monitor.py --ui --host 0.0.0.0 --port 8787
```

Then open:

```text
http://<synology-ip>:8787
```

The UI supports:
- auto-define monitor name from selected mode
- set monitor mode and Kuma push URL
- enable/disable cron and set interval
- replace all monitors with one baseline monitor
- run check now (button)
- connection test (button)
- log panel with refresh/clear for troubleshooting
- detected NAS volumes panel (`/volumeX`) for quick visibility
- SMART elevated-access panel with root task instructions and status check
- beta button to auto-create helper task with status output
- embedded Task Scheduler screenshots in UI to show each setup step
- explicit "run task once" step before pressing "Check elevated access now"
- dark DSM-style dashboard with SMART/storage gauge + history overview
- monitor cards with state badges and per-monitor action buttons
- clickable SMART/storage gauges to filter diagnostics logs
- monitor card actions now include edit and delete
- safer monitor-save default (does not replace all unless explicitly selected)
- config migration support from legacy locations on update
- setup screenshots are embedded per step with steerable hover zoom
- installer preserves existing helper script during updates
- create/edit monitor opens as overlay modal from dashboard buttons
- diagnostics panel now has technician views (logs/task/cache/config/history/paths)
- setup includes update note: run helper task once after update to refresh elevated cache

Use the CLI menu for advanced/multi-monitor setup.

---

## Dependencies

Required:
- `python3` (3.8+)
- `crontab`
- Synology `synospace`

For SMART mode:
- `smartctl` (`smartmontools`)

Optional for NVMe checks:
- `nvme` (`nvme-cli`)

---

## Notes

- Designed for Synology NAS hosts (DSM/Linux).
- Config file is owner-only (`0600`) and written atomically.
- HTTPS push uses certificate verification.
- A basic SPK skeleton is available in `addons/synology-monitor/community-package/`.
- In the SPK skeleton, setup UI is auto-started after package install on port `8787`.
