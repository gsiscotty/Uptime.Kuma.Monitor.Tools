# Unix Monitor

Combined Unix addon for Uptime Kuma that merges:
- mount/share availability checks (`mount-monitor`)
- UNIX SMART + storage/RAID checks (`unix-storage-monitor`)
- Synology-style master/agent peer APIs for remote monitor workflows

The runtime app name is generated from system info:
- `<RunningSystem> Kuma Monitor Addon`
- examples: `Linux Kuma Monitor Addon`, `Darwin Kuma Monitor Addon`

---

## Quick Install

```bash
curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/unix-monitor/install.sh | bash
```

---

## Setup Modes

### 1) Webserver mode
- Runs local UI on port `8787`
- Supports local management and role switching (`standalone`, `master`, `agent`)
- Supports scheduler via systemd by default, cron fallback

### 2) No-webserver mode (agent-only)
- Installer explicitly sets:
  - `web_enabled=false`
  - `peer_role=agent`
  - required `peer_master_url`
  - required `peering_token`
- Local UI is disabled
- Monitor creation and maintenance are menu-based only
- A connection to a master is required

---

## Commands

```bash
python3 unix-monitor.py
python3 unix-monitor.py --agent-menu
python3 unix-monitor.py --ui --host 0.0.0.0 --port 8787
python3 unix-monitor.py --run-scheduled
python3 unix-monitor.py --run-scheduled-loop
```
