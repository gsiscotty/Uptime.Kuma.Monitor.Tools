# Mount Monitor

Interactive menu tool to monitor mounted shares and filesystems, and report their status to Uptime Kuma push monitors.

**Author:** gsi_scotty  
**Version:** 1.1.0  
**Platform:** Linux / macOS  
**Dependencies:** Python 3.8+ (stdlib only, no pip install needed)

---

## What it does

- Lists all currently mounted filesystems on the machine (local drives, NFS, SMB/CIFS, APFS, etc.)
- Lets you select which mounts to watch
- Connects each mount to an Uptime Kuma **Push** monitor URL
- Sends a status message with timestamp and mount health on every check
- Reports mount latency (sub-millisecond precision) as the Kuma `ping` value
- Can run automatically on a schedule via cron

---

## Quick Install

```bash
curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/mount-monitor/install.sh | bash
```

Or with `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/mount-monitor/install.sh | bash
```

> The installer checks for Python 3.8+, installs it if missing (on supported systems), downloads `mount-monitor.py` to a directory of your choice, and sets secure file permissions.

### Prefer to inspect first?

```bash
curl -sLO https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/mount-monitor/install.sh
cat install.sh     # review it
bash install.sh    # then run it
```

---

## Setup Guide

### Step 1 — Create a Push monitor in Uptime Kuma

1. Open your Uptime Kuma instance
2. Click **Add New Monitor**
3. Set type to **Push**
4. Set the heartbeat interval to match your planned check frequency
5. Copy the push URL — it looks like:
   `https://kuma.example.com/api/push/YourToken`

### Step 2 — Install the script

```bash
curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/mount-monitor/install.sh | bash
```

Default install path: `/opt/mount-monitor/`

### Step 3 — Add a monitor

```bash
cd /opt/mount-monitor
python3 mount-monitor.py
```

1. Choose **1) List mounts & add monitor**
2. Select the mount(s) you want to watch (e.g. `1` or `1,3`)
3. Paste your Kuma push URL
4. Give it a name, or press Enter to use the mount path
5. Confirm with **s** to save

### Step 4 — Test it

- Choose **6) Test push** — sends a test message to verify Kuma receives it
- Choose **2) Run check** — runs a real check with optional debug output

### Step 5 — Schedule automatic checks

1. Choose **5) Schedule automatic checks (cron)**
2. Choose **a) Enable**
3. Enter your interval (1–120 minutes)
4. Confirm with **s**

The cron job is written automatically. After you exit, the script runs silently in the background at the configured interval. Re-run `python3 mount-monitor.py` any time to change settings.

---

## Menu

```
1) List mounts & add monitor
2) Run check (all configured monitors)
3) List configured monitors
4) Remove monitor
5) Schedule automatic checks (cron)
6) Test push (send test message to Kuma)
7) Toggle debug mode
8) Exit
```

Every menu action has a **go back** option. No changes are saved until you explicitly confirm with **s**.

---

## CLI flags

```bash
python3 mount-monitor.py            # Interactive menu
python3 mount-monitor.py --run      # Non-interactive check (used by cron)
python3 mount-monitor.py --run -d   # Non-interactive check with debug output
```

---

## Config file

Stored at `<install-dir>/mount-monitor.json` (or `~/.config/mount-monitor.json` if the install dir is not writable).  
Permissions are set to `0600` (owner read/write only).

---

## Security

- Config restricted to owner only (`0600`)
- Atomic config writes (temp file + rename, no partial writes)
- Kuma push URLs validated before saving
- TLS certificate verification on HTTPS connections
- Path traversal protection on mount checks
- No secrets in code — Kuma tokens live only in the local config
- No external dependencies (Python stdlib only)
