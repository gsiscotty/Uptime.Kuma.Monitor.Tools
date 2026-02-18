# Unix Storage Monitor

Interactive menu tool for Ubuntu/Unix systems to monitor:
- disk SMART health (`smartctl`)
- storage usage (`df`)
- software RAID state (`/proc/mdstat`)

Then push status to Uptime Kuma Push monitors.

**Author:** gsi_scotty  
**Version:** 1.0.0  
**Platform:** Linux/Unix (Ubuntu focused)  
**Python:** 3.8+

---

## Quick Install

```bash
curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/unix-storage-monitor/install.sh | bash
```

Or:

```bash
wget -qO- https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/unix-storage-monitor/install.sh | bash
```

---

## What it checks

### SMART check
- Runs `smartctl -H` on selected block devices
- Reports `PASSED` vs `FAILED`
- Requires root permissions

### Storage check
- Detects high filesystem usage:
  - warning at `>=90%`
  - down at `>=98%`
- Detects mdraid degraded arrays from `/proc/mdstat`
- Detects mdraid rebuild/recovery as warning

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

Back navigation and explicit save/apply behavior matches `mount-monitor`.

---

## Setup

1. Create a **Push** monitor in Uptime Kuma and copy the push URL:
   `https://kuma.example.com/api/push/<token>`
2. Run:
   ```bash
   cd /opt/unix-storage-monitor
   python3 unix-storage-monitor.py
   ```
3. Add monitor(s), choose mode (`smart`, `storage`, or `both`), save.
4. Test push from menu option 6.
5. Optional: enable cron (1-120 minutes) in menu option 5.

---

## CLI

```bash
python3 unix-storage-monitor.py
python3 unix-storage-monitor.py --run
python3 unix-storage-monitor.py --run -d
```

---

## Dependencies

Required:
- `python3` (3.8+)
- `df`, `lsblk`, `crontab`

For SMART mode:
- `smartctl` (`smartmontools`)

Install SMART tools on Ubuntu:

```bash
sudo apt update
sudo apt install -y smartmontools
```

---

## Security

- config file is owner-only (`0600`)
- atomic config writes
- Kuma URL validation before save
- TLS certificate verification for HTTPS pushes
- no credentials hardcoded
