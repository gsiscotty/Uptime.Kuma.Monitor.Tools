# Unix Monitor

Unix monitor addon with Synology-grade runtime complexity adapted for generic Unix hosts.

It combines:
- mount checks (`mount-monitor` behavior)
- SMART/storage checks (`unix-storage-monitor` behavior)
- full web UI/auth/session flow
- helper-cache jobs + scheduler state
- master/agent peering APIs and remote monitor creation

Runtime name is generated from system info:
- `<RunningSystem> Kuma Monitor Addon`

## Quick Install

```bash
curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/unix-monitor/install.sh | bash
```

## Setup Modes

### Webserver mode
- Starts local UI (`--ui`) and scheduler
- Full local management (auth, monitor CRUD, diagnostics)
- Supports `standalone`, `master`, `agent`

### No-webserver mode (agent-only)
- Explicitly enforced as `peer_role=agent`
- Requires `peer_master_url` + `peering_token`
- Local UI is disabled
- Menu-based monitor management only
- Master connection is mandatory

## Check Modes

- `mount`
- `smart`
- `storage`
- `ping`
- `port`
- `dns`
- `backup` (best-effort on non-Synology systems)

## Commands

```bash
python3 unix-monitor.py
python3 unix-monitor.py --run
python3 unix-monitor.py --run -d
python3 unix-monitor.py --ui --host 0.0.0.0 --port 8787
python3 unix-monitor.py --run-scheduled
python3 unix-monitor.py --run-scheduled-loop
python3 unix-monitor.py --run-smart-helper
python3 unix-monitor.py --run-backup-helper
python3 unix-monitor.py --run-system-log-helper
```

## Dependencies

Required:
- `python3` 3.8+
- `crontab`

Recommended:
- `smartctl` (`smartmontools`)
- Python packages: `pyotp`, `qrcode`, `pillow`, `werkzeug`, `cryptography`

## Notes

- Some backup/storage helper details are platform-specific; on generic Unix these run in fallback mode where Synology-only tooling is unavailable.
- Installer supports systemd by default and cron fallback.
