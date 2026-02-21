# Synology Monitor Addon - System Architecture

![System Architecture](synology-monitor-architecture.png)

## 1. Package Installation & Service Startup

DSM Package Center installs the SPK. The `postinst` script sets up 4 cron jobs and starts 2 long-running services:

- **Web UI Server** on port 8787 (`--ui`)
- **Scheduler Loop** running every 60 seconds (`--run-scheduled-loop`)

On package upgrade, `postupgrade` clears the backup cache before re-running `postinst`.

### Cron Jobs (installed by postinst)

| Job | Script | Interval | Entry Point |
|-----|--------|----------|-------------|
| SMART helper | `smart-helper.sh` | Every 5 min | `--run-smart-helper` |
| Backup helper | `backup-helper.sh` | Every 5 min | `--run-backup-helper` |
| System-log helper | `system-log-helper.sh` | Every 5 min | `--run-system-log-helper` |
| Monitor scheduler | `monitor-scheduler.sh` | Every 1 min | `--run-scheduled` |

## 2. Root Helpers (cron, every 5 minutes)

Three helpers run as root via cron to collect data the non-root web server cannot access:

- **smart-helper** — Runs `smartctl -H` on SATA/block/SCSI devices and `nvme smart-log` on NVMe. Writes results to `smart-cache.json`.
- **backup-helper** — Queries the `SYNO.Backup.Task` API for Hyper Backup / C2 Backup task status and parses backup log files. Writes results to `backup-cache.json`.
- **system-log-helper** — Reads `/var/log/messages` or `/var/log/syslog`. Writes results to `system-log-cache.json`.

Cache max age: 20 minutes. If the cache is older, checks report a stale-cache warning.

## 3. Monitor Checks (scheduler, every 1 minute)

`run_scheduled()` iterates over all configured monitors. Each monitor runs one of the 6 check modes:

| Mode | Function | How It Works |
|------|----------|--------------|
| **SMART** | `check_smart()` | Reads root-written `smart-cache.json`. Falls back to direct `smartctl` if root. |
| **Storage** | `check_storage()` | Runs `synospace --enum`. Falls back to `df -P` + `/proc/mdstat`. |
| **Backup** | `_probe_backup()` | Reads root-written `backup-cache.json`. Falls back to log parsing without root. |
| **Ping** | `_probe_ping()` | ICMP `ping -c 1`. Falls back to TCP connect on port 80/443. |
| **Port** | `_probe_port()` | TCP `socket.create_connection()` with 3-second timeout. |
| **DNS** | `_probe_dns()` | `nslookup` with custom server, or `socket.getaddrinfo()` for system resolver. |

Each check returns a status (`up`, `warning`, or `down`), a list of message lines, and latency in ms.

### Push to Uptime Kuma

Results are sent via `push_to_kuma()`:

```
GET {base_url}?status={status}&msg={message}&ping={latency_ms}
```

Uptime Kuma only accepts `status=up` or `status=down`. The addon maps `warning` to `up` so degraded-but-not-down states show green in Kuma. The message text conveys the actual warning.

## 4. Web UI (port 8787)

Single-page application served by a built-in `ThreadingHTTPServer`. Optional TLS.

### Authentication

- Password + TOTP two-factor authentication
- Session cookies (30-minute TTL)
- Challenge cookies for the 2FA step (5-minute TTL)
- Recovery codes (one-time use)
- Lockout after 5 failed attempts (15-minute cooldown)

### Views

| View | Description |
|------|-------------|
| **Overview** | Monitor list with status indicators, run check / test push buttons, diagnostics |
| **Setup** | Guided wizard for first-time configuration and elevated-access setup |
| **Settings** | Instance config, peering setup, backup/restore, danger zone |

### Diagnostics Sub-views

Logs, Task status, Config dump, Cache contents, History, File paths, System info.

### Key Actions (POST endpoints)

- Create / edit / delete monitors
- Run check, Test push (per-monitor or all)
- Clear logs, caches, history, task status
- Repair automation (cron re-install)
- Export / import encrypted config backup

## 5. Peering (Master / Agent)

Multi-NAS monitoring with mutual TLS (mTLS).

### Roles

- **Standalone** — Default. Single instance, no peering.
- **Master** — Owns a CA, signs agent certificates, aggregates agent data.
- **Agent** — Runs local checks, pushes snapshots to master after each scheduled run.

### Certificate Flow

1. Master generates a CA and server certificate.
2. Agent sends a CSR to `POST /api/peer/register`.
3. Master signs the CSR and returns the signed client cert + CA cert.
4. All subsequent peer traffic uses mTLS.

### Data Flow

| Direction | Endpoint | Payload |
|-----------|----------|---------|
| Agent → Master | `POST /api/peer/push` | Snapshot (monitors, state, history, version) |
| Agent → Master | `POST /api/peer/register` | CSR → signed cert + CA cert |
| Master → Agent | `GET /api/peer/snapshot` | Agent config and monitor data |
| Master → Agent | `GET /api/peer/diag` | Agent diagnostic logs (with view/filter params) |

## 6. Data Stores

All state files live under `/var/packages/synology-monitor/var/`:

| File | Purpose |
|------|---------|
| `synology-monitor.json` | Main config (monitors, peering, settings) |
| `synology-auth.json` | Auth state (password hash, TOTP secret, sessions) |
| `synology-smart-cache.json` | SMART check results (from root helper) |
| `synology-backup-cache.json` | Backup check results (from root helper) |
| `synology-system-log-cache.json` | System log extract (from root helper) |
| `synology-monitor-state.json` | Current monitor states (last status per monitor) |
| `synology-monitor-history.json` | Status change history |
| `synology-schedule-state.json` | Scheduler timing state |
| `synology-task-status.json` | Task scheduler status |
| `synology-monitor-ui.log` | Append-only UI/helper log |
| `certs/` | mTLS certificates (CA, server, agent certs) |
| `peers/` | Peer data (agent snapshots cached by master) |

## 7. CLI Entry Points

All via `python3 synology-monitor.py <flag>`:

| Flag | Purpose |
|------|---------|
| `--ui` | Start the web UI server (with optional `--host` / `--port`) |
| `--run-smart-helper` | Run SMART + backup data collection (requires root) |
| `--run-backup-helper` | Run backup status collection only (requires root) |
| `--run-system-log-helper` | Run system log collection (requires root) |
| `--run-scheduled` | Run one pass of all scheduled monitor checks |
| `--run-scheduled-loop` | Run scheduled checks in an infinite 60-second loop |
| `--run` / `-r` | Run checks interactively (with optional `--debug`) |
| *(none)* | Interactive CLI menu |
