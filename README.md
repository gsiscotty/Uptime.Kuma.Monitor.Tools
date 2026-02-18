# Uptime Kuma Monitor Tools

A collection of tools for managing and extending [Uptime Kuma](https://github.com/louislam/uptime-kuma).

**Author:** gsi_scotty  
**Version:** 1.0.0-beta

---

## What's in this repo?

This repository contains several independent tools. Each one does a different job — you don't need to use all of them. Pick the one that fits your task.

| Tool | Type | What it does |
|------|------|-------------|
| [Kuma Management Console](#kuma-management-console) | Web UI + CLI | Bulk-edit monitors, tags, notifications via browser or terminal |
| [kuma-bulk-editor.py](#kuma-bulk-editorpy) | CLI script | Bulk-modify monitor properties (intervals, retries, groups, tags, notifications) |
| [kuma-notifications-editor.py](#kuma-notifications-editorpy) | CLI script | Quickly add/replace/remove notifications across many monitors |
| [Mount Monitor](#mount-monitor) | CLI script | Monitor mounted shares/filesystems and push status to Kuma |

---

## Kuma Management Console

A secure, responsive **web interface** for managing Uptime Kuma monitors.  
Provides the same bulk-edit power as the CLI tools, accessible from any browser.

**Features:**
- Two-layer authentication (web login + Kuma API)
- 2FA with TOTP and recovery codes
- Bulk operations: notifications, intervals, retries, groups, tags
- Tag cleanup (remove duplicates)
- Activity log with full audit trail
- Saved server configurations (export/import)
- Runs in Docker

### Quick Start

```bash
git clone https://github.com/gsiscotty/kuma-management-console
cd kuma-management-console
cp .env.example .env
# Set a secure SECRET_KEY in .env:
#   python -c "import secrets; print(secrets.token_hex(32))"
docker compose up -d
# Access at http://localhost:5080
```

On first access you'll be prompted to create an admin account.

**Requirements:** Docker (or Python 3.10+), network access to Kuma

---

## kuma-bulk-editor.py

A CLI tool for making bulk changes to many monitors in one operation.

**Use this when you need to change** any combination of: notifications, heartbeat interval, retries, retry interval, resend interval, groups, tags, or upside-down mode — across multiple monitors at once.

```bash
python3 kuma-bulk-editor.py
```

**Key features:**
- Filter monitors by tag, name, group membership, or active status
- Preview all changes before applying (dry-run)
- Typed confirmation required for destructive actions
- Tag cleanup: removes duplicate tag associations
- List mode: view monitor info without making changes

**Requirements:** Python 3.9+, `uptime-kuma-api`, `pyotp`

```bash
pip install -r requirements.txt
```

---

## kuma-notifications-editor.py

A focused CLI tool for notification management only. Simpler and faster than the bulk editor when you only need to touch notifications.

**Use this when you only need to** add, replace, or remove notifications across monitors.

```bash
python3 kuma-notifications-editor.py
```

**Key features:**
- Add notifications to monitors
- Replace all notifications on monitors
- Remove notifications from monitors
- List mode: view current notifications without changes

**Requirements:** Python 3.9+, `uptime-kuma-api`, `pyotp`

---

## Mount Monitor

A standalone CLI script that monitors mounted filesystems (NFS, SMB, local drives) and pushes their status to Uptime Kuma push monitors.

**Use this when you want to** know in Kuma whether a network share or disk is mounted and reachable — without writing any custom scripts.

```bash
# Install with one command:
curl -sL https://raw.githubusercontent.com/gsiscotty/kuma-management-console/main/Unix/Ubuntu/Mount.Monitor/install.sh | bash

# Then run:
cd /opt/mount-monitor
python3 mount-monitor.py
```

**Key features:**
- Interactive menu: add/remove/list monitors
- Measures mount latency and sends it as the Kuma `ping` value
- Schedules automatic checks via cron (1–120 min interval)
- Test push to verify connectivity
- Debug mode for troubleshooting
- No external dependencies (Python stdlib only)

**Requirements:** Python 3.8+, no pip install needed

See [`Unix/Ubuntu/Mount.Monitor/README.md`](Unix/Ubuntu/Mount.Monitor/README.md) for full setup instructions.

---

## Installation (CLI tools)

```bash
git clone https://github.com/gsiscotty/kuma-management-console
cd kuma-management-console

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

The `requirements.txt` contains:
```
uptime-kuma-api
pyotp
```

> **Note:** The Mount Monitor does not require this — it uses Python stdlib only and has its own installer.

---

## Safe by design

All tools in this repo follow the same principles:

- **Preview before applying** — every change shows a dry-run first
- **Explicit confirmation** — nothing is changed without your approval
- **No secrets stored** — credentials are entered at runtime, never written to disk
- **Stop on error** — no silent partial updates

---

## Troubleshooting & Contributions

Questions, issues, or pull requests → open a GitHub issue or discussion.

---

## Screenshots (Kuma Management Console)

### Login & Authentication
| Login Page | Two-Factor Authentication |
|:----------:|:-------------------------:|
| ![Login](docs/screenshots/01-login.png) | ![2FA](docs/screenshots/02-2fa.png) |
| *Secure login with session management* | *TOTP 2FA with recovery code option* |

### Server Management
![Saved Servers](docs/screenshots/03-servers.png)
*Manage multiple Uptime Kuma server connections with import/export*

### Monitor Filtering & Bulk Changes
| Filter Monitors | Bulk Changes |
|:---------------:|:------------:|
| ![Filters](docs/screenshots/04-filters.png) | ![Bulk Changes](docs/screenshots/05-bulk-changes.png) |
| *Filter by name, tags, groups, type, status* | *Apply changes to multiple monitors at once* |

### System Management & Activity Log
| Manage Tags | Activity Log |
|:-----------:|:------------:|
| ![Manage Tags](docs/screenshots/06-manage-tags.png) | ![Activity Log](docs/screenshots/07-activity-log.png) |
| *Create, edit, delete tags and groups* | *Full audit trail with filtering and export* |

---

## Reverse Proxy Notes (CLI tools & Web UI)

The CLI tools use Socket.IO (same as the Kuma web UI). If Kuma is behind a reverse proxy:

- `/socket.io/` must be reachable
- WebSocket upgrade must be allowed

Test reachability:
```bash
curl -sS -D- "https://kuma.example.com/socket.io/?EIO=4&transport=polling"
```

See the [Web Interface section](#kuma-management-console) for full reverse proxy and Docker configuration options.
