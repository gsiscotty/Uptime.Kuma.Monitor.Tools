# Uptime Kuma Monitor Tools

This repository contains applications and add-ons for Uptime Kuma, organized by role.

## Quick start

### Web UI (recommended)

```bash
cd main
cp -n .env.example .env
docker compose up -d --build
docker compose ps
```

Then open: `http://localhost:5080`

### Addons (monitoring scripts)

| Addon | Platform | Install |
|-------|----------|---------|
| **Unix Monitor** | Linux, macOS | `curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/unix-monitor/install.sh \| sudo bash` |
| **Synology Monitor** | Synology DSM | `curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/synology-monitor/install.sh \| bash` |

*Mount Monitor and Unix Storage Monitor are deprecated; their installers redirect to Unix Monitor.*

## Structure

```
.
├── main/                    # Docker compose entry point
├── apps/
│   ├── kuma-management-console/   # Web UI
│   ├── kuma-bulk-editor/          # CLI bulk editor
│   └── kuma-notifications-editor/ # CLI notifications editor
├── addons/
│   ├── unix-monitor/        # Unix/Linux monitor (mount, SMART, storage, web UI)
│   ├── synology-monitor/    # Synology NAS monitor
│   ├── mount-monitor/       # DEPRECATED → use unix-monitor
│   └── unix-storage-monitor/# DEPRECATED → use unix-monitor
├── scripts/                 # Version bump, migration helpers
└── docs/                    # Shared assets
```

## Documentation

- **Web UI:** `main/README.md`, `apps/kuma-management-console/README.md`
- **Addons:** `addons/README.md`
- **CLI tools:** `apps/kuma-bulk-editor/README.md`, `apps/kuma-notifications-editor/README.md`
