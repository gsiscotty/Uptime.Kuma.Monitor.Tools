# Addons Index

This folder contains optional addon scripts that extend Uptime Kuma monitoring.

## Available addons

### 1) Mount Monitor

Monitors mounted filesystems/shares and pushes status to Uptime Kuma.

- Docs: `addons/mount-monitor/README.md`
- Installer:

```bash
curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/mount-monitor/install.sh | bash
```

### 2) Unix Storage Monitor

Monitors Ubuntu/Unix storage health and SMART status, then pushes to Uptime Kuma.

- Docs: `addons/unix-storage-monitor/README.md`
- Installer:

```bash
curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/unix-storage-monitor/install.sh | bash
```

### 3) Synology Monitor

Monitors Synology NAS storage/RAID status and SMART health, then pushes to Uptime Kuma.

- Docs: `addons/synology-monitor/README.md`
- Community package skeleton: `addons/synology-monitor/community-package/README.md`
- Installer:

```bash
curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/synology-monitor/install.sh | bash
```

### 4) Unix Monitor

Provides Synology-parity runtime complexity on Unix (auth UI, helper/scheduler model, peering APIs), plus mount and UNIX storage/SMART checks.

- Docs: `addons/unix-monitor/README.md`
- Installer:

```bash
curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/unix-monitor/install.sh | sudo bash
```

## Notes

- Addons are standalone tools.
- Each addon has its own config file, menu, and optional cron schedule.
- Install and configure only the addon(s) you need.
