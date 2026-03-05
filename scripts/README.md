# Scripts

## migrate-legacy-to-unix-monitor.sh

Migrates from deprecated **mount-monitor** or **unix-storage-monitor** to **unix-monitor**. Preserves monitors and Kuma URLs, cleans up old cron entries.

Usually run by the deprecated addon install scripts; can also be run directly:

```bash
curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/scripts/migrate-legacy-to-unix-monitor.sh | bash -s mount-monitor
curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/scripts/migrate-legacy-to-unix-monitor.sh | bash -s unix-storage-monitor
```

## bump-addon-version.py

Updates version numbers across all version locations for an addon. **Requires your explicit confirmation** before applying any changes.

Use before every release to keep versions in sync (Python VERSION constant, package INFO, etc.).

```bash
# Preview changes (dry run)
python3 scripts/bump-addon-version.py --dry-run synology-monitor 1.0.0-0056
python3 scripts/bump-addon-version.py --dry-run unix-monitor 1.0.0-0056

# Apply (will prompt: "Apply these changes? [y/N]:")
python3 scripts/bump-addon-version.py synology-monitor 1.0.0-0056
python3 scripts/bump-addon-version.py unix-monitor 1.0.0-0056
```

**synology-monitor** updates:
- `addons/synology-monitor/synology-monitor.py` (VERSION)
- `addons/synology-monitor/community-package/package/INFO` (version)

**unix-monitor** updates:
- `addons/unix-monitor/unix-monitor.py` (VERSION)
