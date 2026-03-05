# Mount Monitor — DEPRECATED

> **This addon is deprecated.** Use [unix-monitor](../unix-monitor/README.md) instead.

unix-monitor includes everything mount-monitor did (mount monitoring) plus storage checks, SMART health, web UI, and peering.

## Migration

If you run the install script, it will detect an existing install and offer to migrate automatically:

```bash
curl -sL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/mount-monitor/install.sh | bash
```

Your monitors will be preserved and migrated to unix-monitor.

## New installs

If you run the install script without an existing install, it will suggest installing unix-monitor instead.

---

*Last supported version: 1.1.0*
