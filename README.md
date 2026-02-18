# Uptime Kuma Monitor Tools

This repository contains multiple applications and add-ons for Uptime Kuma, organized by role so setup is easier to understand.

## Folder hierarchy

```text
.
├── main/                         # Main integration entry point (compose + env)
├── apps/
│   ├── kuma-management-console/  # Web UI application
│   ├── kuma-bulk-editor/         # CLI application
│   └── kuma-notifications-editor/# CLI application
├── addons/
│   └── mount-monitor/            # Optional mount/filesystem monitor addon
└── docs/                         # Shared screenshots/docs assets
```

## Start here

- For full stack startup and "how parts fit together", open `main/README.md`.
- For each app/addon details, use the README in its own folder:
  - `apps/kuma-management-console/README.md`
  - `apps/kuma-bulk-editor/README.md`
  - `apps/kuma-notifications-editor/README.md`
  - `addons/mount-monitor/README.md`

## Quick start (main entry point)

```bash
cd main
cp .env.example .env
docker compose up -d
```

Then open `http://localhost:5080`.
