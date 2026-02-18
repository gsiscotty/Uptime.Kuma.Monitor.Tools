# Kuma Management Console

Secure web application for bulk management of Uptime Kuma monitors, tags, groups, and notifications.

## Features

- Web UI with authentication and optional 2FA.
- Bulk edits for monitor settings.
- Tag/group management and activity logging.
- Saved server profiles (import/export).

## Run with Docker (via main compose)

Use the top-level main integration:

```bash
cd main
cp .env.example .env
docker compose up -d
```

## Run app directly (without Docker)

```bash
cd apps/kuma-management-console
python3 -m venv .venv
source .venv/bin/activate
pip install -r web/requirements.txt
python3 -m web.app
```
