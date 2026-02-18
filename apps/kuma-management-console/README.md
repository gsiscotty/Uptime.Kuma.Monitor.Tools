# Kuma Management Console

Secure web application for bulk management of Uptime Kuma monitors, tags, groups, and notifications.

## Features

- Web UI with authentication and optional 2FA.
- Bulk edits for monitor settings.
- Tag/group management and activity logging.
- Saved server profiles (import/export).

## UI screenshots

From this folder, screenshots live at `../../docs/screenshots/`.

| Login | 2FA |
|---|---|
| ![Login screen](../../docs/screenshots/01-login.png) | ![2FA screen](../../docs/screenshots/02-2fa.png) |

![Saved servers screen](../../docs/screenshots/03-servers.png)

| Filters | Bulk changes |
|---|---|
| ![Filters screen](../../docs/screenshots/04-filters.png) | ![Bulk changes screen](../../docs/screenshots/05-bulk-changes.png) |

| Manage tags | Activity log |
|---|---|
| ![Manage tags screen](../../docs/screenshots/06-manage-tags.png) | ![Activity log screen](../../docs/screenshots/07-activity-log.png) |

## Run with Docker (via main compose)

Use the top-level main integration (recommended):

```bash
cd main
cp -n .env.example .env
docker compose up -d --build
docker compose ps
```

Open `http://localhost:5080`.

## Run app directly (without Docker)

```bash
cd apps/kuma-management-console
python3 -m venv .venv
source .venv/bin/activate
pip install -r web/requirements.txt
python3 -m web.app
```
