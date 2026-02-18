# Kuma Notifications Editor (CLI)

Focused CLI tool for bulk notification updates in Uptime Kuma.

## Script

- `kuma-notifications-editor.py`

## What it changes

- Add notifications to monitors
- Replace notifications on monitors
- Remove notifications from monitors
- List monitors and current notification assignments

## Run

```bash
cd apps/kuma-notifications-editor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 kuma-notifications-editor.py
```

Safety behavior: dry-run preview and explicit confirmation before writes.
