# Kuma Bulk Editor (CLI)

Interactive CLI tool for bulk monitor updates in Uptime Kuma.

## Script

- `kuma-bulk-editor.py`

## What it changes

- Notifications (add/replace/remove)
- Intervals, retries, retry interval, resend interval
- Group assignment/clear
- Tags (add/replace/remove) and duplicate tag cleanup

## Run

```bash
cd apps/kuma-bulk-editor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 kuma-bulk-editor.py
```

Safety behavior: always dry-runs first and asks for confirmation before apply.
