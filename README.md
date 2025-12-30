# Uptime Kuma Bulk Tools

This repository provides interactive, safe-by-default CLI tools for managing large numbers of monitors in Uptime Kuma.

The tools are designed for operators who want control, visibility, and safety when performing bulk changes.

## Core Principles

- 🔍 Always preview changes (dry-run first)
- 🧠 Human confirmation before writing
- 🔐 No hard-coded secrets
- 📦 GitHub-safe by default
- 🛑 Stop on first error (no partial changes)

---

## Included Tools

### kuma-bulk-editor.py

A full-featured bulk editor for Uptime Kuma monitors.

It allows you to select monitors by tags, then modify multiple monitor properties at once (notifications, intervals, retries, groups, tags, etc.).

### kuma-notifications-editor.py

A focused, streamlined tool for bulk notification management.

This tool is specialized for notification changes only. It's simpler and faster when you only need to add, replace, or remove notifications across multiple monitors. Use this when you don't need to modify other monitor properties.

---

## Supported Changes

You can change any combination of the following:

- **Notifications**
  - add
  - replace
  - remove
- **Heartbeat interval** (`interval`)
- **Retries** (`maxretries`)
- **Heartbeat retry interval** (`retryInterval`)
- **Resend notification interval** (`resendInterval`)
- **Upside Down mode**
- **Monitor group**
  - move monitors into a group
  - remove monitors from a group
- **Tags**
  - add
  - replace
  - remove

> ⚠️ **Note:** Tag editing is guarded because API behavior depends on the Kuma version.

---

## Monitor Selection Filters

Before any change, monitors can be filtered by:

- Include monitors by tag(s)
- Exclude monitors by tag(s)
- **Tag matching mode:**
  - `all` → monitor must contain all specified tags
  - `any` → monitor must contain at least one specified tag
- Skip group (container) monitors
- Only modify active monitors

---

## Requirements

- Python 3.9 or newer
- Uptime Kuma 1.23+ (recommended)
- Network access to the Kuma instance

### Python Dependencies

- `uptime-kuma-api`
- `pyotp` (only required if you use a TOTP secret instead of entering a token manually)

---

## Installation

### macOS / Linux

```bash
git clone <your-repo-url>
cd <repo>

python3 -m venv venv
source venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
```

The `requirements.txt` file contains:

```
uptime-kuma-api
pyotp
```

---

## Running the Tools

### kuma-bulk-editor.py

To run the full-featured bulk editor:

```bash
python3 kuma-bulk-editor.py
```

This tool allows you to modify multiple monitor properties (notifications, intervals, retries, groups, tags, etc.) in a single operation.

### kuma-notifications-editor.py

To run the notification-focused editor:

```bash
python3 kuma-notifications-editor.py
```

This tool is streamlined for notification changes only. It's ideal when you only need to:
- Add notifications to monitors
- Replace all notifications on monitors
- Remove notifications from monitors

**Which tool should I use?**

- **Use `kuma-notifications-editor.py`** if you only need to change notifications — it's simpler and faster.
- **Use `kuma-bulk-editor.py`** if you need to change notifications along with other properties (intervals, retries, groups, tags, etc.).

Both tools will prompt you for your Kuma server URL, username, and password (or API token).  
They will walk you through monitor selection, previewing changes (dry-run), and confirming them before applying changes.

**Tip:** No changes are made until you explicitly confirm them after previewing the plan.

### Authentication Flow

You will be prompted for:

1. **Uptime Kuma URL**  
   Example: `https://kuma.example.com`
2. **Username**
3. **Password**
   - Hidden input
   - Never printed
   - Never stored
4. **2FA** (if enabled)  
   You can choose:
   - Enter a current 6-digit TOTP token
   - Enter the TOTP secret
     - The token is generated locally
     - The secret is never stored or logged

No credentials are written to disk or environment variables.

### Workflow

> **Important:** The tool always follows the same safe workflow:

1. Ask how to filter/select monitors
2. Ask what you want to change
3. Ask for new values
4. Perform a dry-run
   - Shows exactly what will change
   - Shows before → after values
5. Ask for confirmation
6. Apply changes only if confirmed

If you answer No, nothing is written.

### Dry-Run Output

During the dry-run phase, the script prints a detailed plan.

For each affected monitor you will see:

- Monitor name and ID
- Current value → new value
- Notification names (not only IDs)
- Group names
- Tag differences

**Example:**

```text
[42] api.example.com

  interval:       60 -> 30

  maxretries:     3  -> 5

  notifications: [1,2] (Email, Slack) -> [2] (Slack)
```

### Dangerous Operations (Extra Safety)

Some actions require typed confirmation, not just y/N.

| Action | Required Confirmation | Tool |
|--------|----------------------|------|
| Replace notifications | `REPLACE` | Both |
| Modify tags | `TAGS` | `kuma-bulk-editor.py` only |
| Clear monitor group | `CLEAR` | `kuma-bulk-editor.py` only |

If the confirmation text does not match exactly, the operation is aborted.

### Tag Editing Notes

Tag editing depends on the Uptime Kuma API version and the Python wrapper.

**Safety behavior:**

- The script attempts to update tags
- If the API rejects the update:
  - The script stops immediately
  - No further monitors are modified

This prevents silent partial updates across many monitors.

### Reverse Proxy / HTTPS Notes

The tool uses Socket.IO, the same mechanism as the Uptime Kuma web UI.

If Kuma is running behind a reverse proxy:

- `/socket.io/` must be reachable
- WebSocket upgrade should be allowed

You can test this manually:

```bash
curl -sS -D- "https://kuma.example.com/socket.io/?EIO=4&transport=polling"
```

If you see an HTTP 200 and some content (or chunks) in response, the backend is reachable.

To test WebSocket support (from a Linux/macOS shell):

```bash
websocat "wss://kuma.example.com/socket.io/?EIO=4&transport=websocket"
```

A successful connection is usually enough for the API. If you have issues, check your proxy and firewall settings.

---

## Troubleshooting & Getting Help

If you have questions, requests, or run into problems, please open a GitHub issue or discussion!  
Pull requests are welcome.

---

## What This Tool Does NOT Do

- ❌ No secrets are stored
- ❌ No environment variables required
- ❌ No config files written
- ❌ No blind batch updates
- ❌ No partial success without warning

---

## Philosophy

These tools follow one simple rule:

> **Preview everything. Confirm explicitly. Never guess.**

They are designed to be boring, predictable, and safe — exactly what you want when touching hundreds of monitors at once.