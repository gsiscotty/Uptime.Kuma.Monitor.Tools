# Kuma Management Console

A comprehensive toolkit for managing Uptime Kuma monitors - featuring a secure web interface and CLI tools for bulk operations.

**Version:** 1.0.0-beta

## Features

- **Web Interface** - Modern, responsive UI for managing monitors
- **CLI Tools** - Interactive command-line tools for bulk operations
- **Two-layer Security** - Web login + Kuma API authentication
- **2FA Support** - TOTP with recovery codes
- **Activity Logging** - Full audit trail of all actions
- **Server Management** - Save and export server configurations

## Core Principles

- Always preview changes (dry-run first)
- Human confirmation before writing
- No hard-coded secrets
- GitHub-safe by default
- Stop on first error (no partial changes)

---

## CLI Tools

### kuma-bulk-editor.py

A full-featured bulk editor for Uptime Kuma monitors.

It allows you to select monitors by tags, then modify multiple monitor properties at once (notifications, intervals, retries, groups, tags, etc.).

### kuma-notifications-editor.py

A focused, streamlined tool for bulk notification management.

This tool is specialized for notification changes only. It's simpler and faster when you only need to add, replace, or remove notifications across multiple monitors. Use this when you don't need to modify other monitor properties.

**Features:**
- List mode: View tags and notifications for monitors without making changes
- Add, replace, or remove notifications
- Filter by tags, groups, and active status

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
  - cleanup duplicates (remove duplicate tag associations)

> ⚠️ **Note:** Tag editing is guarded because API behavior depends on the Kuma version.

---

## Monitor Selection Filters

Before any change, monitors can be filtered by:

- Include monitors by tag(s)
- Exclude monitors by tag(s)
- **Tag matching mode:**  
  - `all` → monitor must contain all specified tags  
  - `any` → monitor must contain at least one specified tag
- **Monitor name filtering:**
  - Filter by monitor name(s) (comma-separated)
  - **Name matching mode:**
    - `full` → monitor name must exactly match one of the provided names
    - `partial` → monitor name must contain one of the provided substrings (case-insensitive)
- **Group filtering:**
  - Skip group (container) monitors (default: No - groups are included by default)
  - Only select group (container) monitors
  - Group monitors are automatically detected by their structure (having `childrenIDs` or missing typical monitor fields)
- **Group membership filtering:**
  - Filter by group name(s) (comma-separated)
  - Selects monitors that belong to the specified group(s)
  - Works alongside other filters (tags, name, active status)
  - Empty = all monitors (no group membership filter applied)
  - If a group name is not found, a warning is displayed with available groups
- Only modify active monitors

---

---

## Web Interface (Kuma Management Console)

A secure, responsive web interface is available for managing Uptime Kuma monitors. It provides the same functionality as the CLI tools but accessible from any browser.

### Features

- **Two-layer authentication**
  - Web app login (username/password + optional TOTP 2FA)
  - Kuma connection credentials (separate from web login)
  - 2FA recovery codes for account recovery
- **Security**
  - CSRF protection
  - Rate limiting (5 login attempts/minute)
  - Account lockout after failed attempts
  - Secure session management
  - Security headers (CSP, X-Frame-Options, etc.)
  - Encrypted credential storage for saved servers
- **Saved Servers**
  - Save multiple Kuma server connections
  - Export/import server configurations
  - Automatic TOTP token generation (optional)
- **Activity Logging**
  - Full audit trail of all actions
  - Configurable retention (default 90 days)
  - Export logs for compliance/review
- **System Management**
  - Create/delete tags and groups
  - Delete monitors in bulk
- **Responsive design** - Works on desktop and mobile
- **Real-time filtering** - Filter monitors by name, tags, groups, type, status
- **Filter negation** - Exclude monitors matching specific criteria
- **Bulk operations** - Same capabilities as CLI tools

### Quick Start with Docker

```bash
# Clone the repository
git clone https://github.com/gsiscotty/kuma-management-console
cd kuma-management-console

# Copy and configure environment
cp .env.example .env
# Edit .env and set a secure SECRET_KEY:
# python -c "import secrets; print(secrets.token_hex(32))"

# Build and run
docker compose up -d

# Access at http://localhost:5080
```

On first access, you'll be prompted to create an admin account.

### Komodo Deployment

The web interface is designed for deployment with Komodo. Simply point Komodo to your Git repository containing this code, and it will automatically build and deploy the Docker container.

**Environment variables for Komodo:**

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Session encryption key (**required**) | - |
| `SESSION_LIFETIME` | Session timeout in seconds | 1800 |
| `SESSION_COOKIE_SECURE` | Require HTTPS for cookies | false |
| `MAX_LOGIN_ATTEMPTS` | Failed attempts before lockout | 5 |
| `LOCKOUT_DURATION` | Lockout duration in minutes | 15 |
| `REQUIRE_2FA` | Force 2FA for all users | false |
| `ALLOWED_IPS` | IP allowlist (comma-separated) | (all) |
| `UNSAFE_MODE` | Disable ALL security (external proxy) | false |
| `TZ` | Timezone | UTC |

### Reverse Proxy Setup

For production, use a reverse proxy (nginx, Traefik, Nginx Proxy Manager) with TLS.

**For external proxy (NPM, Traefik on a different server):**

Set `UNSAFE_MODE=true` - this disables all security restrictions.

```yaml
environment:
  - SECRET_KEY=your-key-here
  - UNSAFE_MODE=true
```

**NPM configuration:**
1. Forward Hostname/IP: `<KMC server IP>`
2. Forward Port: `5080`
3. Enable **Websockets Support**

**Nginx (same server):**

```nginx
server {
    listen 443 ssl http2;
    server_name kuma-console.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:5080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## Requirements

### CLI Tools
- Python 3.9 or newer
- Uptime Kuma 1.23+ (recommended)
- Network access to the Kuma instance

### Web Interface
- Docker (recommended) or Python 3.10+
- Network access to the Kuma instance

### Python Dependencies

- `uptime-kuma-api`
- `pyotp` (only required if you use a TOTP secret instead of entering a token manually)

---

## Installation

### macOS / Linux (CLI Tools)

```bash
git clone https://github.com/gsiscotty/kuma-management-console
cd kuma-management-console

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

**Features:**
- List mode: View tags, notifications, and groups for monitors without making changes
- Detect and display duplicate tags in list mode
- Modify multiple properties in one operation
- Filter by tags, monitor names, group membership, groups (type), and active status
- Tag cleanup mode: Remove duplicate tag associations automatically

### kuma-notifications-editor.py

To run the notification-focused editor:

```bash
python3 kuma-notifications-editor.py
```

This tool is streamlined for notification changes only. It's ideal when you only need to:
- **List** tags and notifications for monitors (no changes made)
- **Add** notifications to monitors
- **Replace** all notifications on monitors
- **Remove** notifications from monitors

**Which tool should I use?**

- **Use `kuma-notifications-editor.py`** if you only need to change notifications — it's simpler and faster.
- **Use `kuma-bulk-editor.py`** if you need to change notifications along with other properties (intervals, retries, groups, tags, etc.).

Both tools will prompt you for your Kuma server URL, username, and password (or API token).  
They will walk you through monitor selection, previewing changes (dry-run), and confirming them before applying changes.

**Tip:** No changes are made until you explicitly confirm them after previewing the plan.

### Authentication Flow

You will be prompted for:

1. **Uptime Kuma URL**  
   - You can enter the URL with or without the protocol
   - Examples: `kuma.example.com` or `https://kuma.example.com`
   - If no protocol is provided, you'll be prompted to choose `http` or `https` (defaults to `https`)
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

1. Authenticate with credentials (URL, username, password, 2FA if enabled)
2. Select what you want to change (or select "list" to view information)
3. Configure filters to select monitors (tags, name, group membership, groups, active status)
4. Ask for new values (skipped for list mode and cleanup mode)
5. Perform a dry-run or display list
   - Shows exactly what will change (for modifications)
   - Shows before → after values (for modifications)
   - Shows current tags, notifications, and groups (for list mode)
   - Shows duplicate tags with counts (for cleanup mode)
6. Ask for confirmation (for modifications)
7. Apply changes only if confirmed (skipped for list mode)
8. After completion, ask if you want to reselect options or exit

**Reselection Loop:**
- After any operation (successful changes, declined changes, or list view), you can choose to:
  - **Reselect** → Start over with new filters/options (keeps you logged in)
  - **Exit/Abort** → Exit the script cleanly
- This allows you to perform multiple operations in one session without re-entering credentials
- If you decline to apply changes or nothing needs to be changed, you can reselect instead of aborting

### List Mode

Both tools support a **list mode** that displays monitor information without making any changes:

**kuma-notifications-editor.py:**
- Select "list" as the notification action
- Displays tags and notifications for all matching monitors

**kuma-bulk-editor.py:**
- Select "LIST: Show tags, notifications, and groups (no changes)" from the change menu
- Displays tags, notifications, and groups for all matching monitors
- Automatically detects and highlights duplicate tags (same tag appearing multiple times on a monitor)

**List Output Example:**

```text
==== MONITOR LIST ====
URL:        https://kuma.example.com
User:       admin
Found:      5 monitors
======================================

[1] api.example.com
  Tags:        ['production', 'api']
  Notifications: ['Email', 'Slack']
  Group:        Infrastructure

[2] web.example.com
  Tags:        ['production', 'web', 'production'] (x2 duplicates)
  ⚠️ DUPLICATES: 'production' appears 2x
  Notifications: ['Email']
  Group:        (none)
```

**Tag Cleanup Mode:**
- Select "Tags: Cleanup duplicates" from the change menu
- Scans monitors for duplicate tag associations (same tag ID appearing multiple times)
- Shows a cleanup plan before execution
- Removes all duplicate instances and re-adds exactly one instance per tag
- Requires explicit confirmation (`CLEANUP`) before proceeding

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
| Cleanup duplicate tags | `CLEANUP` | `kuma-bulk-editor.py` only |
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