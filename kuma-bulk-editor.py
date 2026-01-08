#!/usr/bin/env python3
"""
kuma-bulk-editor.py — GitHub-clean Uptime Kuma bulk editor (interactive).

Key properties supported (matches the screenshot):
- Notifications (add/replace/remove)
- Heartbeat Interval (interval)
- Retries (maxretries)
- Heartbeat Retry Interval (retryInterval)
- Resend Notification if Down X times (resendInterval)
- Upside Down Mode (upsideDown)
- Monitor Group (parent)
- Tags (add/replace/remove)  ⚠️ API support may vary by Kuma version

Safety rules:
- ALWAYS dry-run first and print a detailed plan
- ALWAYS ask for confirmation before applying
- Extra confirmation for dangerous operations (notification REPLACE, tag edits, group CLEAR)
- Stops on first apply error to avoid unknown partial state

Install requirements:
  pip install uptime-kuma-api pyotp

Run:
  python3 kuma-bulk-editor.py
"""

from __future__ import annotations

import getpass
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from uptime_kuma_api import UptimeKumaApi
from uptime_kuma_api.exceptions import Timeout


# -------------------------
# Basic I/O helpers
# -------------------------

def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)


def normalize(s: str) -> str:
    return s.strip().lower()


def parse_csv_list(s: str) -> List[str]:
    if not s.strip():
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def prompt(text: str, default: Optional[str] = None) -> str:
    if default is not None:
        val = input(f"{text} [{default}]: ").strip()
        return val if val else default
    return input(f"{text}: ").strip()


def prompt_int(text: str, default: Optional[int] = None, min_val: Optional[int] = None) -> int:
    while True:
        d = f" [{default}]" if default is not None else ""
        raw = input(f"{text}{d}: ").strip()
        if not raw and default is not None:
            v = default
        else:
            try:
                v = int(raw)
            except Exception:
                print("Please enter an integer.")
                continue
        if min_val is not None and v < min_val:
            print(f"Value must be >= {min_val}.")
            continue
        return v


def prompt_yes_no(text: str, default_yes: bool = False) -> bool:
    default = "Y/n" if default_yes else "y/N"
    val = input(f"{text} ({default}): ").strip().lower()
    if not val:
        return default_yes
    return val in ("y", "yes")


def prompt_choice(text: str, choices: List[str], default: Optional[str] = None) -> str:
    choices_lc = [c.lower() for c in choices]
    while True:
        d = f" [{default}]" if default else ""
        val = input(f"{text} {choices}{d}: ").strip().lower()
        if not val and default:
            return default.lower()
        if val in choices_lc:
            return val
        print(f"Invalid choice. Pick one of: {choices}")


def normalize_url(url: str) -> str:
    """Normalize URL by adding protocol if missing.
    
    If URL doesn't start with http:// or https://, prompt user to choose.
    """
    url = url.strip()
    if not url:
        return url
    
    # Check if URL already has a protocol
    url_lower = url.lower()
    if url_lower.startswith("http://") or url_lower.startswith("https://"):
        return url
    
    # No protocol found, ask user to choose
    protocol = prompt_choice("Choose protocol", ["http", "https"], default="https")
    return f"{protocol}://{url}"


def generate_totp_from_secret(secret: str) -> str:
    try:
        import pyotp  # type: ignore
    except Exception:
        raise RuntimeError("pyotp not installed. Run: pip install pyotp")
    return pyotp.TOTP(secret).now()


def looks_like_invalid_token_error(ex: Exception) -> bool:
    """
    We can't rely on a specific exception class across versions.
    Detect typical messages: AuthInvalidToken / invalid token / 2fa token invalid.
    """
    msg = (str(ex) or "").lower()
    needles = [
        "authinvalidtoken",
        "invalid token",
        "invalid totp",
        "2fa",
        "two-factor",
        "otp",
    ]
    return any(n in msg for n in needles)


# -------------------------
# Kuma object helpers
# -------------------------

def is_group_monitor(monitor: dict) -> bool:
    """Check if a monitor is a group/container monitor.
    
    In Uptime Kuma, group monitors can be identified by:
    - type containing "group" (case-insensitive, e.g., "MonitorType.Group")
    - Having childrenIDs field with non-empty list (group monitors contain other monitors)
    - Missing typical monitor fields like url, hostname, address (group monitors are containers)
    """
    mtype = str(monitor.get("type", "")).strip()
    mtype_lower = mtype.lower()
    
    # Check if type contains "group"
    if "group" in mtype_lower:
        return True
    
    # Check if it has childrenIDs (group monitors contain other monitors)
    children_ids = monitor.get("childrenIDs")
    if isinstance(children_ids, list) and len(children_ids) > 0:
        # Also verify it lacks typical monitor fields to avoid false positives
        has_url = monitor.get("url") or monitor.get("hostname") or monitor.get("address")
        if not has_url:
            return True
    
    # Fallback: check if it's a container by absence of typical monitor fields
    # Group monitors typically don't have url, hostname, address, etc.
    has_url = monitor.get("url")
    has_hostname = monitor.get("hostname")
    has_address = monitor.get("address")
    has_method = monitor.get("method")
    
    # If it has an id and name but no typical monitor fields, might be a group
    if monitor.get("id") and monitor.get("name"):
        if not (has_url or has_hostname or has_address or has_method):
            # Additional check: make sure it's not just a monitor with missing fields
            # Group monitors should have childrenIDs field (even if empty)
            if "childrenIDs" in monitor:
                return True
    
    return False


def get_monitor_tag_names(monitor: dict) -> Set[str]:
    tags = monitor.get("tags") or []
    names: Set[str] = set()
    if isinstance(tags, list):
        for t in tags:
            if isinstance(t, dict):
                nm = t.get("name")
                if isinstance(nm, str) and nm.strip():
                    names.add(normalize(nm))
    return names


def get_monitor_tag_objects(monitor: dict) -> List[dict]:
    """Get the original tag objects from a monitor, preserving IDs and original names."""
    tags = monitor.get("tags") or []
    if not isinstance(tags, list):
        return []
    # Return a copy of tag objects, preserving their structure
    result = []
    for t in tags:
        if isinstance(t, dict):
            # Preserve the tag object as-is (may contain id, name, value, etc.)
            result.append(dict(t))
    return result


def build_tag_name_to_object_map(tag_objects: List[dict]) -> Dict[str, dict]:
    """Build a mapping from normalized tag name to original tag object."""
    mapping: Dict[str, dict] = {}
    for tag_obj in tag_objects:
        name = tag_obj.get("name")
        if isinstance(name, str) and name.strip():
            normalized = normalize(name)
            # Keep the first occurrence if duplicates exist
            if normalized not in mapping:
                mapping[normalized] = tag_obj
    return mapping


def should_include(monitor_tags: Set[str], include: Set[str], mode: str) -> bool:
    if not include:
        return True
    if mode == "all":
        return include.issubset(monitor_tags)
    return len(include.intersection(monitor_tags)) > 0


def has_excluded(monitor_tags: Set[str], exclude: Set[str]) -> bool:
    if not exclude:
        return False
    return len(exclude.intersection(monitor_tags)) > 0


def matches_monitor_name(monitor_name: str, name_filters: List[str], match_mode: str) -> Tuple[bool, str]:
    """
    Check if monitor name matches any of the name filters.
    
    Returns:
        (bool, str): (matches, match_type)
        match_type can be: "full", "partial", or "" (no match)
    """
    if not name_filters:
        return True, ""
    
    monitor_name_norm = normalize(monitor_name)
    
    found_partial = False
    
    for name_filter in name_filters:
        filter_norm = normalize(name_filter)
        
        if match_mode == "full":
            # Exact match (case-insensitive)
            if monitor_name_norm == filter_norm:
                return True, "full"
        else:
            # Partial match (substring, case-insensitive)
            if filter_norm in monitor_name_norm:
                # Check if it's actually a full match
                if monitor_name_norm == filter_norm:
                    return True, "full"
                else:
                    found_partial = True
    
    if found_partial:
        return True, "partial"
    
    return False, ""


def build_notification_maps(notifs: List[dict]) -> Tuple[Dict[str, Tuple[int, str]], Dict[int, str]]:
    """
    name_map: normalized name -> (id, original name)
    id_map:   id -> name
    """
    name_map: Dict[str, Tuple[int, str]] = {}
    id_map: Dict[int, str] = {}
    for n in notifs:
        nid = n.get("id")
        name = n.get("name")
        if isinstance(nid, int) and isinstance(name, str) and name.strip():
            name_map[normalize(name)] = (nid, name.strip())
            id_map[nid] = name.strip()
    return name_map, id_map


def fmt_ids_with_names(ids: List[int], id_to_name: Dict[int, str]) -> str:
    names = [id_to_name.get(i, f"<unknown:{i}>") for i in ids]
    return f"{ids} ({', '.join(names)})"


def try_force_websocket(api: UptimeKumaApi) -> None:
    """
    Best-effort: force websocket transport if the underlying client exposes a knob.
    If it doesn't, we silently do nothing.
    """
    try:
        sio = getattr(api, "sio", None)
        if sio is None:
            return
        if hasattr(sio, "transports"):
            sio.transports = ["websocket"]  # type: ignore[attr-defined]
    except Exception:
        return


def login_with_token_retry(
    api: UptimeKumaApi,
    user: str,
    password: str,
    use_2fa: bool,
    token_mode: str,                # "token" or "secret"
    token_value: str,               # token OR secret (depending on mode)
    max_attempts: int = 5,
    sleep_seconds: float = 1.5,
) -> str:
    """
    Returns the final token used (could be regenerated/prompted).
    Keeps all other options unchanged and does not abort on token expiry.

    Behavior:
    - If 2FA secret mode: regenerate token on each attempt.
    - If 2FA token mode: on invalid token, prompt for a new token.
    - On transient errors/timeouts: retry without re-prompting options.
    """
    last_ex: Optional[Exception] = None

    for attempt in range(1, max_attempts + 1):
        try:
            if not use_2fa:
                api.login(user, password)
                return ""
            if token_mode == "secret":
                # regenerate each attempt to avoid 30s window edge
                fresh_token = generate_totp_from_secret(token_value)
                api.login(user, password, token=fresh_token)
                return fresh_token
            else:
                api.login(user, password, token=token_value)
                return token_value

        except Exception as ex:
            last_ex = ex

            # Handle likely invalid/expired token
            if use_2fa and looks_like_invalid_token_error(ex):
                eprint(f"Login failed (invalid/expired 2FA token). Attempt {attempt}/{max_attempts}.")
                if token_mode == "token":
                    # Ask for a fresh token without restarting the script
                    token_value = prompt("Enter a NEW current 6-digit TOTP token").strip()
                    if not token_value:
                        eprint("ERROR: Token cannot be empty.")
                        continue
                else:
                    # secret mode: just wait a moment and try again (next attempt regenerates)
                    time.sleep(1.0)
            else:
                # Transient / other errors: retry a few times
                eprint(f"Login error. Attempt {attempt}/{max_attempts}: {ex}")
                time.sleep(sleep_seconds)

    # If we got here, all attempts failed
    eprint(f"ERROR: Login failed after {max_attempts} attempts: {last_ex}")
    raise SystemExit(4)


def call_with_retries(fn, retries: int, label: str):
    last = None
    for i in range(retries + 1):
        try:
            return fn()
        except Exception as ex:
            last = ex
            if i >= retries:
                raise
            eprint(f"{label} attempt {i+1} failed ({ex}). Retrying...")
            time.sleep(1.5)
    raise last  # pragma: no cover


# -------------------------
# Change selection
# -------------------------

CHANGE_NOTIFS = "notifications"
CHANGE_INTERVAL = "interval"
CHANGE_MAXRETRIES = "maxretries"
CHANGE_RETRYINTERVAL = "retryInterval"
CHANGE_RESENDINTERVAL = "resendInterval"
CHANGE_UPSIDEDOWN = "upsideDown"
CHANGE_GROUP = "group"
CHANGE_TAGS = "tags"
CHANGE_TAGS_CLEANUP = "tags_cleanup"
CHANGE_LIST = "list"


def choose_changes() -> List[str]:
    menu = [
        (CHANGE_LIST, "LIST: Show tags, notifications, and groups (no changes)"),
        (CHANGE_NOTIFS, "Notifications (add/replace/remove by name)"),
        (CHANGE_INTERVAL, "Heartbeat Interval (seconds)"),
        (CHANGE_MAXRETRIES, "Retries (max retries)"),
        (CHANGE_RETRYINTERVAL, "Heartbeat Retry Interval (seconds)"),
        (CHANGE_RESENDINTERVAL, "Resend Notification if Down X times (0 disables)"),
        (CHANGE_UPSIDEDOWN, "Upside Down Mode (true/false)"),
        (CHANGE_GROUP, "Monitor Group (move to group / clear group)"),
        (CHANGE_TAGS, "Tags (add/replace/remove tags)  ⚠️ API support may vary"),
        (CHANGE_TAGS_CLEANUP, "Tags: Cleanup duplicates (remove duplicate tag associations)"),
    ]
    print("\nWhat do you want to change? (comma-separated numbers)")
    for i, (_, label) in enumerate(menu, start=1):
        print(f"  {i}) {label}")
    raw = prompt("Select", default="1")
    idxs: List[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            idxs.append(int(part))
        except Exception:
            pass

    selected: List[str] = []
    for i in idxs:
        if 1 <= i <= len(menu):
            selected.append(menu[i - 1][0])

    out: List[str] = []
    for x in selected:
        if x not in out:
            out.append(x)
    return out


# -------------------------
# Main
# -------------------------

def main() -> int:
    print("Uptime Kuma Bulk Editor (always dry-run first)")

    # ---- Always ask URL first (per your requirement)
    url_input = prompt("Uptime Kuma URL (root, e.g. kuma.example.com or https://kuma.example.com)")
    if not url_input:
        eprint("ERROR: URL cannot be empty.")
        return 2
    url = normalize_url(url_input)

    user = prompt("Username")
    if not user:
        eprint("ERROR: Username cannot be empty.")
        return 2

    password = getpass.getpass("Password: ").strip()
    if not password:
        eprint("ERROR: Password cannot be empty.")
        return 2

    # ---- 2FA (interactive, no leaks)
    use_2fa = prompt_yes_no("Is 2FA enabled for this user?", default_yes=True)
    token_mode = "token"
    token_value = ""

    if use_2fa:
        token_mode = prompt_choice("Provide 2FA as", ["token", "secret"], default="token")
        if token_mode == "token":
            token_value = prompt("Enter current 6-digit TOTP token").strip()
            if not token_value:
                eprint("ERROR: Token cannot be empty.")
                return 2
        else:
            token_value = getpass.getpass("Enter TOTP secret (BASE32, hidden input): ").strip()
            if not token_value:
                eprint("ERROR: Secret cannot be empty.")
                return 2

    # ---- Main loop: allow reselection after declining to apply
    while True:
        # ---- What to change (select first, before filters)
        selected_changes = choose_changes()
        if not selected_changes:
            print("Nothing selected. Exiting.")
            return 0
        
        # Handle list mode separately
        if CHANGE_LIST in selected_changes:
            # Remove list from selected_changes for processing
            selected_changes = [c for c in selected_changes if c != CHANGE_LIST]
            list_mode = True
        else:
            list_mode = False
        
        # Handle cleanup mode separately
        cleanup_mode = CHANGE_TAGS_CLEANUP in selected_changes
        if cleanup_mode:
            # Remove cleanup from selected_changes for processing
            selected_changes = [c for c in selected_changes if c != CHANGE_TAGS_CLEANUP]

        # ---- Filters (after selecting what to change)
        include_tags = parse_csv_list(prompt("Include tag(s) (comma-separated) - empty = ALL monitors", default=""))
        exclude_tags = parse_csv_list(prompt("Exclude tag(s) (comma-separated) - empty = none", default=""))
        tag_mode = prompt_choice("Include tag match mode", ["all", "any"], default="all")
        name_filters = parse_csv_list(prompt("Filter by monitor name(s) (comma-separated) - empty = ALL monitors", default=""))
        name_match_mode = "partial"
        if name_filters:
            name_match_mode = prompt_choice("Monitor name match mode", ["full", "partial"], default="partial")
        skip_groups = prompt_yes_no("Skip GROUP monitors (containers)?", default_yes=False)
        only_groups = prompt_yes_no("Only select GROUP monitors (containers)?", default_yes=False)
        only_active = prompt_yes_no("Only modify ACTIVE monitors?", default_yes=False)

        include_set = {normalize(t) for t in include_tags if t.strip()}
        exclude_set = {normalize(t) for t in exclude_tags if t.strip()}

        # ---- Change values
        notif_action = ""
        notif_names: List[str] = []
        new_interval: Optional[int] = None
        new_maxretries: Optional[int] = None
        new_retry_interval: Optional[int] = None
        new_resend_interval: Optional[int] = None
        new_upside_down: Optional[bool] = None

        group_mode = ""  # set / clear
        target_group_name = ""
        tag_action = ""  # add/replace/remove
        tag_names: List[str] = []

        if CHANGE_NOTIFS in selected_changes:
            notif_action = prompt_choice("Notifications action", ["add", "replace", "remove"], default="add")
            notif_names = parse_csv_list(prompt(f"Notification name(s) to {notif_action.upper()} (comma-separated)", default=""))
            if not notif_names:
                eprint("ERROR: No notification names provided. Please provide at least one notification name.")
                print("\nReselecting options...\n")
                continue
            print(f"\nYou chose to {notif_action.upper()} these notifications: {notif_names}\n")

        if CHANGE_INTERVAL in selected_changes:
            new_interval = prompt_int("Set Heartbeat Interval in seconds", min_val=1)

        if CHANGE_MAXRETRIES in selected_changes:
            new_maxretries = prompt_int("Set Retries (max retries)", min_val=0)

        if CHANGE_RETRYINTERVAL in selected_changes:
            new_retry_interval = prompt_int("Set Heartbeat Retry Interval in seconds", min_val=1)

        if CHANGE_RESENDINTERVAL in selected_changes:
            new_resend_interval = prompt_int("Set Resend Interval (0 disables)", min_val=0)

        if CHANGE_UPSIDEDOWN in selected_changes:
            new_upside_down = prompt_yes_no("Enable Upside Down Mode?", default_yes=False)

        if CHANGE_GROUP in selected_changes:
            group_mode = prompt_choice("Monitor Group mode", ["set", "clear"], default="set")
            if group_mode == "set":
                target_group_name = prompt("Target Monitor Group name (must match existing group monitor name)").strip()
                if not target_group_name:
                    eprint("ERROR: Group name cannot be empty.")
                    choice = prompt_choice("What would you like to do?", ["reselect", "abort"], default="reselect")
                    if choice == "abort":
                        print("Exiting.")
                        return 0
                    # If reselect, continue the loop
                    print("\nReselecting options...\n")
                    continue

        if CHANGE_TAGS in selected_changes:
            print("\n⚠️ Tags editing: API support can differ by Kuma version/library.")
            print("This script will attempt it, but will STOP on first tag edit failure (no silent half-success).")
            tag_action = prompt_choice("Tags action", ["add", "replace", "remove"], default="add")
            tag_names = parse_csv_list(prompt(f"Tag name(s) to {tag_action.upper()} (comma-separated)", default=""))
            if not tag_names:
                eprint("ERROR: No tag names provided.")
                choice = prompt_choice("What would you like to do?", ["reselect", "abort"], default="reselect")
                if choice == "abort":
                    print("Exiting.")
                    return 0
                # If reselect, continue the loop
                print("\nReselecting options...\n")
                continue
            print(f"\nYou chose to {tag_action.upper()} these tags: {tag_names}\n")

        # ---- Connect
        socket_timeout = 45
        retries = 2

        with UptimeKumaApi(url) as api:
            api.timeout = socket_timeout
            try_force_websocket(api)

            # login with retry; may update token_value if token mode and user re-enters
            final_token_used = login_with_token_retry(
                api=api,
                user=user,
                password=password,
                use_2fa=use_2fa,
                token_mode=token_mode,
                token_value=token_value,
                max_attempts=6,
            )

            # Load notifications (needed for changing notifications or list mode)
            notif_name_map: Dict[str, Tuple[int, str]] = {}
            notif_id_map: Dict[int, str] = {}
            if CHANGE_NOTIFS in selected_changes or list_mode:
                try:
                    notifications = call_with_retries(api.get_notifications, retries, "get_notifications")
                except Timeout as ex:
                    eprint(f"ERROR: Timed out waiting for notifications: {ex}")
                    return 5
                notif_name_map, notif_id_map = build_notification_maps(notifications)

            monitors = api.get_monitors()
            
            # For cleanup mode, collect tags to get tag names for display
            cleanup_tag_id_to_obj: Dict[int, dict] = {}  # tag ID -> tag object (for cleanup display)
            cleanup_all_system_tags: Dict[str, dict] = {}  # normalized name -> tag object (for cleanup)
            
            # Handle cleanup mode separately - scan for duplicate tags and remove them
            if cleanup_mode:
                # First, try to get all tags from the system API (these should have IDs)
                try:
                    if hasattr(api, 'get_tags'):
                        system_tags_list = api.get_tags()
                        if system_tags_list:
                            for tag_obj in system_tags_list:
                                tag_id = tag_obj.get("id")
                                tag_name = tag_obj.get("name")
                                if isinstance(tag_id, int):
                                    cleanup_tag_id_to_obj[tag_id] = tag_obj
                                if isinstance(tag_name, str) and tag_name.strip():
                                    tag_norm = normalize(tag_name)
                                    # Use system tag (which should have IDs)
                                    cleanup_all_system_tags[tag_norm] = tag_obj
                except Exception:
                    pass  # API method might not be available
                
                # Also collect tags from all monitors (as fallback)
                for m in monitors:
                    tag_objs = get_monitor_tag_objects(m)
                    for tag_obj in tag_objs:
                        tag_id = tag_obj.get("id")
                        tag_name = tag_obj.get("name")
                        if isinstance(tag_id, int) and tag_id not in cleanup_tag_id_to_obj:
                            cleanup_tag_id_to_obj[tag_id] = tag_obj
                        if isinstance(tag_name, str) and tag_name.strip():
                            tag_norm = normalize(tag_name)
                            # Only add if not already in system tags (to keep system tag with ID)
                            if tag_norm not in cleanup_all_system_tags:
                                cleanup_all_system_tags[tag_norm] = tag_obj
                print("\n==== TAG CLEANUP MODE ====")
                print("Scanning monitors for duplicate tag associations...\n")
                
                cleanup_plan: List[Tuple[int, str, List[int], Dict[int, int], Dict[int, dict], Dict[str, int]]] = []
                # Entry: (mid, name, duplicate_tag_ids, tag_id_to_count, tag_id_to_obj_map, tag_name_to_count)
                
                for m in monitors:
                    mid = m.get("id")
                    name = m.get("name") or "<unnamed>"
                    
                    if not isinstance(mid, int):
                        continue
                    
                    # Apply filters
                    if only_active and not bool(m.get("active", True)):
                        continue
                    if only_groups:
                        if not is_group_monitor(m):
                            continue
                    elif skip_groups and is_group_monitor(m):
                        continue
                    
                    tags = get_monitor_tag_names(m)
                    if has_excluded(tags, exclude_set):
                        continue
                    if not should_include(tags, include_set, tag_mode):
                        continue
                    
                    # Name filtering
                    name_matches, _ = matches_monitor_name(name, name_filters, name_match_mode)
                    if not name_matches:
                        continue
                    
                    # Find duplicate tags on this monitor
                    # Use EXACTLY the same method as LIST mode: get_monitor_tag_objects() and count by normalized name
                    tag_objects = get_monitor_tag_objects(m)
                    
                    # Count tag occurrences by normalized name (EXACT same logic as LIST mode)
                    tag_name_counts: Dict[str, int] = {}  # normalized name -> count
                    tag_name_to_tag_objects: Dict[str, List[dict]] = {}  # normalized name -> list of tag objects
                    for tag_obj in tag_objects:
                        tag_name = tag_obj.get("name")
                        if isinstance(tag_name, str) and tag_name.strip():
                            tag_norm = normalize(tag_name)
                            tag_name_counts[tag_norm] = tag_name_counts.get(tag_norm, 0) + 1
                            if tag_norm not in tag_name_to_tag_objects:
                                tag_name_to_tag_objects[tag_norm] = []
                            tag_name_to_tag_objects[tag_norm].append(tag_obj)
                    
                    # Find duplicate tag names (EXACT same detection as LIST mode)
                    duplicate_tag_names = [tag_norm for tag_norm, count in tag_name_counts.items() if count > 1]
                    
                    # For each duplicate tag name, collect tag IDs that need to be cleaned
                    # First try to get IDs from tag objects, then fall back to system tag lookup
                    duplicate_tag_ids: List[int] = []
                    tag_id_counts: Dict[int, int] = {}
                    tag_id_to_obj_map: Dict[int, dict] = {}
                    tag_name_to_id_map: Dict[str, int] = {}  # normalized name -> tag ID (from system tags)
                    
                    # Look up tag IDs from system tags by name
                    for tag_norm in tag_name_counts.keys():
                        # Try to find tag ID from system tags
                        system_tag_obj = cleanup_all_system_tags.get(tag_norm)
                        if system_tag_obj:
                            tag_id = system_tag_obj.get("id")
                            if isinstance(tag_id, int):
                                tag_name_to_id_map[tag_norm] = tag_id
                    
                    # For each duplicate tag name, get the tag ID and track counts
                    for tag_norm in duplicate_tag_names:
                        # First try to get ID from tag objects
                        tag_objs = tag_name_to_tag_objects.get(tag_norm, [])
                        tag_id_from_obj = None
                        for tag_obj in tag_objs:
                            tag_id = tag_obj.get("id")
                            if isinstance(tag_id, int):
                                tag_id_from_obj = tag_id
                                break
                        
                        # If not found in objects, try system tag lookup
                        if tag_id_from_obj is None:
                            tag_id_from_obj = tag_name_to_id_map.get(tag_norm)
                        
                        if tag_id_from_obj is not None:
                            if tag_id_from_obj not in duplicate_tag_ids:
                                duplicate_tag_ids.append(tag_id_from_obj)
                            # Count how many times this tag appears (from tag_name_counts)
                            count = tag_name_counts.get(tag_norm, 0)
                            tag_id_counts[tag_id_from_obj] = count
                            # Store tag object (use first one or system tag)
                            if tag_id_from_obj not in tag_id_to_obj_map:
                                tag_obj = tag_objs[0] if tag_objs else cleanup_all_system_tags.get(tag_norm, {})
                                tag_id_to_obj_map[tag_id_from_obj] = tag_obj
                    
                    # Collect all unique tag IDs that should remain (for re-adding)
                    unique_tag_ids = set()
                    unique_tag_names_set = set(tag_name_counts.keys())  # All unique tag names
                    
                    for tag_norm in unique_tag_names_set:
                        # Try to get tag ID from tag objects first
                        tag_objs = tag_name_to_tag_objects.get(tag_norm, [])
                        tag_id = None
                        for tag_obj in tag_objs:
                            tag_id = tag_obj.get("id")
                            if isinstance(tag_id, int):
                                break
                        
                        # If not found, try system tag lookup
                        if tag_id is None or not isinstance(tag_id, int):
                            tag_id = tag_name_to_id_map.get(tag_norm)
                        
                        if tag_id is not None and isinstance(tag_id, int):
                            unique_tag_ids.add(tag_id)
                            if tag_id not in tag_id_to_obj_map:
                                tag_obj = tag_objs[0] if tag_objs else cleanup_all_system_tags.get(tag_norm, {})
                                tag_id_to_obj_map[tag_id] = tag_obj
                    
                    # Only add to cleanup plan if we detected duplicates AND have tag IDs to work with
                    if duplicate_tag_names and len(unique_tag_ids) > 0:
                        cleanup_plan.append((mid, name, duplicate_tag_ids, tag_id_counts, tag_id_to_obj_map, tag_name_counts))
                
                if not cleanup_plan:
                    print("No duplicate tags found. All monitors are clean.\n")
                    choice = prompt_choice("What would you like to do?", ["reselect", "exit"], default="reselect")
                    if choice == "exit":
                        print("Exiting.")
                        return 0
                    print("\nReselecting options...\n")
                    continue
                
                # Show cleanup plan
                print(f"\n==== CLEANUP PLAN ====")
                print(f"Found {len(cleanup_plan)} monitors with duplicate tags:\n")
                
                total_duplicates = 0
                for mid, name, duplicate_tag_ids, tag_id_counts, tag_id_to_obj_map, tag_name_counts in cleanup_plan:
                    duplicate_info = []
                    all_tag_names = []
                    
                    # Show duplicates that will be cleaned
                    for tag_id in duplicate_tag_ids:
                        count = tag_id_counts.get(tag_id, 1)
                        tag_obj = tag_id_to_obj_map.get(tag_id) or cleanup_tag_id_to_obj.get(tag_id, {})
                        tag_name = tag_obj.get("name", f"<unknown:{tag_id}>")
                        if not tag_name or tag_name.startswith("<unknown"):
                            # Try to get name from system tags
                            for norm, tag_obj2 in cleanup_all_system_tags.items():
                                if tag_obj2.get("id") == tag_id:
                                    tag_name = tag_obj2.get("name", tag_name)
                                    break
                        
                        duplicate_info.append(f"{tag_name} (appears {count}x, will remove duplicates and keep 1)")
                        total_duplicates += (count - 1)
                        all_tag_names.append(tag_name)
                    
                    # Also show other tags that won't be touched
                    for tag_id, count in tag_id_counts.items():
                        if tag_id not in duplicate_tag_ids:
                            tag_obj = tag_id_to_obj_map.get(tag_id) or cleanup_tag_id_to_obj.get(tag_id, {})
                            tag_name = tag_obj.get("name", f"<unknown:{tag_id}>")
                            if not tag_name or tag_name.startswith("<unknown"):
                                for norm, tag_obj2 in cleanup_all_system_tags.items():
                                    if tag_obj2.get("id") == tag_id:
                                        tag_name = tag_obj2.get("name", tag_name)
                                        break
                            all_tag_names.append(tag_name)
                    
                    print(f"[{mid}] {name}")
                    print(f"  Duplicate tags: {', '.join(duplicate_info)}")
                    if all_tag_names:
                        print(f"  All tags after cleanup: {', '.join(sorted(set(all_tag_names)))}")
                    print()
                
                print(f"Total duplicate tag associations to remove: {total_duplicates}\n")
                
                # Confirm cleanup
                if not prompt_yes_no(f"Remove {total_duplicates} duplicate tag association(s) from {len(cleanup_plan)} monitor(s)?", default_yes=False):
                    choice = prompt_choice("What would you like to do?", ["reselect", "exit"], default="reselect")
                    if choice == "exit":
                        print("Exiting.")
                        return 0
                    print("\nReselecting options...\n")
                    continue
                
                # Extra confirmation
                typed = input("CONFIRM TAG CLEANUP: type CLEANUP to proceed: ").strip()
                if typed != "CLEANUP":
                    choice = prompt_choice("What would you like to do?", ["reselect", "exit"], default="reselect")
                    if choice == "exit":
                        print("Exiting.")
                        return 0
                    print("\nReselecting options...\n")
                    continue
                
                # Perform cleanup
                # Strategy: For each duplicate tag ID (from initial scan), remove all instances, then re-add exactly one
                print("\nRemoving duplicate tags (removing duplicates, keeping one instance of each)...")
                cleaned = 0
                removed_count = 0
                for mid, name, duplicate_tag_ids, tag_id_counts, tag_id_to_obj_map, tag_name_counts in cleanup_plan:
                    try:
                        # Use the duplicate tag IDs and counts from the initial scan
                        # These are the tags that were detected as duplicates before the API could deduplicate them
                        for tag_id in duplicate_tag_ids:
                            count = tag_id_counts.get(tag_id, 1)
                            if count <= 1:
                                continue  # Skip if not actually duplicated
                            
                            tag_obj = tag_id_to_obj_map.get(tag_id) or cleanup_tag_id_to_obj.get(tag_id, {})
                            tag_name = tag_obj.get("name", f"<unknown:{tag_id}>")
                            
                            try:
                                # Record initial state from scan (duplicates detected: count > 1)
                                duplicates_removed = count - 1  # We want to keep 1, so remove (count - 1)
                                
                                # Check current state (API might deduplicate, so we might not see duplicates)
                                # Tags from monitor have "tag_id" field, not "id" field
                                current_monitor = api.get_monitor(mid)
                                current_tags = current_monitor.get("tags") or []
                                current_tag_ids = []
                                for t in current_tags:
                                    if isinstance(t, dict):
                                        # Try both "id" and "tag_id" fields
                                        tag_id_val = t.get("id") or t.get("tag_id")
                                        if isinstance(tag_id_val, int):
                                            current_tag_ids.append(tag_id_val)
                                current_count = current_tag_ids.count(tag_id)
                                
                                # If tag appears multiple times now, we need to remove duplicates
                                # delete_monitor_tag removes ALL instances, so we call it once, then re-add one
                                if current_count > 1:
                                    # Remove all instances (delete_monitor_tag removes all at once)
                                    api.delete_monitor_tag(tag_id=tag_id, monitor_id=mid)
                                    
                                    # Verify removal
                                    verify_monitor = api.get_monitor(mid)
                                    verify_tags = verify_monitor.get("tags") or []
                                    verify_tag_ids = []
                                    for t in verify_tags:
                                        if isinstance(t, dict):
                                            tag_id_val = t.get("id") or t.get("tag_id")
                                            if isinstance(tag_id_val, int):
                                                verify_tag_ids.append(tag_id_val)
                                    
                                    if tag_id not in verify_tag_ids:
                                        # Tag completely removed, re-add exactly one instance
                                        api.add_monitor_tag(tag_id=tag_id, monitor_id=mid)
                                        removed_count += duplicates_removed
                                        print(f"  [{mid}] {name}: Removed {duplicates_removed} duplicate(s) of '{tag_name}' (was {count}x from scan), kept 1")
                                    else:
                                        # Tag still exists after deletion (unexpected)
                                        remaining_count = verify_tag_ids.count(tag_id)
                                        if remaining_count > 1:
                                            # Still has duplicates, try more aggressive removal
                                            eprint(f"  ⚠️  Warning: [{mid}] {name}: '{tag_name}' still has {remaining_count} instance(s), attempting additional removal...")
                                            # Try removing multiple times
                                            for attempt in range(remaining_count + 2):
                                                try:
                                                    api.delete_monitor_tag(tag_id=tag_id, monitor_id=mid)
                                                    verify_monitor = api.get_monitor(mid)
                                                    verify_tags = verify_monitor.get("tags") or []
                                                    verify_tag_ids = []
                                                    for t in verify_tags:
                                                        if isinstance(t, dict):
                                                            tag_id_val = t.get("id") or t.get("tag_id")
                                                            if isinstance(tag_id_val, int):
                                                                verify_tag_ids.append(tag_id_val)
                                                    if tag_id not in verify_tag_ids:
                                                        api.add_monitor_tag(tag_id=tag_id, monitor_id=mid)
                                                        removed_count += duplicates_removed
                                                        print(f"  [{mid}] {name}: Removed {duplicates_removed} duplicate(s) of '{tag_name}' after {attempt + 1} attempt(s), kept 1")
                                                        break
                                                except Exception as retry_ex:
                                                    if attempt == remaining_count + 1:
                                                        raise retry_ex
                                        else:
                                            # Exactly one instance remains, which is what we want
                                            removed_count += duplicates_removed
                                            print(f"  [{mid}] {name}: Cleaned '{tag_name}' (was {count}x from scan, now 1x)")
                                elif current_count == 1:
                                    # Tag already has exactly one instance (API deduplicated it)
                                    # But we detected duplicates in the initial scan, so they might still exist in DB
                                    # Try to remove and re-add to ensure no duplicates remain
                                    api.delete_monitor_tag(tag_id=tag_id, monitor_id=mid)
                                    api.add_monitor_tag(tag_id=tag_id, monitor_id=mid)
                                    removed_count += duplicates_removed
                                    print(f"  [{mid}] {name}: Cleaned '{tag_name}' (removed duplicates from DB, was {count}x from scan, now 1x)")
                                else:
                                    # Tag not found (shouldn't happen if we detected duplicates)
                                    eprint(f"  ⚠️  Warning: [{mid}] {name}: '{tag_name}' (ID: {tag_id}) not found on monitor (was {count}x in scan)")
                                
                            except Exception as tag_ex:
                                eprint(f"  ⚠️  Failed to clean duplicate tag '{tag_name}' (ID: {tag_id}) from [{mid}] {name}: {tag_ex}")
                                raise
                        
                        cleaned += 1
                        
                    except Exception as monitor_ex:
                        eprint(f"  ⚠️  Failed to clean [{mid}] {name}: {monitor_ex}")
                        raise
                    except Exception as ex:
                        eprint(f"\nERROR cleaning up [{mid}] {name}: {ex}")
                        eprint("Stopped to avoid partial/unknown state.")
                        return 10
                
                print(f"\nDone. Cleaned up {cleaned} monitors.")
                print(f"Removed {removed_count} duplicate tag association(s).\n")
                
                # Ask if user wants to reselect or exit
                choice = prompt_choice("What would you like to do?", ["reselect", "exit"], default="reselect")
                if choice == "exit":
                    print("Exiting.")
                    return 0
                print("\nReselecting options...\n")
                continue
            
            # For tag editing, collect all tags from all monitors to understand the structure
            # and to find/create tags that need to be added
            all_system_tags: Dict[str, dict] = {}  # normalized name -> tag object
            all_tag_ids: Dict[str, int] = {}  # normalized name -> tag ID
            tag_id_to_obj: Dict[int, dict] = {}  # tag ID -> tag object (for case-sensitive lookup)
            if CHANGE_TAGS in selected_changes:
                # Try to fetch all tags from the system using get_tags() if available
                try:
                    if hasattr(api, "get_tags"):
                        system_tags_list = api.get_tags()
                        for tag in system_tags_list:
                            tag_name = tag.get("name")
                            if isinstance(tag_name, str) and tag_name.strip():
                                normalized = normalize(tag_name)
                                tag_dict = dict(tag)
                                all_system_tags[normalized] = tag_dict
                                tag_id = tag.get("id")
                                if isinstance(tag_id, int):
                                    all_tag_ids[normalized] = tag_id
                                    # Store by ID for case-sensitive lookup
                                    tag_id_to_obj[tag_id] = tag_dict
                except Exception:
                    # get_tags() might not be available, fall back to collecting from monitors
                    pass
                
                # Also collect all existing tags from all monitors (for tags not in system list)
                for m in monitors:
                    tag_objs = get_monitor_tag_objects(m)
                    for tag_obj in tag_objs:
                        tag_name = tag_obj.get("name")
                        if isinstance(tag_name, str) and tag_name.strip():
                            normalized = normalize(tag_name)
                            tag_dict = dict(tag_obj)
                            # Keep first occurrence, preserving original structure
                            if normalized not in all_system_tags:
                                all_system_tags[normalized] = tag_dict
                                tag_id = tag_obj.get("id")
                                if isinstance(tag_id, int):
                                    all_tag_ids[normalized] = tag_id
                                    # Store by ID for case-sensitive lookup
                                    if tag_id not in tag_id_to_obj:
                                        tag_id_to_obj[tag_id] = tag_dict

            # Build group maps (name -> id, id -> name)
            group_name_to_id: Dict[str, int] = {}
            group_id_to_name: Dict[int, str] = {}
            for m in monitors:
                if is_group_monitor(m) and isinstance(m.get("id"), int):
                    gid = int(m["id"])
                    gname = str(m.get("name") or "").strip()
                    if gname:
                        group_name_to_id[normalize(gname)] = gid
                        group_id_to_name[gid] = gname

            # For tags, try to create missing tags first
            if CHANGE_TAGS in selected_changes:
                # Build mapping from normalized to original tag names
                tag_norm_to_original: Dict[str, str] = {}
                for orig_tag_name in tag_names:
                    norm_name = normalize(orig_tag_name)
                    if norm_name not in tag_norm_to_original:
                        tag_norm_to_original[norm_name] = orig_tag_name
                
                desired_normalized = {normalize(t) for t in tag_names}
                for tag_norm in desired_normalized:
                    if tag_norm not in all_system_tags:
                        # Tag doesn't exist - try to create it
                        original_tag_name = tag_norm_to_original.get(tag_norm)
                        if original_tag_name:
                            try:
                                # Try to create the tag if add_tag/create_tag method exists
                                if hasattr(api, "add_tag"):
                                    new_tag = api.add_tag(original_tag_name)
                                    if new_tag and isinstance(new_tag, dict):
                                        all_system_tags[tag_norm] = new_tag
                                        tag_id = new_tag.get("id")
                                        if isinstance(tag_id, int):
                                            all_tag_ids[tag_norm] = tag_id
                                        # Tag created successfully
                                        pass
                                elif hasattr(api, "create_tag"):
                                    new_tag = api.create_tag(original_tag_name)
                                    if new_tag and isinstance(new_tag, dict):
                                        all_system_tags[tag_norm] = new_tag
                                        tag_id = new_tag.get("id")
                                        if isinstance(tag_id, int):
                                            all_tag_ids[tag_norm] = tag_id
                                        # Tag created successfully
                                        pass
                            except Exception as create_ex:
                                eprint(f"⚠️  Could not create tag '{original_tag_name}': {create_ex}")
                                eprint("   Tag might need to be created manually in Uptime Kuma UI first.")

            target_group_id: Optional[int] = None
            if CHANGE_GROUP in selected_changes and group_mode == "set":
                key = normalize(target_group_name)
                if key not in group_name_to_id:
                    eprint("\nERROR: Group not found.")
                    eprint("Available groups:")
                    for gn_norm in sorted(group_name_to_id.keys()):
                        eprint(f"  - {group_id_to_name[group_name_to_id[gn_norm]]}")
                    return 7
                target_group_id = group_name_to_id[key]

            # Resolve target notification IDs (if needed)
            target_notif_ids: List[int] = []
            target_notif_pretty: List[str] = []
            if CHANGE_NOTIFS in selected_changes:
                missing = [n for n in notif_names if normalize(n) not in notif_name_map]
                if missing:
                    eprint("ERROR: These notification names were not found:")
                    for x in missing:
                        eprint(f"  - {x}")
                    eprint("\nAvailable notifications:")
                    # If you want to list available: need original notifs. We'll fetch again for safe display.
                    notifications = api.get_notifications()
                    for n in sorted(notifications, key=lambda d: str(d.get("name", ""))):
                        eprint(f"  - {n.get('name')} (id={n.get('id')})")
                    return 6

                for n in notif_names:
                    nid, nm = notif_name_map[normalize(n)]
                    target_notif_ids.append(nid)
                    target_notif_pretty.append(nm)

            # ---- Build dry-run plan or collect list data
            # Plan entry: (mid, name, payload, before, after, match_type, tag_changes)
            # tag_changes: Tuple[List[int], List[int]] = (tags_to_add_ids, tags_to_remove_ids)
            plan: List[Tuple[int, str, Dict[str, Any], Dict[str, Any], Dict[str, Any], str, Tuple[List[int], List[int]]]] = []
            # List entry: (mid, name, tags, notifications, group, match_type, tag_counts)
            # tag_counts: Dict[str, int] = normalized name -> count (to show duplicates)
            list_results: List[Tuple[int, str, List[str], List[str], str, str, Dict[str, int]]] = []

            notif_replace_losing = 0
            notif_dropped_union: Set[int] = set()

            for m in monitors:
                mid = m.get("id")
                name = m.get("name") or "<unnamed>"
                active = bool(m.get("active", True))

                if not isinstance(mid, int):
                    continue
                if only_active and not active:
                    continue
                # Group filtering: only_groups takes precedence over skip_groups
                if only_groups:
                    if not is_group_monitor(m):
                        continue
                elif skip_groups and is_group_monitor(m):
                    continue

                tags = get_monitor_tag_names(m)
                if has_excluded(tags, exclude_set):
                    continue
                if not should_include(tags, include_set, tag_mode):
                    continue
                
                # Name filtering
                name_matches, match_type = matches_monitor_name(name, name_filters, name_match_mode)
                if not name_matches:
                    continue

                # Group display
                parent = m.get("parent")  # can be int or None
                parent_name = group_id_to_name.get(parent, "") if isinstance(parent, int) else ""
                group_name = parent_name or "(none)"
                
                # For list mode, collect info and skip change processing
                if list_mode:
                    # Get notifications
                    notif_ids = m.get("notificationIDList") or []
                    if not isinstance(notif_ids, list):
                        notif_ids = []
                    notif_names_list = [notif_id_map.get(i, f"<unknown:{i}>") for i in notif_ids]
                    
                    # Get actual tag objects to detect duplicates
                    tag_objects = get_monitor_tag_objects(m)
                    # Count tag occurrences by normalized name to detect duplicates
                    tag_counts: Dict[str, int] = {}  # normalized name -> count
                    for tag_obj in tag_objects:
                        tag_name = tag_obj.get("name")
                        if isinstance(tag_name, str) and tag_name.strip():
                            tag_norm = normalize(tag_name)
                            tag_counts[tag_norm] = tag_counts.get(tag_norm, 0) + 1
                    
                    # Use sorted unique tags for display (normalized), but track counts
                    list_results.append((mid, name, sorted(tags), notif_names_list, group_name, match_type, tag_counts))
                    continue

                payload: Dict[str, Any] = {}
                before: Dict[str, Any] = {}
                after: Dict[str, Any] = {}

                before["group"] = group_name
                before["tags"] = sorted(tags)

                if CHANGE_INTERVAL in selected_changes:
                    before["interval"] = m.get("interval")
                    after["interval"] = new_interval
                    payload["interval"] = new_interval

                if CHANGE_MAXRETRIES in selected_changes:
                    before["maxretries"] = m.get("maxretries")
                    after["maxretries"] = new_maxretries
                    payload["maxretries"] = new_maxretries

                if CHANGE_RETRYINTERVAL in selected_changes:
                    before["retryInterval"] = m.get("retryInterval")
                    after["retryInterval"] = new_retry_interval
                    payload["retryInterval"] = new_retry_interval

                if CHANGE_RESENDINTERVAL in selected_changes:
                    before["resendInterval"] = m.get("resendInterval")
                    after["resendInterval"] = new_resend_interval
                    payload["resendInterval"] = new_resend_interval

                if CHANGE_UPSIDEDOWN in selected_changes:
                    before["upsideDown"] = bool(m.get("upsideDown", False))
                    after["upsideDown"] = bool(new_upside_down)
                    payload["upsideDown"] = bool(new_upside_down)

                if CHANGE_GROUP in selected_changes:
                    if group_mode == "clear":
                        after["group"] = "(none)"
                        payload["parent"] = None
                    else:
                        after["group"] = group_id_to_name.get(target_group_id, "(unknown)") if target_group_id else "(none?)"
                        payload["parent"] = target_group_id

                if CHANGE_NOTIFS in selected_changes:
                    cur_ids = m.get("notificationIDList") or []
                    if not isinstance(cur_ids, list):
                        cur_ids = []

                    cur_set = set(int(x) for x in cur_ids if isinstance(x, int))
                    tgt_set = set(target_notif_ids)

                    if notif_action == "replace":
                        new_set = tgt_set
                    elif notif_action == "add":
                        new_set = cur_set.union(tgt_set)
                    else:
                        new_set = cur_set.difference(tgt_set)

                    new_ids = sorted(new_set)
                    before["notifications"] = sorted(cur_set)
                    after["notifications"] = new_ids
                    payload["notificationIDList"] = new_ids

                    if notif_action == "replace":
                        dropped = cur_set.difference(new_set)
                        if dropped:
                            notif_replace_losing += 1
                            notif_dropped_union.update(dropped)

                if CHANGE_TAGS in selected_changes:
                    # Get original tag objects from monitor
                    original_tag_objects = get_monitor_tag_objects(m)
                    tag_name_to_obj = build_tag_name_to_object_map(original_tag_objects)
                    
                    cur_tags = set(tags)  # normalized names
                    desired_normalized = {normalize(t) for t in tag_names}
                    # Map from normalized name to original tag name (for user input)
                    norm_to_original: Dict[str, str] = {}
                    for orig_name in tag_names:
                        norm_name = normalize(orig_name)
                        # Keep first occurrence if duplicates exist
                        if norm_name not in norm_to_original:
                            norm_to_original[norm_name] = orig_name

                    if tag_action == "replace":
                        new_tags_normalized = desired_normalized
                    elif tag_action == "add":
                        new_tags_normalized = cur_tags.union(desired_normalized)
                    else:
                        new_tags_normalized = cur_tags.difference(desired_normalized)

                    after["tags"] = sorted(new_tags_normalized)

                    # Build payload with tag objects
                    # The API expects tags - we'll try using full tag objects (with ID if available)
                    # Some APIs might require tag IDs, others might accept just names
                    # Sort by tag ID if available, otherwise by name, to ensure consistent ordering
                    payload_tags = []
                    tag_info_list = []  # (tag_norm, tag_obj, tag_source, tag_id)
                    for tag_norm in sorted(new_tags_normalized):
                        tag_obj = None
                        tag_source = None
                        
                        # First, try to find the tag object from system-wide tags
                        if tag_norm in all_system_tags:
                            tag_obj = all_system_tags[tag_norm]
                            tag_source = "system"
                        # Then try current monitor's tags
                        elif tag_norm in tag_name_to_obj:
                            tag_obj = tag_name_to_obj[tag_norm]
                            tag_source = "monitor"
                        
                        if tag_obj:
                            # Store tag info for sorting
                            tag_id = tag_obj.get("id")
                            tag_info_list.append((tag_norm, tag_obj, tag_source, tag_id))
                        else:
                            # Tag not found in system - use original name from user input
                            tag_name = norm_to_original.get(tag_norm)
                            if tag_name:
                                # Try to find if tag exists with different casing by checking all system tags
                                found_exact_match = False
                                for sys_tag_norm, sys_tag_obj in all_system_tags.items():
                                    sys_tag_name = sys_tag_obj.get("name", "")
                                    # Check if normalized names match or if exact name match
                                    if normalize(sys_tag_name) == tag_norm or sys_tag_name == tag_name:
                                        sys_tag_id = sys_tag_obj.get("id")
                                        tag_info_list.append((tag_norm, sys_tag_obj, "system (casing match)", sys_tag_id))
                                        found_exact_match = True
                                        break
                                
                                if not found_exact_match:
                                    tag_info_list.append((tag_norm, {"name": tag_name}, "user input", None))
                            else:
                                # Fallback: use normalized name (shouldn't happen in normal flow)
                                tag_info_list.append((tag_norm, {"name": tag_norm}, "fallback", None))
                    
                    # Sort tags by ID if available, otherwise by name - ensures consistent ordering
                    # Use a sort key: (has_id, id or 999999, name)
                    tag_info_list.sort(key=lambda x: (
                        x[3] is not None,  # Tags with IDs first
                        x[3] if x[3] is not None else 999999,  # Then by ID
                        x[0]  # Then by normalized name
                    ))
                    
                    # Build payload tags from sorted list
                    # IMPORTANT: Tags are case-sensitive - use exact name from system, not user input
                    for tag_norm, tag_obj, tag_source, tag_id in tag_info_list:
                        # Build simplified tag object - API might not accept all fields
                        tag_copy = {}
                        # Include ID if present (some APIs require it)
                        if isinstance(tag_id, int):
                            tag_copy["id"] = tag_id
                        
                        # Get the exact tag name from the system (case-sensitive!)
                        # Since tags are case-sensitive, we need to use the exact case from the system
                        tag_name = None
                        
                        # If we have an ID, look it up by ID to get the exact case from system
                        if isinstance(tag_id, int) and tag_id in tag_id_to_obj:
                            # Use the tag object stored by ID - this has the exact case from the system
                            system_tag_obj = tag_id_to_obj[tag_id]
                            tag_name = system_tag_obj.get("name")
                        
                        # Fallback: use name from tag_obj
                        if not tag_name:
                            tag_name = tag_obj.get("name")
                        
                        if tag_name:
                            # Use the exact case from the system - tags are case-sensitive
                            tag_copy["name"] = tag_name
                        else:
                            # Last resort: use normalized name (shouldn't happen)
                            tag_copy["name"] = tag_norm
                        
                        # Some APIs might ignore color, value, etc. - try without them first
                        payload_tags.append(tag_copy)
                    
                    # Don't send tags in edit_monitor payload - use add_monitor_tag/delete_monitor_tag instead
                    # Calculate which tags to add and remove
                    # Get current tag IDs directly from original_tag_objects to catch all tags (including duplicates)
                    # Use a set to get unique tag IDs only (ignore duplicates that might already exist)
                    current_tag_ids = set()
                    for tag_obj in original_tag_objects:
                        tag_id = tag_obj.get("id")
                        if isinstance(tag_id, int):
                            current_tag_ids.add(tag_id)
                    
                    new_tag_ids = set()
                    for tag_obj in payload_tags:
                        tag_id = tag_obj.get("id")
                        if isinstance(tag_id, int):
                            new_tag_ids.add(tag_id)
                        else:
                            # Tag without ID - this shouldn't happen if tag exists in system
                            tag_name = tag_obj.get("name", "unknown")
                            eprint(f"  ⚠️  WARNING: Tag '{tag_name}' has no ID - may not be applied correctly")
                    
                    # Tags to add (in new but not in current) - only tags that don't already exist
                    tags_to_add = sorted(new_tag_ids - current_tag_ids)
                    # Tags to remove (in current but not in new)
                    tags_to_remove = sorted(current_tag_ids - new_tag_ids)
                    
                    tag_changes = (tags_to_add, tags_to_remove)
                else:
                    tag_changes = ([], [])

                if payload or (CHANGE_TAGS in selected_changes and (tag_changes[0] or tag_changes[1])):
                    plan.append((mid, str(name), payload, before, after, match_type, tag_changes))

            # ---- List mode or DRY RUN output
            if list_mode:
                print("\n==== MONITOR LIST ====")
                print(f"URL:           {url}")
                print(f"User:          {user}")
                print(f"Found:         {len(list_results)} monitors")
                if name_filters:
                    print(f"Name filter:   {name_filters} (mode: {name_match_mode})")
                print("======================================\n")
                
                for mid, name, tags, notif_names_list, group_name, match_type, tag_counts in sorted(list_results, key=lambda x: x[1].lower()):
                    match_info = f" [{match_type.upper()} match]" if match_type else ""
                    print(f"[{mid}] {name}{match_info}")
                    
                    # Show tags - check for duplicates
                    has_duplicates = any(count > 1 for count in tag_counts.values())
                    if has_duplicates:
                        # Show tags with duplicate indicators
                        tags_display = []
                        for tag_norm in sorted(tags):
                            count = tag_counts.get(tag_norm, 1)
                            if count > 1:
                                tags_display.append(f"{tag_norm} (x{count} duplicates)")
                            else:
                                tags_display.append(tag_norm)
                        print(f"  Tags:         {', '.join(tags_display) if tags_display else '(none)'}")
                        
                        # Also show duplicate summary
                        dup_details = []
                        for tag_norm, count in sorted(tag_counts.items()):
                            if count > 1:
                                dup_details.append(f"'{tag_norm}' appears {count}x")
                        if dup_details:
                            print(f"  ⚠️  DUPLICATES: {', '.join(dup_details)}")
                    else:
                        print(f"  Tags:         {tags if tags else '(none)'}")
                    
                    print(f"  Notifications: {notif_names_list if notif_names_list else '(none)'}")
                    print(f"  Group:        {group_name}")
                    print()
            else:
                print("\n==== DRY-RUN PLAN ====")
                print(f"URL:           {url}")
                print(f"User:          {user}")
                print(f"2FA:           {'YES' if use_2fa else 'NO'}")
                print(f"Filter include:{sorted(include_set) if include_set else '(none)'} (mode: {tag_mode})")
                print(f"Filter exclude:{sorted(exclude_set) if exclude_set else '(none)'}")
                if name_filters:
                    print(f"Name filter:   {name_filters} (mode: {name_match_mode})")
                if only_groups:
                    print(f"Group filter:  Only groups")
                else:
                    print(f"Skip groups:   {skip_groups}")
                print(f"Only active:   {only_active}")
                print(f"Will change:   {len(plan)} monitors")
                print("======================\n")

            if not list_mode:
                if CHANGE_NOTIFS in selected_changes:
                    print(f"Notifications: {notif_action.upper()} {target_notif_pretty} (IDs: {target_notif_ids})")
                    if notif_action == "replace" and notif_replace_losing > 0:
                        dropped_list = sorted(notif_dropped_union)
                        dropped_names = [notif_id_map.get(i, f"<unknown:{i}>") for i in dropped_list]
                        print("\n!!! WARNING: NOTIFICATION REPLACE WILL DROP NOTIFICATIONS !!!")
                        print(f"Monitors that would lose at least one notification: {notif_replace_losing}")
                        print(f"Dropped somewhere: {dropped_list} ({', '.join(dropped_names)})")
                        print("If you meant 'keep existing + add', choose ADD next time.\n")

                if CHANGE_GROUP in selected_changes:
                    if group_mode == "clear":
                        print("Group: CLEAR (move monitors out of any group)")
                    else:
                        print(f"Group: SET -> {group_id_to_name.get(target_group_id, target_group_name)}")

                if CHANGE_TAGS in selected_changes:
                    print(f"Tags: {tag_action.upper()} {tag_names}  (⚠️ will stop on first tag API failure)")

                print("\nChanges per monitor:\n")
            for mid, name, payload, before, after, match_type, tag_changes in plan:
                match_info = f" [{match_type.upper()} match]" if match_type else ""
                print(f"[{mid}] {name}{match_info}")

                if "notificationIDList" in payload:
                    cur_ids = before.get("notifications") or []
                    new_ids = after.get("notifications") or []
                    cur_list = cur_ids if isinstance(cur_ids, list) else []
                    cur_list_int = [x for x in cur_list if isinstance(x, int)]
                    print(f"  notifications: {fmt_ids_with_names(cur_list_int, notif_id_map)} -> {fmt_ids_with_names(new_ids, notif_id_map)}")

                if "interval" in payload:
                    print(f"  interval:      {before.get('interval')} -> {after.get('interval')}")

                if "maxretries" in payload:
                    print(f"  maxretries:    {before.get('maxretries')} -> {after.get('maxretries')}")

                if "retryInterval" in payload:
                    print(f"  retryInterval: {before.get('retryInterval')} -> {after.get('retryInterval')}")

                if "resendInterval" in payload:
                    print(f"  resendInterval:{before.get('resendInterval')} -> {after.get('resendInterval')}")

                if "upsideDown" in payload:
                    print(f"  upsideDown:    {before.get('upsideDown')} -> {after.get('upsideDown')}")

                if "parent" in payload:
                    print(f"  group:         {before.get('group')} -> {after.get('group')}")

                # Display tag changes
                tags_to_add, tags_to_remove = tag_changes
                if tags_to_add or tags_to_remove:
                    tag_changes_str = []
                    if tags_to_remove:
                        tag_changes_str.append(f"remove: {tags_to_remove}")
                    if tags_to_add:
                        tag_changes_str.append(f"add: {tags_to_add}")
                    print(f"  tags:          {before.get('tags')} -> {after.get('tags')} ({', '.join(tag_changes_str)})")

            # For list mode, skip the apply confirmation
            if list_mode:
                # Ask if user wants to reselect or exit
                choice = prompt_choice("What would you like to do?", ["reselect", "exit"], default="reselect")
                if choice == "exit":
                    print("Exiting.")
                    return 0
                # If reselect, continue the loop
                print("\nReselecting options...\n")
                continue

            if not plan:
                print("\nNothing to change.")
                # Ask if user wants to reselect or abort
                choice = prompt_choice("What would you like to do?", ["reselect", "abort"], default="reselect")
                if choice == "abort":
                    print("Exiting.")
                    return 0
                # If reselect, continue the loop
                print("\nReselecting options...\n")
                continue

            # ---- Confirm apply
            if not prompt_yes_no(f"\nApply these changes to {len(plan)} monitors NOW?", default_yes=False):
                # Ask if user wants to reselect or abort
                choice = prompt_choice("What would you like to do?", ["reselect", "abort"], default="reselect")
                if choice == "abort":
                    print("Aborted. No changes were written.")
                    return 0
                # If reselect, continue the loop
                print("\nReselecting options...\n")
                continue

            # Extra safety latches
            if CHANGE_NOTIFS in selected_changes and notif_action == "replace":
                typed = input("CONFIRM NOTIFICATION REPLACE: type REPLACE to proceed: ").strip()
                if typed != "REPLACE":
                    # Ask if user wants to reselect or abort
                    choice = prompt_choice("What would you like to do?", ["reselect", "abort"], default="reselect")
                    if choice == "abort":
                        print("Aborted. No changes were written.")
                        return 0
                    # If reselect, continue the loop
                    print("\nReselecting options...\n")
                    continue

            if CHANGE_TAGS in selected_changes:
                typed = input("CONFIRM TAG CHANGES: type TAGS to proceed: ").strip()
                if typed != "TAGS":
                    # Ask if user wants to reselect or abort
                    choice = prompt_choice("What would you like to do?", ["reselect", "abort"], default="reselect")
                    if choice == "abort":
                        print("Aborted. No changes were written.")
                        return 0
                    # If reselect, continue the loop
                    print("\nReselecting options...\n")
                    continue

            if CHANGE_GROUP in selected_changes and group_mode == "clear":
                typed = input("CONFIRM GROUP CLEAR: type CLEAR to proceed: ").strip()
                if typed != "CLEAR":
                    # Ask if user wants to reselect or abort
                    choice = prompt_choice("What would you like to do?", ["reselect", "abort"], default="reselect")
                    if choice == "abort":
                        print("Aborted. No changes were written.")
                        return 0
                    # If reselect, continue the loop
                    print("\nReselecting options...\n")
                    continue

            # ---- Apply (stop on first failure)
            print("\nApplying changes (will stop on first error)...")
            changed = 0
            for mid, name, payload, _before, _after, _match_type, tag_changes in plan:
                try:
                    tags_to_add, tags_to_remove = tag_changes
                    
                    # First, apply non-tag changes using edit_monitor
                    if payload:
                        # Remove tags from payload if present (we handle tags separately)
                        edit_payload = {k: v for k, v in payload.items() if k != "tags"}
                        if edit_payload:
                            api.edit_monitor(mid, **edit_payload)
                    
                    # Then, handle tags using add_monitor_tag/delete_monitor_tag API methods
                    if tags_to_remove:
                        for tag_id in tags_to_remove:
                            try:
                                api.delete_monitor_tag(tag_id=tag_id, monitor_id=mid)
                            except Exception as tag_ex:
                                eprint(f"  ⚠️  Failed to remove tag ID {tag_id} from [{mid}] {name}: {tag_ex}")
                                raise
                    
                    if tags_to_add:
                        for tag_id in tags_to_add:
                            try:
                                # Double-check tag doesn't already exist (prevents duplicates)
                                # Fetch current monitor state right before adding to be sure
                                current_monitor = api.get_monitor(mid)
                                current_tags = current_monitor.get("tags") or []
                                current_tag_ids_on_monitor = set()
                                for tag_obj in current_tags:
                                    if isinstance(tag_obj, dict):
                                        existing_tag_id = tag_obj.get("id")
                                        if isinstance(existing_tag_id, int):
                                            current_tag_ids_on_monitor.add(existing_tag_id)
                                
                                # Only add if not already present (prevents duplicates)
                                if tag_id not in current_tag_ids_on_monitor:
                                    api.add_monitor_tag(tag_id=tag_id, monitor_id=mid)
                                # else: tag already exists on monitor, skip (prevents duplicates)
                            except Exception as tag_ex:
                                eprint(f"  ⚠️  Failed to add tag ID {tag_id} to [{mid}] {name}: {tag_ex}")
                                raise
                    
                    # After applying, verify tags if they were changed
                    if tags_to_add or tags_to_remove:
                        # Re-fetch monitor to verify tags were applied
                        try:
                            updated_monitor = api.get_monitor(mid)
                            updated_tags = get_monitor_tag_names(updated_monitor)
                            expected_tags = sorted(_after.get('tags', []))
                            actual_tags = sorted(updated_tags)
                            if actual_tags != expected_tags:
                                eprint(f"  ⚠️  WARNING: Tags mismatch on [{mid}] {name}")
                                eprint(f"     Expected: {expected_tags}")
                                eprint(f"     Actual:   {actual_tags}")
                        except Exception as verify_ex:
                            eprint(f"  ⚠️  Could not verify tags on [{mid}] {name}: {verify_ex}")
                    
                except Exception as ex:
                    eprint(f"\nERROR applying to [{mid}] {name}: {ex}")
                    eprint("Stopped to avoid partial/unknown state across many monitors.")
                    if tags_to_add or tags_to_remove:
                        eprint("Tip: if this failed on TAGS, check that tag IDs are correct.")
                    return 10
                changed += 1

            print(f"Done. Applied changes to {changed} monitors.")
            
            # Ask if user wants to reselect or exit
            choice = prompt_choice("What would you like to do?", ["reselect", "exit"], default="reselect")
            if choice == "exit":
                print("Exiting.")
                return 0
            # If reselect, continue the loop
            print("\nReselecting options...\n")
            continue


if __name__ == "__main__":
    raise SystemExit(main())