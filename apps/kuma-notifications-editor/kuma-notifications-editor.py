#!/usr/bin/env python3
"""
kuma-notifications-editor.py — Safe bulk notification editor for Uptime Kuma.

Features:
- Add / replace / remove notifications on many monitors
- Filter monitors by tags (include / exclude, all / any)
- Skip group monitors
- Optional: only active monitors
- 2FA support (token or secret)
- ALWAYS dry-run first
- Explicit confirmation before writing

Reliability:
- Retries login on transient failures/timeouts
- If 2FA token expires (AuthInvalidToken), it will re-prompt/re-generate and retry
- Remembers all already selected options during retries

GitHub-safe:
- No hard-coded URLs
- No env vars
- No secrets stored or logged
"""

from __future__ import annotations

import getpass
import sys
import time
from typing import Dict, List, Set, Tuple, Optional

from uptime_kuma_api import UptimeKumaApi
from uptime_kuma_api.exceptions import Timeout


# -------------------------
# Helpers
# -------------------------

def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)


def normalize(s: str) -> str:
    return s.strip().lower()


def parse_csv_list(s: str) -> List[str]:
    if not s.strip():
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def prompt(text: str, default: str | None = None) -> str:
    if default is not None:
        val = input(f"{text} [{default}]: ").strip()
        return val if val else default
    return input(f"{text}: ").strip()


def prompt_yes_no(text: str, default_yes: bool = False) -> bool:
    default = "Y/n" if default_yes else "y/N"
    val = input(f"{text} ({default}): ").strip().lower()
    if not val:
        return default_yes
    return val in ("y", "yes")


def prompt_choice(text: str, choices: List[str], default: str | None = None) -> str:
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
    """
    Strict mode (as requested): expects ONLY raw BASE32 secret.
    """
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
# Kuma helpers
# -------------------------

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


def build_notification_maps(notifs: List[dict]) -> Tuple[Dict[str, Tuple[int, str]], Dict[int, str]]:
    name_map: Dict[str, Tuple[int, str]] = {}
    id_map: Dict[int, str] = {}
    for n in notifs:
        nid = n.get("id")
        name = n.get("name")
        if isinstance(nid, int) and isinstance(name, str) and name.strip():
            name_map[normalize(name)] = (nid, name.strip())
            id_map[nid] = name.strip()
    return name_map, id_map


def format_notifs(ids: List[int], id_to_name: Dict[int, str]) -> str:
    names = [id_to_name.get(i, f"<unknown:{i}>") for i in ids]
    return f"{ids} ({', '.join(names)})"


# -------------------------
# Login with retry + remember inputs
# -------------------------

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


# -------------------------
# Main
# -------------------------

def main() -> int:
    print("Uptime Kuma Notification Editor (always dry-run first)")

    # ---- Auth (always ask, GitHub-clean)
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

    # ---- 2FA (remember mode/inputs)
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
        # ---- Filters
        include_tags = parse_csv_list(prompt("Include tag(s) (comma-separated) - empty = ALL monitors", default=""))
        exclude_tags = parse_csv_list(prompt("Exclude tag(s) (comma-separated) - empty = none", default=""))
        tag_mode = prompt_choice("Include tag match mode", ["all", "any"], default="all")

        skip_groups = prompt_yes_no("Skip GROUP monitors (containers)?", default_yes=False)
        only_groups = prompt_yes_no("Only select GROUP monitors (containers)?", default_yes=False)
        only_active = prompt_yes_no("Only modify ACTIVE monitors?", default_yes=False)

        include_set = {normalize(t) for t in include_tags}
        exclude_set = {normalize(t) for t in exclude_tags}

        # ---- Action
        action = prompt_choice("Notification action", ["list", "add", "replace", "remove"], default="list")

        # If list mode, skip notification name input
        if action == "list":
            notif_names = []
        else:
            notif_names = parse_csv_list(
                prompt(f"Notification name(s) to {action.upper()} (comma-separated, must match Kuma names)")
            )
            if not notif_names:
                eprint("ERROR: No notification names provided. Please provide at least one notification name.")
                print("\nReselecting options...\n")
                continue
            print(f"\nYou chose to {action.upper()} these notifications: {notif_names}\n")

        # ---- Connect
        with UptimeKumaApi(url) as api:
            api.timeout = 45

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

            # Fetch notifications
            try:
                notifications = api.get_notifications()
            except Timeout:
                eprint("ERROR: Timed out loading notifications.")
                return 5

            name_map, id_map = build_notification_maps(notifications)

            # For list mode, skip notification validation
            if action != "list":
                missing = [n for n in notif_names if normalize(n) not in name_map]
                if missing:
                    eprint("ERROR: These notification names were not found:")
                    for n in missing:
                        eprint(f"  - {n}")
                    return 6

                target_ids = [name_map[normalize(n)][0] for n in notif_names]
                target_pretty = [name_map[normalize(n)][1] for n in notif_names]
            else:
                target_ids = []
                target_pretty = []

            monitors = api.get_monitors()

            plan: List[Tuple[int, str, List[int], List[int], List[str], List[int]]] = []
            losing_count = 0
            dropped_union: Set[int] = set()
            
            # Diagnostic counter
            monitors_after_filters = 0
            # For list mode, collect monitor info
            list_results: List[Tuple[int, str, List[str], List[int]]] = []

            for m in monitors:
                mid = m.get("id")
                name = m.get("name") or "<unnamed>"

                if not isinstance(mid, int):
                    continue
                
                if only_active and not bool(m.get("active", True)):
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
                
                monitors_after_filters += 1

                current = m.get("notificationIDList") or []
                if not isinstance(current, list):
                    current = []

                # For list mode, just collect the info
                if action == "list":
                    list_results.append((mid, name, sorted(tags), current))
                    continue

                cur_set = set(current)
                tgt_set = set(target_ids)

                if action == "replace":
                    new_set = tgt_set
                elif action == "add":
                    new_set = cur_set.union(tgt_set)
                else:
                    new_set = cur_set.difference(tgt_set)

                new_ids = sorted(new_set)
                dropped = sorted(cur_set.difference(new_set))

                if action == "replace" and dropped:
                    losing_count += 1
                    dropped_union.update(dropped)

                if set(current) != set(new_ids):
                    plan.append((mid, name, current, new_ids, sorted(tags), dropped))

            # ---- List mode or Dry run
            if action == "list":
                print("\n==== MONITOR LIST ====")
                print(f"URL:        {url}")
                print(f"User:       {user}")
                print(f"Found:      {len(list_results)} monitors")
                print("======================================\n")
                
                for mid, name, tags, notif_ids in sorted(list_results, key=lambda x: x[1].lower()):
                    notif_names_list = [id_map.get(i, f"<unknown:{i}>") for i in notif_ids]
                    print(f"[{mid}] {name}")
                    print(f"  Tags:        {tags if tags else '(none)'}")
                    print(f"  Notifications: {notif_names_list if notif_names_list else '(none)'}")
                    print()
            else:
                print("\n==== DRY-RUN: Notification Changes ====")
                print(f"URL:        {url}")
                print(f"User:       {user}")
                print(f"Action:     {action.upper()}")
                print(f"Target:     {target_pretty} (IDs: {target_ids})")
                print(f"Will change:{len(plan)} monitors")
                if len(plan) == 0 and monitors_after_filters > 0:
                    print(f"\nNote: {monitors_after_filters} monitor(s) matched filters but no changes needed.")
                    print("      (They may already have the notification(s) you're trying to add.)")
                print("======================================\n")

            if action == "replace" and losing_count:
                dropped_names = [id_map.get(i, f"<unknown:{i}>") for i in sorted(dropped_union)]
                print("!!! WARNING: REPLACE WILL DROP NOTIFICATIONS !!!")
                print(f"Monitors affected: {losing_count}")
                print(f"Dropped somewhere: {dropped_names}\n")

            for mid, name, cur, new, tags, dropped in plan:
                print(f"[{mid}] {name}")
                print(f"  tags:  {tags}")
                print(f"  notif: {format_notifs(cur, id_map)} -> {format_notifs(new, id_map)}")
                if dropped:
                    print(f"  drop:  {dropped}")

            # For list mode, skip the apply confirmation
            if action == "list":
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

            if not prompt_yes_no(f"\nApply these changes to {len(plan)} monitors NOW?", default_yes=False):
                # Ask if user wants to reselect or abort
                choice = prompt_choice("What would you like to do?", ["reselect", "abort"], default="reselect")
                if choice == "abort":
                    print("Aborted. No changes written.")
                    return 0
                # If reselect, continue the loop
                print("\nReselecting options...\n")
                continue

            if action == "replace":
                typed = input("CONFIRM REPLACE: type REPLACE to proceed: ").strip()
                if typed != "REPLACE":
                    # Ask if user wants to reselect or abort
                    choice = prompt_choice("What would you like to do?", ["reselect", "abort"], default="reselect")
                    if choice == "abort":
                        print("Aborted. No changes written.")
                        return 0
                    # If reselect, continue the loop
                    print("\nReselecting options...\n")
                    continue

            # Apply
            print("\nApplying changes...")
            for mid, _, _, new, _, _ in plan:
                api.edit_monitor(mid, notificationIDList=new)

            print(f"Done. Applied changes to {len(plan)} monitors.")
            
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