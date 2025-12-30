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


def generate_totp_from_secret(secret: str) -> str:
    try:
        import pyotp  # type: ignore
    except Exception:
        raise RuntimeError("pyotp not installed. Run: pip install pyotp")
    return pyotp.TOTP(secret).now()


# -------------------------
# Kuma object helpers
# -------------------------

def is_group_monitor(monitor: dict) -> bool:
    return str(monitor.get("type", "")).strip().lower() == "group"


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


def login_with_retries(api: UptimeKumaApi, user: str, password: str, token: str, retries: int) -> None:
    last = None
    for i in range(retries + 1):
        try:
            api.login(user, password, token=token)
            return
        except Exception as ex:
            last = ex
            if i >= retries:
                raise
            eprint(f"Login attempt {i+1} failed ({ex}). Retrying...")
            time.sleep(1.5)
    raise last  # pragma: no cover


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


def choose_changes() -> List[str]:
    menu = [
        (CHANGE_NOTIFS, "Notifications (add/replace/remove by name)"),
        (CHANGE_INTERVAL, "Heartbeat Interval (seconds)"),
        (CHANGE_MAXRETRIES, "Retries (max retries)"),
        (CHANGE_RETRYINTERVAL, "Heartbeat Retry Interval (seconds)"),
        (CHANGE_RESENDINTERVAL, "Resend Notification if Down X times (0 disables)"),
        (CHANGE_UPSIDEDOWN, "Upside Down Mode (true/false)"),
        (CHANGE_GROUP, "Monitor Group (move to group / clear group)"),
        (CHANGE_TAGS, "Tags (add/replace/remove tags)  ⚠️ API support may vary"),
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
    url = prompt("Uptime Kuma URL (root, e.g. https://kuma.example.com)")
    if not url:
        eprint("ERROR: URL cannot be empty.")
        return 2

    user = prompt("Username")
    if not user:
        eprint("ERROR: Username cannot be empty.")
        return 2

    password = getpass.getpass("Password: ").strip()
    if not password:
        eprint("ERROR: Password cannot be empty.")
        return 2

    # ---- 2FA (interactive, no leaks)
    token = ""
    use_2fa = prompt_yes_no("Is 2FA enabled for this user?", default_yes=True)
    if use_2fa:
        mode = prompt_choice("Provide 2FA as", ["token", "secret"], default="token")
        if mode == "token":
            token = prompt("Enter current 6-digit TOTP token").strip()
        else:
            totp_secret = getpass.getpass("Enter TOTP secret (BASE32, hidden input): ").strip()
            if not totp_secret:
                eprint("ERROR: TOTP secret cannot be empty.")
                return 2
            token = generate_totp_from_secret(totp_secret)

    # ---- Filters
    include_tags = parse_csv_list(prompt("Include tag(s) (comma-separated) - empty = ALL monitors", default=""))
    exclude_tags = parse_csv_list(prompt("Exclude tag(s) (comma-separated) - empty = none", default=""))
    tag_mode = prompt_choice("Include tag match mode", ["all", "any"], default="all")
    skip_groups = prompt_yes_no("Skip GROUP monitors (containers)?", default_yes=True)
    only_active = prompt_yes_no("Only modify ACTIVE monitors?", default_yes=False)

    include_set = {normalize(t) for t in include_tags if t.strip()}
    exclude_set = {normalize(t) for t in exclude_tags if t.strip()}

    # ---- What to change
    selected_changes = choose_changes()
    if not selected_changes:
        print("Nothing selected. Exiting.")
        return 0

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
            eprint("ERROR: No notification names provided.")
            return 2
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
                return 2

    if CHANGE_TAGS in selected_changes:
        print("\n⚠️ Tags editing: API support can differ by Kuma version/library.")
        print("This script will attempt it, but will STOP on first tag edit failure (no silent half-success).")
        tag_action = prompt_choice("Tags action", ["add", "replace", "remove"], default="add")
        tag_names = parse_csv_list(prompt(f"Tag name(s) to {tag_action.upper()} (comma-separated)", default=""))
        if not tag_names:
            eprint("ERROR: No tag names provided.")
            return 2
        print(f"\nYou chose to {tag_action.upper()} these tags: {tag_names}\n")

    # ---- Connect
    socket_timeout = 45
    retries = 2

    with UptimeKumaApi(url) as api:
        api.timeout = socket_timeout
        try_force_websocket(api)

        try:
            login_with_retries(api, user, password, token, retries)
        except Exception as ex:
            eprint(f"ERROR: Login failed: {ex}")
            eprint("Tip: If this is intermittent behind a proxy, try again or increase timeouts/retries in the script.")
            return 4

        # Load notifications (only needed if changing notifications)
        notif_name_map: Dict[str, Tuple[int, str]] = {}
        notif_id_map: Dict[int, str] = {}
        if CHANGE_NOTIFS in selected_changes:
            try:
                notifications = call_with_retries(api.get_notifications, retries, "get_notifications")
            except Timeout as ex:
                eprint(f"ERROR: Timed out waiting for notifications: {ex}")
                return 5
            notif_name_map, notif_id_map = build_notification_maps(notifications)

        monitors = api.get_monitors()

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

        # ---- Build dry-run plan
        # Plan entry: (mid, name, payload, before, after)
        plan: List[Tuple[int, str, Dict[str, Any], Dict[str, Any], Dict[str, Any]]] = []

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
            if skip_groups and is_group_monitor(m):
                continue

            tags = get_monitor_tag_names(m)
            if has_excluded(tags, exclude_set):
                continue
            if not should_include(tags, include_set, tag_mode):
                continue

            payload: Dict[str, Any] = {}
            before: Dict[str, Any] = {}
            after: Dict[str, Any] = {}

            # Group display
            parent = m.get("parent")  # can be int or None
            parent_name = group_id_to_name.get(parent, "") if isinstance(parent, int) else ""
            before["group"] = parent_name or "(none)"
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
                cur_tags = set(tags)
                desired = {normalize(t) for t in tag_names}

                if tag_action == "replace":
                    new_tags = desired
                elif tag_action == "add":
                    new_tags = cur_tags.union(desired)
                else:
                    new_tags = cur_tags.difference(desired)

                after["tags"] = sorted(new_tags)

                # Best-effort payload shape. If Kuma expects different schema, apply will fail and we stop.
                payload["tags"] = [{"name": t} for t in sorted(new_tags)]

            if payload:
                plan.append((mid, str(name), payload, before, after))

        # ---- DRY RUN output (always)
        print("\n==== DRY-RUN PLAN ====")
        print(f"URL:           {url}")
        print(f"User:          {user}")
        print(f"2FA:           {'YES' if token else 'NO token'}")
        print(f"Filter include:{sorted(include_set) if include_set else '(none)'} (mode: {tag_mode})")
        print(f"Filter exclude:{sorted(exclude_set) if exclude_set else '(none)'}")
        print(f"Skip groups:   {skip_groups}")
        print(f"Only active:   {only_active}")
        print(f"Will change:   {len(plan)} monitors")
        print("======================\n")

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
        for mid, name, payload, before, after in plan:
            print(f"[{mid}] {name}")

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

            if "tags" in payload:
                print(f"  tags:          {before.get('tags')} -> {after.get('tags')}")

        if not plan:
            print("\nNothing to change. Exiting.")
            return 0

        # ---- Confirm apply
        if not prompt_yes_no(f"\nApply these changes to {len(plan)} monitors NOW?", default_yes=False):
            print("Aborted. No changes were written.")
            return 0

        # Extra safety latches
        if CHANGE_NOTIFS in selected_changes and notif_action == "replace":
            typed = input("CONFIRM NOTIFICATION REPLACE: type REPLACE to proceed: ").strip()
            if typed != "REPLACE":
                print("Aborted. No changes were written.")
                return 0

        if CHANGE_TAGS in selected_changes:
            typed = input("CONFIRM TAG CHANGES: type TAGS to proceed: ").strip()
            if typed != "TAGS":
                print("Aborted. No changes were written.")
                return 0

        if CHANGE_GROUP in selected_changes and group_mode == "clear":
            typed = input("CONFIRM GROUP CLEAR: type CLEAR to proceed: ").strip()
            if typed != "CLEAR":
                print("Aborted. No changes were written.")
                return 0

        # ---- Apply (stop on first failure)
        print("\nApplying changes (will stop on first error)...")
        changed = 0
        for mid, name, payload, _before, _after in plan:
            try:
                api.edit_monitor(mid, **payload)
            except Exception as ex:
                eprint(f"\nERROR applying to [{mid}] {name}: {ex}")
                eprint("Stopped to avoid partial/unknown state across many monitors.")
                eprint("Tip: if this failed on TAGS, your Kuma/API wrapper may not accept tag writes in this format.")
                return 10
            changed += 1

        print(f"Done. Applied changes to {changed} monitors.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())