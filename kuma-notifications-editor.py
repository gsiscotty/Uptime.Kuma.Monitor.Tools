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

GitHub-safe:
- No hard-coded URLs
- No env vars
- No secrets stored or logged
"""

from __future__ import annotations

import getpass
import sys
import time
from typing import Dict, List, Set, Tuple

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


def generate_totp_from_secret(secret: str) -> str:
    try:
        import pyotp  # type: ignore
    except Exception:
        raise RuntimeError("pyotp not installed. Run: pip install pyotp")
    return pyotp.TOTP(secret).now()


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
    return str(monitor.get("type", "")).strip().lower() == "group"


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
# Main
# -------------------------

def main() -> int:
    print("Uptime Kuma Notification Editor (always dry-run first)")

    # ---- Auth (always ask)
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

    token = ""
    use_2fa = prompt_yes_no("Is 2FA enabled for this user?", default_yes=True)
    if use_2fa:
        mode = prompt_choice("Provide 2FA as", ["token", "secret"], default="token")
        if mode == "token":
            token = prompt("Enter current 6-digit TOTP token").strip()
        else:
            secret = getpass.getpass("Enter TOTP secret (BASE32, hidden input): ").strip()
            token = generate_totp_from_secret(secret)

    # ---- Filters
    include_tags = parse_csv_list(prompt("Include tag(s) (comma-separated) - empty = ALL monitors", default=""))
    exclude_tags = parse_csv_list(prompt("Exclude tag(s) (comma-separated) - empty = none", default=""))
    tag_mode = prompt_choice("Include tag match mode", ["all", "any"], default="all")

    skip_groups = prompt_yes_no("Skip GROUP monitors (containers)?", default_yes=True)
    only_active = prompt_yes_no("Only modify ACTIVE monitors?", default_yes=False)

    include_set = {normalize(t) for t in include_tags}
    exclude_set = {normalize(t) for t in exclude_tags}

    # ---- Action first
    action = prompt_choice("Notification action", ["add", "replace", "remove"], default="add")

    notif_names = parse_csv_list(
        prompt(f"Notification name(s) to {action.upper()} (comma-separated, must match Kuma names)")
    )
    if not notif_names:
        eprint("ERROR: No notification names provided.")
        return 2

    print(f"\nYou chose to {action.upper()} these notifications: {notif_names}\n")

    # ---- Connect
    with UptimeKumaApi(url) as api:
        api.timeout = 45

        try:
            api.login(user, password, token=token)
        except Exception as ex:
            eprint(f"ERROR: Login failed: {ex}")
            return 4

        try:
            notifications = api.get_notifications()
        except Timeout:
            eprint("ERROR: Timed out loading notifications.")
            return 5

        name_map, id_map = build_notification_maps(notifications)

        missing = [n for n in notif_names if normalize(n) not in name_map]
        if missing:
            eprint("ERROR: These notification names were not found:")
            for n in missing:
                eprint(f"  - {n}")
            return 6

        target_ids = [name_map[normalize(n)][0] for n in notif_names]
        target_pretty = [name_map[normalize(n)][1] for n in notif_names]

        monitors = api.get_monitors()

        plan: List[Tuple[int, str, List[int], List[int], List[str], List[int]]] = []
        losing_count = 0
        dropped_union: Set[int] = set()

        for m in monitors:
            mid = m.get("id")
            name = m.get("name") or "<unnamed>"

            if not isinstance(mid, int):
                continue
            if only_active and not bool(m.get("active", True)):
                continue
            if skip_groups and is_group_monitor(m):
                continue

            tags = get_monitor_tag_names(m)
            if has_excluded(tags, exclude_set):
                continue
            if not should_include(tags, include_set, tag_mode):
                continue

            current = m.get("notificationIDList") or []
            if not isinstance(current, list):
                current = []

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

        # ---- Dry run
        print("\n==== DRY-RUN: Notification Changes ====")
        print(f"URL:        {url}")
        print(f"User:       {user}")
        print(f"Action:     {action.upper()}")
        print(f"Target:     {target_pretty} (IDs: {target_ids})")
        print(f"Will change:{len(plan)} monitors")
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

        if not plan:
            print("\nNothing to change. Exiting.")
            return 0

        if not prompt_yes_no(f"\nApply these changes to {len(plan)} monitors NOW?", default_yes=False):
            print("Aborted. No changes written.")
            return 0

        if action == "replace":
            typed = input("CONFIRM REPLACE: type REPLACE to proceed: ").strip()
            if typed != "REPLACE":
                print("Aborted. No changes written.")
                return 0

        print("\nApplying changes...")
        for mid, _, _, new, _, _ in plan:
            api.edit_monitor(mid, notificationIDList=new)

        print(f"Done. Applied changes to {len(plan)} monitors.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
    print("Done. Applied changes to {len(plan)} monitors.")