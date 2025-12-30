#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from typing import Dict, List, Set, Tuple

from uptime_kuma_api import UptimeKumaApi
from uptime_kuma_api.exceptions import Timeout


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


def build_notification_name_map(notifs: List[dict]) -> Dict[str, Tuple[int, str]]:
    out: Dict[str, Tuple[int, str]] = {}
    for n in notifs:
        nid = n.get("id")
        name = n.get("name")
        if isinstance(nid, int) and isinstance(name, str) and name.strip():
            out[normalize(name)] = (nid, name.strip())
    return out


def build_notification_id_map(notifs: List[dict]) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for n in notifs:
        nid = n.get("id")
        name = n.get("name")
        if isinstance(nid, int) and isinstance(name, str) and name.strip():
            out[nid] = name.strip()
    return out


def format_notifs(ids: List[int], id_to_name: Dict[int, str]) -> str:
    names = [id_to_name.get(i, f"<unknown:{i}>") for i in ids]
    return f"{ids} ({', '.join(names)})"


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
    t = monitor.get("type")
    return str(t).strip().lower() == "group"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Interactive Uptime Kuma bulk notification editor (tags + 2FA).")

    p.add_argument("--url", default=os.getenv("KUMA_URL", "").strip())
    p.add_argument("--user", default=os.getenv("KUMA_USER", "").strip())
    p.add_argument("--password", default=os.getenv("KUMA_PASS", "").strip())
    p.add_argument("--totp", default=os.getenv("KUMA_TOTP", "").strip())
    p.add_argument("--totp-secret", default=os.getenv("KUMA_TOTP_SECRET", "").strip())

    p.add_argument("--tag-mode", choices=["all", "any"], default="")
    p.add_argument("--action", choices=["replace", "add", "remove"], default="")

    p.add_argument("--only-active", action="store_true")
    p.add_argument("--skip-groups", action="store_true")

    # socket timeout tuning
    p.add_argument("--socket-timeout", type=int, default=30,
                   help="Socket.IO call timeout seconds (default: 30)")
    p.add_argument("--login-retry", type=int, default=1,
                   help="Retry login N times on timeout (default: 1)")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    # --- Auth first
    url = args.url or prompt("Uptime Kuma URL (root, e.g. https://kuma.gsi.li)")
    user = args.user or prompt("Username")

    password = args.password
    if not password:
        password = getpass.getpass("Password: ").strip()

    totp = args.totp.strip()
    totp_secret = args.totp_secret.strip()

    if not totp and not totp_secret:
        use_2fa = prompt_yes_no("Is 2FA enabled for this user?", default_yes=True)
        if use_2fa:
            mode = prompt_choice("Provide 2FA as", ["token", "secret"], default="token")
            if mode == "token":
                totp = prompt("Enter current 6-digit TOTP token")
            else:
                totp_secret = getpass.getpass("Enter TOTP secret (BASE32, hidden input): ").strip()

    token = ""
    if totp_secret:
        token = generate_totp_from_secret(totp_secret)
    elif totp:
        token = totp.strip()

    # --- Filters
    include_tags = parse_csv_list(prompt("Include tag(s) (comma-separated) - leave empty for ALL monitors", default=""))
    exclude_tags = parse_csv_list(prompt("Exclude tag(s) (comma-separated) - leave empty for none", default=""))
    tag_mode = args.tag_mode.strip().lower() or prompt_choice("Include tag match mode", ["all", "any"], default="all")

    skip_groups = args.skip_groups if args.skip_groups else prompt_yes_no("Skip GROUP monitors (containers)?", default_yes=True)
    only_active = args.only_active if args.only_active else prompt_yes_no("Only modify ACTIVE monitors?", default_yes=False)

    # --- Action first (fixing your UX complaint)
    action = args.action.strip().lower() or prompt_choice("Action on notifications", ["replace", "add", "remove"], default="replace")

    # --- Now notifications (so it reads naturally)
    notif_names = parse_csv_list(prompt(f"Notification name(s) to {action.upper()} (comma-separated, must match Kuma names)"))

    if not notif_names:
        eprint("ERROR: No notifications provided.")
        return 2

    print(f"\nYou chose to {action.upper()} the following notifications: {notif_names}\n")

    include_set = {normalize(t) for t in include_tags if t.strip()}
    exclude_set = {normalize(t) for t in exclude_tags if t.strip()}
    notif_norm = [normalize(n) for n in notif_names]

    # --- Connect
    with UptimeKumaApi(url) as api:
        # Increase call timeout to reduce flaky timeouts behind proxies
        api.timeout = args.socket_timeout

        # Login retry on socket timeout
        for attempt in range(args.login_retry + 1):
            try:
                api.login(user, password, token=token)
                break
            except Exception as ex:
                if attempt >= args.login_retry:
                    eprint(f"ERROR: Login failed after retries: {ex}")
                    eprint("If this is intermittent, your proxy is likely not passing /socket.io properly.")
                    return 4
                eprint(f"Login timeout/error ({ex}). Retrying...")
                time.sleep(1.5)

        # Fetch notifications
        try:
            notif_list = api.get_notifications()
        except Timeout:
            eprint("ERROR: Timed out waiting for notificationList.")
            return 5

        notif_name_map = build_notification_name_map(notif_list)
        notif_id_map = build_notification_id_map(notif_list)

        missing = [notif_names[i] for i, k in enumerate(notif_norm) if k not in notif_name_map]
        if missing:
            eprint("ERROR: These notification names were not found:")
            for x in missing:
                eprint(f"  - {x}")
            eprint("\nAvailable notifications:")
            for n in sorted(notif_list, key=lambda d: str(d.get("name", ""))):
                eprint(f"  - {n.get('name')} (id={n.get('id')}, type={n.get('type')})")
            return 6

        target_ids = [notif_name_map[k][0] for k in notif_norm]
        target_pretty = [notif_name_map[k][1] for k in notif_norm]

        monitors = api.get_monitors()

        # Plan entry: (id, name, cur_ids, new_ids, tags, dropped_ids)
        plan: List[Tuple[int, str, List[int], List[int], List[str], List[int]]] = []
        matched = 0
        losing_count = 0
        dropped_union: Set[int] = set()

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

            matched += 1

            current_ids = m.get("notificationIDList") or []
            if not isinstance(current_ids, list):
                current_ids = []

            current_set = set(current_ids)
            target_set = set(target_ids)

            if action == "replace":
                new_set = target_set
            elif action == "add":
                new_set = current_set.union(target_set)
            else:
                new_set = current_set.difference(target_set)

            new_ids = sorted(new_set)
            dropped = sorted(current_set.difference(new_set))

            if action == "replace" and dropped:
                losing_count += 1
                dropped_union.update(dropped)

            if set(current_ids) != set(new_ids):
                plan.append((mid, name, current_ids, new_ids, sorted(tags), dropped))

        # --- ALWAYS DRY RUN first
        print("\n==== DRY-RUN: Bulk Notification Plan ====")
        print(f"URL:           {url}")
        print(f"User:          {user}")
        print(f"2FA:           {'YES (token provided/generated)' if token else 'NO token'}")
        print(f"Action:        {action.upper()}")
        print(f"Selected notif:{target_pretty} (IDs: {target_ids})")
        print(f"Include tags:  {sorted(include_set) if include_set else '(none)'} (mode: {tag_mode})")
        print(f"Exclude tags:  {sorted(exclude_set) if exclude_set else '(none)'}")
        print(f"Only active:   {only_active}")
        print(f"Skip groups:   {skip_groups}")
        print(f"Matched:       {matched} monitors")
        print(f"Will change:   {len(plan)} monitors")
        print("========================================\n")

        if action == "replace" and losing_count > 0:
            dropped_list = sorted(dropped_union)
            dropped_names = [notif_id_map.get(i, f"<unknown:{i}>") for i in dropped_list]
            print("!!! WARNING: REPLACE MODE WILL DROP NOTIFICATIONS !!!")
            print(f"Monitors that would lose at least one notification: {losing_count}")
            print(f"Notifications that would be dropped somewhere: {dropped_list} ({', '.join(dropped_names)})")
            print("If you meant 'keep existing + add Monitor GSI', use ADD.\n")

        for mid, name, cur, new, tags, dropped in plan:
            print(f"[{mid}] {name}")
            print(f"  tags:  {tags if tags else '(none)'}")
            print(f"  notif: {format_notifs(cur, notif_id_map)}  ->  {format_notifs(new, notif_id_map)}")
            if action == "replace" and dropped:
                dropped_names = [notif_id_map.get(i, f"<unknown:{i}>") for i in dropped]
                print(f"  drop:  {dropped} ({', '.join(dropped_names)})")

        if not plan:
            print("\nNothing to change. Exiting.")
            return 0

        # Confirm
        if not prompt_yes_no(f"\nApply these {len(plan)} changes NOW?", default_yes=False):
            print("Aborted. No changes were written.")
            return 0

        # Extra replace confirmation
        if action == "replace":
            typed = input("REPLACE MODE CONFIRMATION: type REPLACE to proceed: ").strip()
            if typed != "REPLACE":
                print("Aborted. Confirmation phrase did not match. No changes were written.")
                return 0

        # Apply
        print("\nApplying changes...")
        changed = 0
        for mid, _name, _cur, new, _tags, _dropped in plan:
            api.edit_monitor(mid, notificationIDList=new)
            changed += 1

        print(f"Done. Applied changes to {changed} monitors.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())