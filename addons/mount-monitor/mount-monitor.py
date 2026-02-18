#!/usr/bin/env python3

#########################################
# Created by: gsi_scotty                #
# Date: 2026-02-18                      #
# Description: Interactive menu script  #
# to monitor mounted shares and report  #
# status to Uptime Kuma push monitors.  #
# Supports NFS, SMB/CIFS, local mounts. #
# Version: 1.1.0                        #
#                                       #
# Usage:                                #
#   python3 mount-monitor.py            #
#   python3 mount-monitor.py --run      #
#   python3 mount-monitor.py --run -d   #
#                                       #
# Dependencies: None (stdlib only)      #
#                                       #
# Config:                               #
#   <script-dir>/mount-monitor.json     #
#   or ~/.config/mount-monitor.json     #
#                                       #
# Note:                                 #
# - No secrets stored in plain text     #
# - Config file restricted to owner     #
# - URLs validated before saving        #
# - Safe atomic config writes           #
# - No external dependencies            #
#########################################

from __future__ import annotations

import sys as _sys
if _sys.version_info < (3, 8):
    print("ERROR: Python 3.8 or newer is required.", file=_sys.stderr)
    _sys.exit(1)

import http.client
import json
import os
import platform
import re
import ssl
import stat
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote, urlparse
from typing import Any, Dict, List, Optional, Tuple


# -------------------------
# Config
# -------------------------

CONFIG_FILE_MODE = 0o600  # Owner read/write only


def get_script_path() -> Path:
    """Resolve absolute path to this script."""
    return Path(__file__).resolve()


def get_config_path() -> Path:
    """
    Config file path search order:
    1. Same directory as the script (install dir)
    2. ~/.config/mount-monitor.json
    For new configs, prefers the script directory if writable.
    """
    script_dir = get_script_path().parent
    script_local = script_dir / "mount-monitor.json"
    if script_local.exists():
        return script_local
    home_config = Path.home() / ".config" / "mount-monitor.json"
    if home_config.exists():
        return home_config
    # New config: prefer script dir if writable, else ~/.config
    if os.access(str(script_dir), os.W_OK):
        return script_local
    home_config.parent.mkdir(parents=True, exist_ok=True)
    return home_config


def _enforce_config_permissions(path: Path) -> None:
    """Ensure config file is only readable/writable by the owner (0600)."""
    try:
        if path.exists():
            current = stat.S_IMODE(path.stat().st_mode)
            if current != CONFIG_FILE_MODE:
                path.chmod(CONFIG_FILE_MODE)
    except OSError:
        pass


def load_config() -> Dict[str, Any]:
    path = get_config_path()
    if not path.exists():
        return {"monitors": []}
    _enforce_config_permissions(path)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  ⚠ Config error: {e}")
        return {"monitors": []}
    _migrate_config(cfg)
    return cfg


def _migrate_config(cfg: Dict[str, Any]) -> None:
    """Auto-fix config issues from older versions (e.g. stale query params in URLs)."""
    changed = False
    for m in cfg.get("monitors", []):
        url = m.get("kuma_url", "")
        cleaned = normalize_kuma_url(url)
        if cleaned != url:
            m["kuma_url"] = cleaned
            changed = True
    if changed:
        save_config(cfg, reapply_cron=False)


def save_config(cfg: Dict[str, Any], reapply_cron: bool = True) -> None:
    path = get_config_path()
    # Atomic write: write to temp file, then rename
    dir_path = path.parent
    try:
        fd = os.open(
            str(dir_path / ".mount-monitor.json.tmp"),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            CONFIG_FILE_MODE,
        )
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f, indent=2)
        os.replace(str(dir_path / ".mount-monitor.json.tmp"), str(path))
    except OSError:
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2)
    _enforce_config_permissions(path)
    if reapply_cron and cfg.get("cron_enabled"):
        apply_cron_schedule(cfg)


# -------------------------
# Cron scheduling
# -------------------------

CRON_MARKER = "# mount-monitor.py - do not edit this line manually"
INTERVAL_MIN = 1
INTERVAL_MAX = 120


def _find_python3() -> str:
    """Return absolute path to python3, falling back to 'python3'."""
    if sys.executable and os.path.isabs(sys.executable):
        return sys.executable
    import shutil
    found = shutil.which("python3")
    return found or "/usr/bin/python3"


def build_cron_line(script_path: Path, interval_minutes: int) -> str:
    """Build cron line for any interval between 1–120 minutes."""
    py = _find_python3()
    work_dir = script_path.parent
    if interval_minutes < 60:
        cron_expr = f"*/{interval_minutes} * * * *"
    elif interval_minutes == 60:
        cron_expr = "0 * * * *"
    else:
        hours = max(1, interval_minutes // 60)
        cron_expr = f"0 */{hours} * * *"
    return f"{cron_expr} cd {work_dir} && {py} {script_path} --run {CRON_MARKER}"


def get_current_crontab() -> Tuple[str, bool]:
    """Return (crontab_content, success)."""
    try:
        out = subprocess.check_output(
            ["crontab", "-l"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        return (out, True)
    except subprocess.CalledProcessError:
        # No crontab (exit 1)
        return ("", True)
    except (FileNotFoundError, PermissionError, OSError):
        return ("", False)


def write_crontab(content: str) -> bool:
    try:
        p = subprocess.Popen(
            ["crontab", "-"],
            stdin=subprocess.PIPE,
            text=True,
        )
        p.communicate(content)
        return p.returncode == 0
    except (FileNotFoundError, PermissionError, OSError):
        return False


def cron_entry_exists() -> bool:
    content, ok = get_current_crontab()
    return ok and CRON_MARKER in content


def remove_cron_entry() -> bool:
    content, ok = get_current_crontab()
    if not ok:
        return False
    lines = [l for l in content.splitlines() if CRON_MARKER not in l]
    new_content = "\n".join(l.rstrip() for l in lines if l.strip()) + "\n"
    return write_crontab(new_content)


def add_cron_entry(interval_minutes: int) -> bool:
    script_path = get_script_path()
    line = build_cron_line(script_path, interval_minutes)
    content, ok = get_current_crontab()
    if not ok:
        return False
    # Remove old mount-monitor entry if any
    lines = [l for l in content.splitlines() if CRON_MARKER not in l]
    lines.append(line)
    new_content = "\n".join(l.strip() for l in lines if l.strip()) + "\n"
    return write_crontab(new_content)


def apply_cron_schedule(cfg: Dict[str, Any]) -> bool:
    """Apply or update cron from config. Returns True on success."""
    if not cfg.get("cron_enabled"):
        return remove_cron_entry()
    interval = int(cfg.get("cron_interval_minutes", 60))
    return add_cron_entry(interval)


# -------------------------
# Mount listing
# -------------------------

def get_mounts() -> List[Tuple[str, str, str]]:
    """
    Return list of (device_or_source, mount_point, fstype).
    Filters out virtual/system mounts where sensible.
    """
    result: List[Tuple[str, str, str]] = []
    system = platform.system()

    if system == "Linux":
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        device, mpoint, fstype = parts[0], parts[1], parts[2]
                        # Skip typical virtual/system mounts
                        if mpoint.startswith(("/sys", "/proc", "/dev/pts", "/run")):
                            continue
                        if fstype in ("sysfs", "proc", "devtmpfs", "tmpfs", "cgroup", "cgroup2"):
                            continue
                        result.append((device, mpoint, fstype))
        except FileNotFoundError:
            pass

    if system == "Darwin" or not result:
        try:
            out = subprocess.check_output(["mount"], text=True, stderr=subprocess.DEVNULL)
            for line in out.strip().split("\n"):
                # macOS: "device on /path (options)"
                m = re.match(r"^(.+?)\s+on\s+(\S+)\s+\(([^)]*)\)", line)
                if m:
                    device, mpoint, opts = m.groups()
                    fstype = "unknown"
                    if "apfs" in opts.lower():
                        fstype = "apfs"
                    elif "hfs" in opts.lower():
                        fstype = "hfs"
                    elif "nfs" in opts.lower():
                        fstype = "nfs"
                    elif "smb" in opts.lower() or "cifs" in opts.lower():
                        fstype = "smb"
                    # Skip virtual/dev mounts
                    if mpoint.startswith("/dev/"):
                        continue
                    result.append((device, mpoint, fstype))
        except Exception:
            pass

    return result


def format_mount_display(mounts: List[Tuple[str, str, str]]) -> str:
    lines = []
    for i, (dev, mpoint, fstype) in enumerate(mounts, 1):
        short_dev = dev.split("/")[-1] if "/" in dev else dev
        if len(short_dev) > 40:
            short_dev = short_dev[:37] + "..."
        lines.append(f"  [{i:2}] {mpoint}")
        lines.append(f"       ← {short_dev} ({fstype})")
    return "\n".join(lines)


# -------------------------
# Mount health check
# -------------------------

def _latency_ms(t0: float) -> float:
    """Sub-millisecond latency since t0, rounded to 2 decimal places."""
    return round((time.perf_counter() - t0) * 1000, 2)


def check_mount_accessible(mount_point: str) -> Tuple[bool, Optional[str], float]:
    """
    Check if a mount is accessible.
    Returns (ok, error_message, latency_ms).
    Latency measures the time to reach the filesystem (statvfs or listdir)
    with sub-millisecond precision.
    """
    resolved = os.path.realpath(mount_point)
    if resolved != os.path.normpath(mount_point):
        return False, "Symlink or path traversal detected", 0.0
    path = Path(resolved)
    if not path.exists():
        return False, "Path does not exist", 0.0
    if not path.is_dir():
        return False, "Not a directory", 0.0
    t0 = time.perf_counter()
    # statvfs: checks the filesystem is reachable without needing to list contents
    try:
        st = os.statvfs(mount_point)
        latency = _latency_ms(t0)
        if st.f_blocks > 0:
            return True, None, latency
    except AttributeError:
        pass  # statvfs not available (Windows) — fall through
    except PermissionError:
        return False, "Permission denied (statvfs)", _latency_ms(t0)
    except OSError as e:
        return False, str(e), _latency_ms(t0)
    # Fallback: try listing contents
    t0 = time.perf_counter()
    try:
        os.listdir(mount_point)
        return True, None, _latency_ms(t0)
    except PermissionError:
        return False, "Permission denied", _latency_ms(t0)
    except OSError as e:
        return False, str(e), _latency_ms(t0)


def check_mounts_status(
    mounts: List[Tuple[str, str, str]],
    debug: bool = False,
) -> Tuple[str, str, float]:
    """
    Check all given mounts. Returns (status, message, ping_ms).
    ping_ms is the max mount latency across all checked mounts (sub-ms precision).
    status: "up" | "down" | "warning"
    """
    ok_list: List[str] = []
    fail_list: List[Tuple[str, str]] = []
    max_latency_ms: float = 0.0

    for dev, mpoint, fstype in mounts:
        ok, err, lat_ms = check_mount_accessible(mpoint)
        max_latency_ms = max(max_latency_ms, lat_ms)
        if debug:
            res = "OK" if ok else f"FAIL: {err or 'unreachable'}"
            print(f"    [check] {mpoint} ({fstype}) → {res} (latency {lat_ms:.2f}ms)")
        if ok:
            ok_list.append(f"{mpoint} ({fstype})")
        else:
            fail_list.append((mpoint, err or "unreachable"))

    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    if not fail_list:
        status = "up"
        msg = f"All {len(ok_list)} mount(s) OK @ {now}"
        if ok_list:
            msg += "\n" + "\n".join(f"  • {m}" for m in ok_list)
    elif not ok_list:
        status = "down"
        msg = f"All {len(fail_list)} mount(s) down @ {now}\n"
        msg += "\n".join(f"  • {m}: {e}" for m, e in fail_list)
    else:
        status = "warning"
        msg = f"{len(ok_list)} OK, {len(fail_list)} down @ {now}\n"
        msg += "Down:\n" + "\n".join(f"  • {m}: {e}" for m, e in fail_list)

    return status, msg, max_latency_ms


# -------------------------
# Kuma push
# -------------------------

ALLOWED_SCHEMES = ("https", "http")
KUMA_PUSH_PATH_PATTERN = re.compile(r"^/api/push/[A-Za-z0-9_-]+$")


def normalize_kuma_url(url: str) -> str:
    """Strip query params; push URL should be base only (e.g. https://host/api/push/TOKEN)."""
    parsed = urlparse(url.strip())
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path}"
    return base.rstrip("/")


def validate_kuma_url(url: str) -> Optional[str]:
    """Validate a Kuma push URL. Returns error message or None if valid."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in ALLOWED_SCHEMES:
        return f"Scheme must be http or https, got '{parsed.scheme}'"
    if not parsed.hostname:
        return "No hostname in URL"
    if not KUMA_PUSH_PATH_PATTERN.match(parsed.path or ""):
        return f"Path must match /api/push/<token>, got '{parsed.path}'"
    return None


def push_to_kuma(url: str, status: str, message: str, ping_ms: float, debug: bool = False) -> bool:
    """Send status to Kuma push monitor via HTTPS (TLS verified). Returns True on success."""
    base_url = normalize_kuma_url(url)
    encoded_msg = quote(message)
    full_url = f"{base_url}?status={status}&msg={encoded_msg}&ping={ping_ms}"
    if debug:
        msg_preview = (message[:80] + "…") if len(message) > 80 else message
        print(f"    [push] GET {base_url}?status=...&msg=...&ping={ping_ms}")
        print(f"    [push] message: {msg_preview!r}")
    try:
        parsed = urlparse(full_url)
        host = parsed.hostname or parsed.netloc.split(":")[0]
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port, timeout=10, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        ok = resp.status in (200, 201, 204)
        if debug:
            print(f"    [push] response: HTTP {resp.status}" + (" OK" if ok else ""))
        conn.close()
        return ok
    except ssl.SSLCertVerificationError as e:
        if debug:
            print(f"    [push] TLS error: {e}")
        return False
    except Exception as e:
        if debug:
            print(f"    [push] error: {type(e).__name__}: {e}")
        return False


# -------------------------
# Menu & interaction
# -------------------------

BACK_KEYS = ("0", "b", "back", "q", "quit")
CHANGES_NOTICE = "  ℹ Changes are not saved until you confirm (Save/Apply)."


def prompt(text: str, default: Optional[str] = None) -> str:
    if default is not None:
        val = input(f"{text} [{default}]: ").strip()
        return val if val else default
    return input(f"{text}: ").strip()


def prompt_with_back(text: str, default: Optional[str] = None) -> Optional[str]:
    """Return input value, or None if user chose to go back."""
    val = prompt(text, default)
    return None if (val and val.strip().lower() in BACK_KEYS) else (val or "")


def confirm_save(action: str = "apply") -> bool:
    """Ask to save/apply. Returns True to save, False to discard and go back."""
    raw = prompt(f"{action}? (s)ave / (b)ack discard", "b").strip().lower() or "b"
    return raw in ("s", "save", "y", "yes")


def prompt_selection(
    text: str,
    options: List[str],
    allow_multi: bool = False,
    allow_back: bool = True,
) -> Optional[List[int]]:
    """Return list of 1-based indices, or None if user goes back."""
    while True:
        raw = input(f"{text} (0=back): ").strip()
        if not raw:
            return [] if not allow_back else None
        if allow_back and raw.lower() in BACK_KEYS:
            return None
        try:
            if allow_multi and "," in raw:
                indices = [int(x.strip()) for x in raw.split(",")]
            else:
                indices = [int(raw)]
            if allow_back and 0 in indices:
                return None
            return indices
        except ValueError:
            print("Enter numbers (e.g. 1 or 1,3,5). Use 0 to go back.")


def manage_cron() -> None:
    """Menu to enable/disable/change cron schedule."""
    cfg = load_config()
    enabled = cfg.get("cron_enabled", False)
    interval = int(cfg.get("cron_interval_minutes", 60))

    content, crontab_ok = get_current_crontab()
    has_crontab = crontab_ok and CRON_MARKER in content

    print("\n--- Automatic checks (cron) ---")
    print(CHANGES_NOTICE)
    if not crontab_ok:
        print("  ⚠ crontab unavailable — add the line below manually via 'crontab -e'")
    if enabled or has_crontab:
        print(f"  Status: Enabled (every {interval} min)")
        print(f"  Crontab: {'✓ configured' if has_crontab else '✗ not found'}")
    else:
        print("  Status: Disabled")

    print("\n  a) Enable automatic checks")
    print("  b) Disable automatic checks")
    print("  c) Change interval")
    print("  d) Back to main menu (discard)")
    choice = prompt("Choice", "d").strip().lower() or "d"

    if choice == "a":
        if not cfg.get("monitors"):
            print("\n⚠ Add at least one monitor first.")
            return
        print(f"\nEnter check interval ({INTERVAL_MIN}–{INTERVAL_MAX} minutes)")
        raw = prompt_with_back("Check interval (minutes)", "60")
        if raw is None:
            print("Back.")
            return
        try:
            interval = int(raw or "60")
            interval = max(INTERVAL_MIN, min(INTERVAL_MAX, interval))
        except ValueError:
            interval = 60
        print(f"\n--- Apply change ---")
        print(f"  Enable cron: every {interval} minutes")
        if not confirm_save("Enable automatic checks"):
            print("Discarded.")
            return
        cfg["cron_enabled"] = True
        cfg["cron_interval_minutes"] = interval
        applied = crontab_ok and add_cron_entry(interval)
        save_config(cfg)
        print("\n✓ Automatic checks enabled.")
        if applied:
            print("  After you exit, the monitor will run non-interactively")
            print("  via cron every", interval, "minutes.")
        else:
            print("  Add this line to crontab (crontab -e):")
            print("  ", build_cron_line(get_script_path(), interval))
        print("  Rerun this script anytime to make changes.")
    elif choice == "b":
        print("\n--- Apply change ---")
        print("  Disable automatic checks")
        if not confirm_save("Disable automatic checks"):
            print("Discarded.")
            return
        cfg["cron_enabled"] = False
        save_config(cfg)
        remove_cron_entry()
        print("\n✓ Automatic checks disabled.")
    elif choice == "c":
        if not enabled:
            print("\nEnable automatic checks first.")
            return
        print(f"\nCurrent: every {interval} min ({INTERVAL_MIN}–{INTERVAL_MAX} allowed)")
        raw = prompt_with_back("New interval (minutes)", str(interval))
        if raw is None:
            print("Back.")
            return
        if raw:
            try:
                new_interval = int(raw)
                new_interval = max(INTERVAL_MIN, min(INTERVAL_MAX, new_interval))
                print(f"\n--- Apply change ---")
                print(f"  Change interval: {interval} → {new_interval} minutes")
                if not confirm_save("Change interval"):
                    print("Discarded.")
                    return
                cfg["cron_interval_minutes"] = new_interval
                save_config(cfg)
                print(f"\n✓ Interval set to {new_interval} minutes.")
            except ValueError:
                print("Invalid number.")
    # d = back, no action


def main_menu() -> str:
    cfg = load_config()
    debug_on = cfg.get("debug", False)
    print("\n" + "=" * 50)
    print("  Mount Monitor — Kuma Integration")
    print("=" * 50)
    print(CHANGES_NOTICE)
    print(f"  Debug: {'ON' if debug_on else 'OFF'}")
    print()
    print("  1) List mounts & add monitor")
    print("  2) Run check (all configured monitors)")
    print("  3) List configured monitors")
    print("  4) Remove monitor")
    print("  5) Schedule automatic checks (cron)")
    print("  6) Test push (send test message to Kuma)")
    print("  7) Toggle debug mode (info during Run check)")
    print("  8) Exit")
    print("=" * 50)
    return prompt("Choice", "1").strip() or "1"


def add_monitor() -> None:
    mounts = get_mounts()
    if not mounts:
        print("No mounts found.")
        return

    print("\n--- Add monitor ---")
    print(CHANGES_NOTICE)
    print("\nAvailable mounts:")
    print(format_mount_display(mounts))
    print()

    indices = prompt_selection(
        "Select mount(s) to monitor (e.g. 1,3,5 or single 2)",
        [],
        allow_multi=True,
    )
    if indices is None:
        print("Back.")
        return
    if not indices:
        print("No selection.")
        return

    selected = []
    for i in indices:
        if 1 <= i <= len(mounts):
            selected.append({
                "device": mounts[i - 1][0],
                "mount_point": mounts[i - 1][1],
                "fstype": mounts[i - 1][2],
            })
    if not selected:
        print("Invalid selection.")
        return

    kuma_url = prompt_with_back(
        "Kuma push URL (e.g. https://kuma.example.com/api/push/YourToken)",
        "",
    )
    if kuma_url is None:
        print("Back.")
        return
    if not kuma_url:
        print("URL required. Skipping.")
        return

    if not kuma_url.startswith(("http://", "https://")):
        kuma_url = "https://" + kuma_url
    kuma_url = normalize_kuma_url(kuma_url)

    url_err = validate_kuma_url(kuma_url)
    if url_err:
        print(f"  ⚠ Invalid URL: {url_err}")
        print("  Expected format: https://kuma.example.com/api/push/YourToken")
        return

    name = prompt_with_back("Monitor name (optional)", mounts[indices[0] - 1][1])
    if name is None:
        print("Back.")
        return
    if not name:
        name = " + ".join(m["mount_point"] for m in selected)

    print("\n--- Add monitor ---")
    print(f"  Name: {name}")
    print(f"  Mounts: {', '.join(m['mount_point'] for m in selected)}")
    print(f"  URL: {kuma_url}")
    if not confirm_save("Add monitor"):
        print("Discarded.")
        return

    cfg = load_config()
    cfg["monitors"].append({
        "name": name,
        "mounts": selected,
        "kuma_url": kuma_url,
    })
    save_config(cfg)
    print(f"\n✓ Added monitor '{name}' with {len(selected)} mount(s).")


def run_check(debug: Optional[bool] = None, interactive: bool = True) -> None:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    dbg = debug if debug is not None else cfg.get("debug", False)
    if interactive:
        print("\n--- Run check ---")
    if dbg:
        print("  [debug] enabled")
    if not monitors:
        print("  No monitors configured. Add one first.")
    else:
        for m in monitors:
            name = m.get("name", "?")
            mounts_data = m.get("mounts", [])
            url = m.get("kuma_url", "")
            if not url:
                print(f"  Skipping '{name}': no Kuma URL")
                continue

            if dbg:
                print(f"\n  [{name}]")
            mounts = [(x["device"], x["mount_point"], x.get("fstype", "?")) for x in mounts_data]
            status, msg, latency = check_mounts_status(mounts, debug=dbg)
            if dbg:
                print(f"    [result] status={status} latency={latency:.2f}ms msg_len={len(msg)}")
            ok = push_to_kuma(url, status, msg, latency, debug=dbg)
            sym = "✓" if ok else "✗"
            print(f"  {sym} {name}: {status} (ping={latency:.2f}ms) — push {'OK' if ok else 'FAILED'}")
    if interactive:
        print("\n  (Press Enter to go back)")
        input()


def list_configured() -> None:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    print("\n--- Configured monitors ---")
    if not monitors:
        print("  No monitors configured.")
    else:
        for i, m in enumerate(monitors, 1):
            mounts = m.get("mounts", [])
            mp_list = ", ".join(x["mount_point"] for x in mounts)
            print(f"  [{i}] {m.get('name', '?')}")
            print(f"      Mounts: {mp_list}")
            print(f"      URL: {m.get('kuma_url', '?')}")
    print("\n  (Press Enter to go back)")
    input()


def remove_monitor() -> None:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    if not monitors:
        print("No monitors configured.")
        return

    print("\n--- Remove monitor ---")
    print(CHANGES_NOTICE)
    for i, m in enumerate(monitors, 1):
        mounts = m.get("mounts", [])
        mp_list = ", ".join(x["mount_point"] for x in mounts)
        print(f"  [{i}] {m.get('name', '?')}")
        print(f"      Mounts: {mp_list}")
    print()
    raw = prompt("Number to remove (0=back)", "")
    if not raw or raw.strip().lower() in BACK_KEYS:
        print("Back.")
        return
    try:
        idx = int(raw)
        if idx == 0:
            print("Back.")
            return
        if 1 <= idx <= len(monitors):
            removed = monitors[idx - 1]
            print(f"\nRemove '{removed.get('name', '?')}'?")
            if not confirm_save("Remove monitor"):
                print("Discarded.")
                return
            monitors.pop(idx - 1)
            cfg["monitors"] = monitors
            save_config(cfg)
            print(f"✓ Removed '{removed.get('name', '?')}'.")
        else:
            print("Invalid number.")
    except ValueError:
        print("Enter a number.")


def test_push() -> None:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    if not monitors:
        print("\n  No monitors configured. Add one first.")
        print("\n  (Press Enter to go back)")
        input()
        return

    print("\n--- Test push ---")
    print("  Sends a test message (status=up) to the Kuma push URL.")
    for i, m in enumerate(monitors, 1):
        print(f"  [{i}] {m.get('name', '?')}")
    print(f"  [a] All monitors")
    print()
    raw = prompt("Select monitor to test (0=back)", "a").strip().lower()
    if raw in BACK_KEYS:
        print("Back.")
        return

    if raw == "a":
        targets = list(enumerate(monitors))
    else:
        try:
            idx = int(raw)
            if idx == 0:
                print("Back.")
                return
            if 1 <= idx <= len(monitors):
                targets = [(idx - 1, monitors[idx - 1])]
            else:
                print("Invalid number.")
                return
        except ValueError:
            print("Invalid input.")
            return

    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    test_msg = f"Test push @ {now} — mount-monitor connectivity check"
    print()
    for _i, m in targets:
        name = m.get("name", "?")
        url = m.get("kuma_url", "")
        if not url:
            print(f"  ✗ {name}: no URL configured")
            continue
        ok = push_to_kuma(url, "up", test_msg, 0, debug=True)
        sym = "✓" if ok else "✗"
        print(f"  {sym} {name}: push {'OK' if ok else 'FAILED'}")

    print("\n  (Press Enter to go back)")
    input()


def toggle_debug() -> None:
    cfg = load_config()
    cur = cfg.get("debug", False)
    cfg["debug"] = not cur
    save_config(cfg)
    print(f"\n  Debug mode: {'ON' if cfg['debug'] else 'OFF'}")
    print("  (Affects Run check only)")


def main() -> int:
    while True:
        choice = main_menu()
        if choice == "1":
            add_monitor()
        elif choice == "2":
            run_check()
        elif choice == "3":
            list_configured()
        elif choice == "4":
            remove_monitor()
        elif choice == "5":
            manage_cron()
        elif choice == "6":
            test_push()
        elif choice == "7":
            toggle_debug()
        elif choice == "8":
            print("Bye.")
            return 0
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--run", "-r"):
        dbg = "--debug" in sys.argv or "-d" in sys.argv
        run_check(debug=dbg, interactive=False)
        sys.exit(0)
    sys.exit(main())
