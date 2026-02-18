#!/usr/bin/env python3

#########################################
# Created by: gsi_scotty                #
# Date: 2026-02-18                      #
# Description: Interactive menu script  #
# to monitor Ubuntu/Unix storage and    #
# SMART health and report to Kuma.      #
# Version: 1.0.0                        #
#                                       #
# Usage:                                #
#   python3 unix-storage-monitor.py     #
#   python3 unix-storage-monitor.py --run
#   python3 unix-storage-monitor.py --run -d
#########################################

from __future__ import annotations

import sys as _sys

if _sys.version_info < (3, 8):
    print("ERROR: Python 3.8 or newer is required.", file=_sys.stderr)
    _sys.exit(1)

import http.client
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse


CONFIG_FILE_MODE = 0o600
CRON_MARKER = "# unix-storage-monitor.py - do not edit this line manually"
INTERVAL_MIN = 1
INTERVAL_MAX = 120
CHECK_MODES = ("smart", "storage", "both")
BACK_KEYS = ("0", "b", "back", "q", "quit")
CHANGES_NOTICE = "  ℹ Changes are not saved until you confirm (Save/Apply)."
ALLOWED_SCHEMES = ("https", "http")
KUMA_PUSH_PATH_PATTERN = re.compile(r"^/api/push/[A-Za-z0-9_-]+$")
USAGE_WARN_PCT = 90
USAGE_DOWN_PCT = 98


def get_script_path() -> Path:
    return Path(__file__).resolve()


def get_config_path() -> Path:
    script_dir = get_script_path().parent
    script_local = script_dir / "unix-storage-monitor.json"
    if script_local.exists():
        return script_local
    home_config = Path.home() / ".config" / "unix-storage-monitor.json"
    if home_config.exists():
        return home_config
    if os.access(str(script_dir), os.W_OK):
        return script_local
    home_config.parent.mkdir(parents=True, exist_ok=True)
    return home_config


def _enforce_config_permissions(path: Path) -> None:
    try:
        if path.exists():
            current = stat.S_IMODE(path.stat().st_mode)
            if current != CONFIG_FILE_MODE:
                path.chmod(CONFIG_FILE_MODE)
    except OSError:
        pass


def normalize_kuma_url(url: str) -> str:
    parsed = urlparse(url.strip())
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path}"
    return base.rstrip("/")


def validate_kuma_url(url: str) -> Optional[str]:
    parsed = urlparse(url.strip())
    if parsed.scheme not in ALLOWED_SCHEMES:
        return f"Scheme must be http or https, got '{parsed.scheme}'"
    if not parsed.hostname:
        return "No hostname in URL"
    if not KUMA_PUSH_PATH_PATTERN.match(parsed.path or ""):
        return f"Path must match /api/push/<token>, got '{parsed.path}'"
    return None


def load_config() -> Dict[str, Any]:
    path = get_config_path()
    if not path.exists():
        return {"monitors": []}
    _enforce_config_permissions(path)
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  ⚠ Config error: {e}")
        return {"monitors": []}

    changed = False
    for monitor in cfg.get("monitors", []):
        cleaned = normalize_kuma_url(monitor.get("kuma_url", ""))
        if cleaned != monitor.get("kuma_url", ""):
            monitor["kuma_url"] = cleaned
            changed = True
        mode = str(monitor.get("check_mode", "both")).lower()
        if mode not in CHECK_MODES:
            monitor["check_mode"] = "both"
            changed = True
    if changed:
        save_config(cfg, reapply_cron=False)
    return cfg


def save_config(cfg: Dict[str, Any], reapply_cron: bool = True) -> None:
    path = get_config_path()
    tmp_path = path.parent / ".unix-storage-monitor.json.tmp"
    try:
        fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, CONFIG_FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.replace(str(tmp_path), str(path))
    except OSError:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    _enforce_config_permissions(path)
    if reapply_cron and cfg.get("cron_enabled"):
        apply_cron_schedule(cfg)


def _find_python3() -> str:
    if sys.executable and os.path.isabs(sys.executable):
        return sys.executable
    import shutil

    found = shutil.which("python3")
    return found or "/usr/bin/python3"


def build_cron_line(script_path: Path, interval_minutes: int) -> str:
    py = _find_python3()
    work_dir = script_path.parent
    if interval_minutes < 60:
        expr = f"*/{interval_minutes} * * * *"
    elif interval_minutes == 60:
        expr = "0 * * * *"
    else:
        expr = f"0 */{max(1, interval_minutes // 60)} * * *"
    return f"{expr} cd {work_dir} && {py} {script_path} --run {CRON_MARKER}"


def get_current_crontab() -> Tuple[str, bool]:
    try:
        out = subprocess.check_output(["crontab", "-l"], text=True, stderr=subprocess.DEVNULL)
        return out, True
    except subprocess.CalledProcessError:
        return "", True
    except (FileNotFoundError, PermissionError, OSError):
        return "", False


def write_crontab(content: str) -> bool:
    try:
        p = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
        p.communicate(content)
        return p.returncode == 0
    except (FileNotFoundError, PermissionError, OSError):
        return False


def remove_cron_entry() -> bool:
    content, ok = get_current_crontab()
    if not ok:
        return False
    lines = [l for l in content.splitlines() if CRON_MARKER not in l]
    return write_crontab("\n".join(l for l in lines if l.strip()) + "\n")


def add_cron_entry(interval_minutes: int) -> bool:
    content, ok = get_current_crontab()
    if not ok:
        return False
    line = build_cron_line(get_script_path(), interval_minutes)
    lines = [l for l in content.splitlines() if CRON_MARKER not in l]
    lines.append(line)
    return write_crontab("\n".join(l for l in lines if l.strip()) + "\n")


def apply_cron_schedule(cfg: Dict[str, Any]) -> bool:
    if not cfg.get("cron_enabled"):
        return remove_cron_entry()
    return add_cron_entry(int(cfg.get("cron_interval_minutes", 60)))


def _run_cmd(cmd: List[str], timeout_sec: int = 20) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec, check=False)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "Timeout"
    except Exception as e:
        return 1, f"{type(e).__name__}: {e}"


def _latency_ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)


def _severity(status: str) -> int:
    return {"up": 0, "warning": 1, "down": 2}.get(status, 2)


def list_block_devices() -> List[str]:
    rc, out = _run_cmd(["lsblk", "-dn", "-o", "NAME,TYPE"], timeout_sec=8)
    if rc != 0:
        return []
    devices: List[str] = []
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[1] == "disk":
            devices.append(f"/dev/{parts[0]}")
    return devices


def check_smart(devices: List[str], debug: bool = False) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    if os.name != "posix" or not sys.platform.startswith("linux"):
        return "down", ["SMART check supports Linux hosts only"], _latency_ms(t0)
    if os.geteuid() != 0:
        return "down", ["SMART check requires root privileges"], _latency_ms(t0)
    rc, out = _run_cmd(["smartctl", "--version"], timeout_sec=6)
    if rc != 0:
        return "down", [f"smartctl unavailable: {out.strip()}"], _latency_ms(t0)

    lines: List[str] = []
    if not devices:
        return "warning", ["No block devices configured for SMART check"], _latency_ms(t0)

    failed = 0
    for dev in devices:
        rc, info = _run_cmd(["smartctl", "-H", dev], timeout_sec=20)
        ok = bool(re.search(r"\bPASSED\b|SMART Health Status:\s*OK", info, flags=re.IGNORECASE))
        if debug:
            print(f"    [smart] {dev}: rc={rc} ok={ok}")
        if ok:
            lines.append(f"SMART {dev}: PASSED")
        else:
            failed += 1
            msg = info.strip().splitlines()[-1] if info.strip() else "health check failed"
            lines.append(f"SMART {dev}: FAILED ({msg})")

    status = "down" if failed else "up"
    return status, lines, _latency_ms(t0)


def check_storage(debug: bool = False) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    lines: List[str] = []
    status = "up"
    max_fs_latency_ms = 0.0

    rc, out = _run_cmd(["df", "-P", "-x", "tmpfs", "-x", "devtmpfs"], timeout_sec=10)
    if rc != 0:
        return "down", [f"df failed: {out.strip()}"], _latency_ms(t0)

    fs_summary: List[str] = []
    for line in out.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 6:
            continue
        fs, used, mpoint = cols[0], cols[4], cols[5]
        if not used.endswith("%"):
            continue
        try:
            pct = int(used.rstrip("%"))
        except ValueError:
            continue

        free_pct = max(0, 100 - pct)
        fs_summary.append(f"{mpoint} ({fs}): used={pct}% free={free_pct}%")

        # Probe filesystem metadata latency for a host-relevant storage ping signal.
        tfs = time.perf_counter()
        try:
            os.statvfs(mpoint)
            lat = _latency_ms(tfs)
            max_fs_latency_ms = max(max_fs_latency_ms, lat)
            if debug:
                print(f"    [storage] {mpoint}: statvfs latency {lat:.2f}ms")
        except OSError as e:
            if debug:
                print(f"    [storage] {mpoint}: statvfs failed: {e}")

        if pct >= USAGE_DOWN_PCT:
            status = "down"
            lines.append(f"FS {mpoint} ({fs}): {pct}% used (critical)")
        elif pct >= USAGE_WARN_PCT and _severity(status) < _severity("warning"):
            status = "warning"
            lines.append(f"FS {mpoint} ({fs}): {pct}% used (warning)")

    md_path = Path("/proc/mdstat")
    if md_path.exists():
        text = md_path.read_text(encoding="utf-8", errors="ignore")
        degraded = re.findall(r"\[[U_]+\]", text)
        bad = [token for token in degraded if "_" in token]
        if bad:
            status = "down"
            lines.append(f"mdraid degraded: {' '.join(sorted(set(bad)))}")
        if re.search(r"\b(recovery|resync|reshape|check)\b", text):
            if _severity(status) < _severity("warning"):
                status = "warning"
            lines.append("mdraid maintenance/rebuild in progress")

    # Always include storage usage overview to make checks/debug more informative.
    if fs_summary:
        lines.append("Filesystems:")
        lines.extend(f"  {item}" for item in fs_summary)

    # Prefer storage probe latency as ping signal; fall back to total check duration.
    check_elapsed_ms = _latency_ms(t0)
    ping_ms = max_fs_latency_ms if max_fs_latency_ms > 0 else check_elapsed_ms
    lines.append(f"Storage latency basis: {ping_ms:.2f}ms")

    if not lines:
        lines.append("Storage checks OK (usage/RAID)")
    return status, lines, ping_ms


def check_host(mode: str, devices: List[str], debug: bool = False) -> Tuple[str, str, float]:
    worst = "up"
    max_latency = 0.0
    sections: List[str] = []

    if mode in ("smart", "both"):
        s_status, s_lines, s_lat = check_smart(devices, debug=debug)
        max_latency = max(max_latency, s_lat)
        if _severity(s_status) > _severity(worst):
            worst = s_status
        if debug:
            print(f"    [smart] section latency {s_lat:.2f}ms")
        sections.append("SMART:\n" + "\n".join(f"  • {x}" for x in s_lines))

    if mode in ("storage", "both"):
        st_status, st_lines, st_lat = check_storage(debug=debug)
        max_latency = max(max_latency, st_lat)
        if _severity(st_status) > _severity(worst):
            worst = st_status
        if debug:
            print(f"    [storage] section latency {st_lat:.2f}ms")
        sections.append("Storage:\n" + "\n".join(f"  • {x}" for x in st_lines))

    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    msg = f"Host check ({mode}) = {worst} @ {now}\n" + "\n".join(sections)
    return worst, msg, max_latency


def push_to_kuma(url: str, status: str, message: str, ping_ms: float, debug: bool = False) -> bool:
    base = normalize_kuma_url(url)
    full = f"{base}?status={status}&msg={quote(message)}&ping={ping_ms}"
    if debug:
        print(f"    [push] GET {base}?status=...&msg=...&ping={ping_ms}")
    try:
        parsed = urlparse(full)
        host = parsed.hostname or parsed.netloc.split(":")[0]
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=10, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        ok = resp.status in (200, 201, 204)
        if debug:
            print(f"    [push] response: HTTP {resp.status}")
        conn.close()
        return ok
    except Exception as e:
        if debug:
            print(f"    [push] error: {type(e).__name__}: {e}")
        return False


def prompt(text: str, default: Optional[str] = None) -> str:
    if default is not None:
        val = input(f"{text} [{default}]: ").strip()
        return val if val else default
    return input(f"{text}: ").strip()


def prompt_with_back(text: str, default: Optional[str] = None) -> Optional[str]:
    val = prompt(text, default)
    return None if (val and val.lower() in BACK_KEYS) else (val or "")


def confirm_save(action: str = "apply") -> bool:
    raw = prompt(f"{action}? (s)ave / (b)ack discard", "b").strip().lower() or "b"
    return raw in ("s", "save", "y", "yes")


def prompt_multi_indices(max_n: int, text: str) -> Optional[List[int]]:
    while True:
        raw = input(f"{text} (0=back, a=all): ").strip().lower()
        if raw in BACK_KEYS:
            return None
        if raw == "a":
            return list(range(1, max_n + 1))
        try:
            vals = [int(x.strip()) for x in raw.split(",") if x.strip()]
            if any(v < 1 or v > max_n for v in vals):
                raise ValueError
            return sorted(set(vals))
        except ValueError:
            print("Enter numbers like 1,3 or use 'a' for all.")


def add_monitor() -> None:
    print("\n--- Add monitor ---")
    print(CHANGES_NOTICE)
    mode = prompt_with_back("Check mode: smart / storage / both", "both")
    if mode is None:
        return
    mode = (mode or "both").lower()
    if mode not in CHECK_MODES:
        print("Invalid mode.")
        return

    devices: List[str] = []
    if mode in ("smart", "both"):
        candidates = list_block_devices()
        if not candidates:
            print("No block devices found via lsblk.")
        else:
            print("\nDetected disks:")
            for i, d in enumerate(candidates, 1):
                print(f"  [{i}] {d}")
            idxs = prompt_multi_indices(len(candidates), "Select disk(s) for SMART")
            if idxs is None:
                return
            devices = [candidates[i - 1] for i in idxs]

    kuma_url = prompt_with_back("Kuma push URL (https://host/api/push/TOKEN)", "")
    if kuma_url is None or not kuma_url:
        print("URL required.")
        return
    if not kuma_url.startswith(("http://", "https://")):
        kuma_url = "https://" + kuma_url
    kuma_url = normalize_kuma_url(kuma_url)
    err = validate_kuma_url(kuma_url)
    if err:
        print(f"Invalid URL: {err}")
        return

    name = prompt_with_back("Monitor name", f"{mode}-host-check")
    if name is None:
        return
    print(f"\nName: {name}\nMode: {mode}\nDevices: {', '.join(devices) if devices else '(auto/none)'}\nURL: {kuma_url}")
    if not confirm_save("Add monitor"):
        print("Discarded.")
        return

    cfg = load_config()
    cfg.setdefault("monitors", []).append(
        {"name": name, "check_mode": mode, "devices": devices, "kuma_url": kuma_url}
    )
    save_config(cfg)
    print(f"✓ Added monitor '{name}'.")


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
    for m in monitors:
        name = m.get("name", "?")
        mode = str(m.get("check_mode", "both")).lower()
        if mode not in CHECK_MODES:
            mode = "both"
        devices = [str(x) for x in m.get("devices", [])]
        url = m.get("kuma_url", "")
        if not url:
            print(f"  ✗ {name}: no Kuma URL")
            continue
        status, msg, lat = check_host(mode, devices, debug=dbg)
        if dbg:
            print(f"    [result] {name}: status={status} ping={lat:.2f}ms")
        ok = push_to_kuma(url, status, msg, lat, debug=dbg)
        print(f"  {'✓' if ok else '✗'} {name}: {status} (ping={lat:.2f}ms) — push {'OK' if ok else 'FAILED'}")
    if interactive:
        print("\n  (Press Enter to go back)")
        input()


def list_configured() -> None:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    print("\n--- Configured monitors ---")
    if not monitors:
        print("  No monitors configured.")
    for i, m in enumerate(monitors, 1):
        print(f"  [{i}] {m.get('name', '?')}")
        print(f"      Mode: {m.get('check_mode', 'both')}")
        print(f"      Devices: {', '.join(m.get('devices', [])) or '(auto/none)'}")
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
        print(f"  [{i}] {m.get('name', '?')} ({m.get('check_mode', 'both')})")
    raw = prompt("Number to remove (0=back)", "")
    if not raw or raw.lower() in BACK_KEYS:
        return
    try:
        idx = int(raw)
        if not (1 <= idx <= len(monitors)):
            print("Invalid number.")
            return
    except ValueError:
        print("Invalid number.")
        return
    target = monitors[idx - 1]
    print(f"Remove '{target.get('name', '?')}'?")
    if not confirm_save("Remove monitor"):
        print("Discarded.")
        return
    monitors.pop(idx - 1)
    cfg["monitors"] = monitors
    save_config(cfg)
    print("✓ Removed.")


def manage_cron() -> None:
    cfg = load_config()
    enabled = cfg.get("cron_enabled", False)
    interval = int(cfg.get("cron_interval_minutes", 60))
    content, ok = get_current_crontab()
    has = ok and CRON_MARKER in content
    print("\n--- Automatic checks (cron) ---")
    print(CHANGES_NOTICE)
    if not ok:
        print("  ⚠ crontab unavailable — manual setup required.")
    print(f"  Status: {'Enabled' if enabled or has else 'Disabled'} (every {interval} min)")
    print("\n  a) Enable automatic checks\n  b) Disable automatic checks\n  c) Change interval\n  d) Back")
    choice = prompt("Choice", "d").strip().lower()
    if choice == "a":
        if not cfg.get("monitors"):
            print("Add at least one monitor first.")
            return
        raw = prompt_with_back("Check interval (minutes)", str(interval))
        if raw is None:
            return
        try:
            interval = max(INTERVAL_MIN, min(INTERVAL_MAX, int(raw)))
        except ValueError:
            interval = 60
        print(f"Enable cron every {interval} minutes")
        if not confirm_save("Enable automatic checks"):
            print("Discarded.")
            return
        cfg["cron_enabled"] = True
        cfg["cron_interval_minutes"] = interval
        applied = ok and add_cron_entry(interval)
        save_config(cfg)
        print("✓ Automatic checks enabled.")
        if not applied:
            print("Add this line manually via crontab -e:")
            print(" ", build_cron_line(get_script_path(), interval))
    elif choice == "b":
        if not confirm_save("Disable automatic checks"):
            print("Discarded.")
            return
        cfg["cron_enabled"] = False
        save_config(cfg)
        remove_cron_entry()
        print("✓ Automatic checks disabled.")
    elif choice == "c":
        raw = prompt_with_back("New interval (minutes)", str(interval))
        if raw is None:
            return
        try:
            new_interval = max(INTERVAL_MIN, min(INTERVAL_MAX, int(raw)))
        except ValueError:
            print("Invalid number.")
            return
        if not confirm_save("Change interval"):
            print("Discarded.")
            return
        cfg["cron_interval_minutes"] = new_interval
        save_config(cfg)
        print(f"✓ Interval set to {new_interval} minutes.")


def test_push() -> None:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    if not monitors:
        print("\n  No monitors configured.")
        print("\n  (Press Enter to go back)")
        input()
        return
    print("\n--- Test push ---")
    for i, m in enumerate(monitors, 1):
        print(f"  [{i}] {m.get('name', '?')}")
    raw = prompt("Select monitor (0=back, a=all)", "a").strip().lower()
    if raw in BACK_KEYS:
        return
    targets: List[Dict[str, Any]] = []
    if raw == "a":
        targets = monitors
    else:
        try:
            idx = int(raw)
            if 1 <= idx <= len(monitors):
                targets = [monitors[idx - 1]]
        except ValueError:
            pass
    if not targets:
        print("Invalid selection.")
        return
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    msg = f"Test push @ {now} — unix-storage-monitor connectivity check"
    for m in targets:
        ok = push_to_kuma(m.get("kuma_url", ""), "up", msg, 0, debug=True)
        print(f"  {'✓' if ok else '✗'} {m.get('name', '?')}: push {'OK' if ok else 'FAILED'}")
    print("\n  (Press Enter to go back)")
    input()


def toggle_debug() -> None:
    cfg = load_config()
    cfg["debug"] = not cfg.get("debug", False)
    save_config(cfg)
    print(f"\n  Debug mode: {'ON' if cfg['debug'] else 'OFF'}")


def main_menu() -> str:
    cfg = load_config()
    print("\n" + "=" * 50)
    print("  Unix Storage Monitor — Kuma Integration")
    print("=" * 50)
    print(CHANGES_NOTICE)
    print(f"  Debug: {'ON' if cfg.get('debug', False) else 'OFF'}")
    print()
    print("  1) Add monitor (SMART / Storage / Both)")
    print("  2) Run check (all configured monitors)")
    print("  3) List configured monitors")
    print("  4) Remove monitor")
    print("  5) Schedule automatic checks (cron)")
    print("  6) Test push (send test message to Kuma)")
    print("  7) Toggle debug mode")
    print("  8) Exit")
    print("=" * 50)
    return prompt("Choice", "1").strip() or "1"


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
