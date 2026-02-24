#!/usr/bin/env python3
from __future__ import annotations

import sys as _sys
if _sys.version_info < (3, 8):
    print("ERROR: Python 3.8 or newer is required.", file=_sys.stderr)
    _sys.exit(1)

import argparse
import http.client
import json
import os
import platform
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse


APP_NAME = "unix-monitor"
APP_VERSION = "1.0.0"
CHECK_MODES = ("mount", "smart", "storage", "both", "ping", "port", "dns")
PEER_ROLES = ("standalone", "agent", "master")
CONFIG_FILE_MODE = 0o600
CRON_MARKER = "# unix-monitor.py - do not edit this line manually"
INTERVAL_MIN = 1
INTERVAL_MAX = 120
USAGE_WARN_PCT = 90
USAGE_DOWN_PCT = 98
BACK_KEYS = ("0", "b", "back", "q", "quit")
ALLOWED_SCHEMES = ("https", "http")
KUMA_PUSH_PATH_PATTERN = re.compile(r"^/api/push/[A-Za-z0-9_-]+$")

RUNTIME_DATA_DIR_NAME = "unix-monitor"
STATE_FILE = "unix-monitor-state.json"
HISTORY_FILE = "unix-monitor-history.json"
LOG_FILE = "unix-monitor-ui.log"


def get_system_label() -> str:
    uname = platform.uname()
    return (uname.system or platform.system() or "Unix").strip()


APP_DISPLAY_NAME = f"{get_system_label()} Kuma Monitor Addon"


def now_s() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _severity(status: str) -> int:
    return {"up": 0, "warning": 1, "down": 2}.get(status, 2)


def _latency_ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)


def get_script_path() -> Path:
    return Path(__file__).resolve()


def get_runtime_data_dir() -> Path:
    script_dir = get_script_path().parent
    for c in (
        script_dir / "var",
        Path("/var/lib") / RUNTIME_DATA_DIR_NAME,
        Path.home() / ".config" / RUNTIME_DATA_DIR_NAME,
    ):
        try:
            c.mkdir(parents=True, exist_ok=True)
            if os.access(str(c), os.W_OK):
                return c
        except OSError:
            continue
    return script_dir


def get_config_path() -> Path:
    script_dir = get_script_path().parent
    local = script_dir / f"{APP_NAME}.json"
    if local.exists():
        return local
    runtime_cfg = get_runtime_data_dir() / f"{APP_NAME}.json"
    if runtime_cfg.exists():
        return runtime_cfg
    home_cfg = Path.home() / ".config" / f"{APP_NAME}.json"
    if home_cfg.exists():
        return home_cfg
    if os.access(str(script_dir), os.W_OK):
        return local
    runtime_cfg.parent.mkdir(parents=True, exist_ok=True)
    return runtime_cfg


def _enforce_file_mode(path: Path, mode: int = CONFIG_FILE_MODE) -> None:
    try:
        if path.exists():
            cur = stat.S_IMODE(path.stat().st_mode)
            if cur != mode:
                path.chmod(mode)
    except OSError:
        pass


def _default_config() -> Dict[str, Any]:
    return {
        "instance_id": uuid.uuid4().hex,
        "instance_name": socket.gethostname() or "unix-monitor",
        "monitors": [],
        "debug": False,
        "cron_enabled": False,
        "cron_interval_minutes": 5,
        "peer_role": "standalone",
        "peer_master_url": "",
        "peering_token": "",
        "peer_port": 8787,
        "web_enabled": True,
        "ui_host": "0.0.0.0",
        "ui_port": 8787,
        "scheduler_backend": "systemd",
        "agent_only_notice_ack": False,
    }


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
        cfg = _default_config()
        save_config(cfg, reapply_cron=False)
        return cfg
    _enforce_file_mode(path)
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        cfg = _default_config()

    changed = False
    for key, value in _default_config().items():
        if key not in cfg:
            cfg[key] = value
            changed = True
    cfg["peer_role"] = str(cfg.get("peer_role", "standalone")).lower()
    if cfg["peer_role"] not in PEER_ROLES:
        cfg["peer_role"] = "standalone"
        changed = True
    for m in cfg.get("monitors", []):
        mode = str(m.get("check_mode", "both")).lower()
        if mode not in CHECK_MODES:
            m["check_mode"] = "both"
            changed = True
        raw_url = str(m.get("kuma_url", "") or "").strip()
        if raw_url:
            clean = normalize_kuma_url(raw_url)
            if clean != raw_url:
                m["kuma_url"] = clean
                changed = True
    if changed:
        save_config(cfg, reapply_cron=False)
    return cfg


def save_config(cfg: Dict[str, Any], reapply_cron: bool = True) -> None:
    path = get_config_path()
    tmp = path.parent / f".{APP_NAME}.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, CONFIG_FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.replace(str(tmp), str(path))
    except OSError:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    _enforce_file_mode(path)
    if reapply_cron:
        apply_cron_schedule(cfg)


def _state_path() -> Path:
    return get_runtime_data_dir() / STATE_FILE


def _history_path() -> Path:
    return get_runtime_data_dir() / HISTORY_FILE


def _log_path() -> Path:
    return get_runtime_data_dir() / LOG_FILE


def append_ui_log(line: str) -> None:
    msg = f"{now_s()} | {line}\n"
    try:
        with open(_log_path(), "a", encoding="utf-8") as f:
            f.write(msg)
        _enforce_file_mode(_log_path())
    except OSError:
        pass


def load_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def save_json_file(path: Path, data: Any) -> None:
    tmp = path.parent / f".{path.name}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(str(tmp), str(path))
        _enforce_file_mode(path)
    except OSError:
        pass


def _find_python3() -> str:
    if sys.executable and os.path.isabs(sys.executable):
        return sys.executable
    return shutil.which("python3") or "/usr/bin/python3"


def build_cron_line(script_path: Path, interval_minutes: int) -> str:
    py = _find_python3()
    work_dir = script_path.parent
    if interval_minutes < 60:
        cron_expr = f"*/{interval_minutes} * * * *"
    elif interval_minutes == 60:
        cron_expr = "0 * * * *"
    else:
        cron_expr = f"0 */{max(1, interval_minutes // 60)} * * *"
    return f"{cron_expr} cd {work_dir} && {py} {script_path} --run-scheduled {CRON_MARKER}"


def get_current_crontab() -> Tuple[str, bool]:
    try:
        out = subprocess.check_output(["crontab", "-l"], text=True, stderr=subprocess.DEVNULL)
        return out, True
    except subprocess.CalledProcessError:
        return "", True
    except (OSError, FileNotFoundError, PermissionError):
        return "", False


def write_crontab(content: str) -> bool:
    try:
        p = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
        p.communicate(content)
        return p.returncode == 0
    except (OSError, FileNotFoundError, PermissionError):
        return False


def remove_cron_entry() -> bool:
    content, ok = get_current_crontab()
    if not ok:
        return False
    lines = [line for line in content.splitlines() if CRON_MARKER not in line]
    new = "\n".join(line for line in lines if line.strip()) + "\n"
    return write_crontab(new)


def add_cron_entry(interval_minutes: int) -> bool:
    content, ok = get_current_crontab()
    if not ok:
        return False
    lines = [line for line in content.splitlines() if CRON_MARKER not in line]
    lines.append(build_cron_line(get_script_path(), interval_minutes))
    new = "\n".join(line for line in lines if line.strip()) + "\n"
    return write_crontab(new)


def apply_cron_schedule(cfg: Dict[str, Any]) -> bool:
    if cfg.get("scheduler_backend") != "cron":
        return remove_cron_entry()
    if not cfg.get("cron_enabled"):
        return remove_cron_entry()
    interval = int(cfg.get("cron_interval_minutes", 5))
    interval = max(INTERVAL_MIN, min(INTERVAL_MAX, interval))
    return add_cron_entry(interval)


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


def list_block_devices() -> List[str]:
    rc, out = _run_cmd(["lsblk", "-dn", "-o", "NAME,TYPE"], timeout_sec=8)
    if rc != 0:
        return []
    disks: List[str] = []
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[1] == "disk":
            disks.append(f"/dev/{parts[0]}")
    return disks


def get_mounts() -> List[Tuple[str, str, str]]:
    result: List[Tuple[str, str, str]] = []
    system = platform.system()
    if system == "Linux":
        try:
            with open("/proc/mounts", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    device, mpoint, fstype = parts[0], parts[1], parts[2]
                    if mpoint.startswith(("/sys", "/proc", "/dev/pts", "/run")):
                        continue
                    if fstype in ("sysfs", "proc", "devtmpfs", "tmpfs", "cgroup", "cgroup2"):
                        continue
                    result.append((device, mpoint, fstype))
        except FileNotFoundError:
            pass
    return result


def check_mount_accessible(mount_point: str) -> Tuple[bool, Optional[str], float]:
    resolved = os.path.realpath(mount_point)
    if resolved != os.path.normpath(mount_point):
        return False, "Symlink or path traversal detected", 0.0
    path = Path(resolved)
    if not path.exists():
        return False, "Path does not exist", 0.0
    if not path.is_dir():
        return False, "Not a directory", 0.0
    t0 = time.perf_counter()
    try:
        st = os.statvfs(mount_point)
        lat = _latency_ms(t0)
        if st.f_blocks >= 0:
            return True, None, lat
    except PermissionError:
        return False, "Permission denied (statvfs)", _latency_ms(t0)
    except OSError as e:
        return False, str(e), _latency_ms(t0)
    t0 = time.perf_counter()
    try:
        os.listdir(mount_point)
        return True, None, _latency_ms(t0)
    except OSError as e:
        return False, str(e), _latency_ms(t0)


def check_mounts_status(mounts: List[Tuple[str, str, str]], debug: bool = False) -> Tuple[str, List[str], float]:
    ok_list: List[str] = []
    fail_list: List[Tuple[str, str]] = []
    max_lat = 0.0
    for _dev, mpoint, fstype in mounts:
        ok, err, lat = check_mount_accessible(mpoint)
        max_lat = max(max_lat, lat)
        if debug:
            print(f"    [mount] {mpoint} ({fstype}) -> {'OK' if ok else 'FAIL'} {lat:.2f}ms")
        if ok:
            ok_list.append(f"{mpoint} ({fstype})")
        else:
            fail_list.append((mpoint, err or "unreachable"))
    if not fail_list:
        return "up", [f"All {len(ok_list)} mount(s) healthy", *ok_list], max_lat
    if not ok_list:
        return "down", [f"All {len(fail_list)} mount(s) failed", *[f"{m}: {e}" for m, e in fail_list]], max_lat
    return "warning", [f"{len(ok_list)} mount(s) healthy, {len(fail_list)} failed", *[f"{m}: {e}" for m, e in fail_list]], max_lat


def check_smart(devices: List[str], debug: bool = False) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    if os.name != "posix" or not sys.platform.startswith("linux"):
        return "down", ["SMART check supports Linux hosts only"], _latency_ms(t0)
    if os.geteuid() != 0:
        return "down", ["SMART check requires root privileges"], _latency_ms(t0)
    rc, out = _run_cmd(["smartctl", "--version"], timeout_sec=6)
    if rc != 0:
        return "down", [f"smartctl unavailable: {out.strip()}"], _latency_ms(t0)
    if not devices:
        devices = list_block_devices()
    if not devices:
        return "warning", ["No block devices available for SMART checks"], _latency_ms(t0)
    failed = 0
    lines: List[str] = []
    for dev in devices:
        rc, info = _run_cmd(["smartctl", "-H", dev], timeout_sec=20)
        ok = bool(re.search(r"\bPASSED\b|SMART Health Status:\s*OK", info, flags=re.IGNORECASE))
        if debug:
            print(f"    [smart] {dev}: rc={rc} ok={ok}")
        if ok:
            lines.append(f"{dev}: PASSED")
        else:
            failed += 1
            msg = info.strip().splitlines()[-1] if info.strip() else "health check failed"
            lines.append(f"{dev}: FAILED ({msg})")
    return ("down" if failed else "up"), lines, _latency_ms(t0)


def check_storage(debug: bool = False) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    rc, out = _run_cmd(["df", "-P", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs"], timeout_sec=10)
    if rc != 0:
        return "down", [f"df failed: {out.strip()}"], _latency_ms(t0)
    status = "up"
    lines: List[str] = []
    max_fs_latency = 0.0
    for line in out.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 6:
            continue
        fs, used, mpoint = cols[0], cols[4], cols[5]
        if fs.startswith("/dev/loop") or mpoint.startswith("/snap/"):
            continue
        if not used.endswith("%"):
            continue
        try:
            pct = int(used.rstrip("%"))
        except ValueError:
            continue
        tfs = time.perf_counter()
        try:
            os.statvfs(mpoint)
            max_fs_latency = max(max_fs_latency, _latency_ms(tfs))
        except OSError:
            pass
        if pct >= USAGE_DOWN_PCT:
            status = "down"
            lines.append(f"{mpoint}: {pct}% used (critical)")
        elif pct >= USAGE_WARN_PCT and _severity(status) < _severity("warning"):
            status = "warning"
            lines.append(f"{mpoint}: {pct}% used (warning)")
    md = Path("/proc/mdstat")
    if md.exists():
        text = md.read_text(encoding="utf-8", errors="ignore")
        degraded = re.findall(r"\[[U_]+\]", text)
        if any("_" in token for token in degraded):
            status = "down"
            lines.append("mdraid degraded state detected")
        elif re.search(r"\b(recovery|resync|reshape|check)\b", text):
            if _severity(status) < _severity("warning"):
                status = "warning"
            lines.append("mdraid maintenance/rebuild in progress")
    if not lines:
        lines.append("Storage checks OK")
    ping = max_fs_latency if max_fs_latency > 0 else _latency_ms(t0)
    lines.append(f"Storage latency basis: {ping:.2f}ms")
    if debug:
        print(f"    [storage] status={status} ping={ping:.2f}ms")
    return status, lines, ping


def check_ping(host: str) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    host = host.strip()
    if not host:
        return "down", ["Ping target host missing"], _latency_ms(t0)
    rc, out = _run_cmd(["ping", "-c", "1", "-W", "2", host], timeout_sec=5)
    ok = rc == 0
    lines = [f"Ping target: {host}"]
    lines.append("Reachable" if ok else f"Ping failed: {out.strip().splitlines()[-1] if out.strip() else 'no response'}")
    return ("up" if ok else "down"), lines, _latency_ms(t0)


def check_port(host: str, port: int) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    host = host.strip()
    if not host:
        return "down", ["Port probe host missing"], _latency_ms(t0)
    try:
        with socket.create_connection((host, int(port)), timeout=3):
            return "up", [f"TCP {host}:{int(port)} reachable"], _latency_ms(t0)
    except OSError as e:
        return "down", [f"TCP {host}:{int(port)} failed: {e}"], _latency_ms(t0)


def check_dns(name: str, server: str = "") -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    name = name.strip()
    if not name:
        return "down", ["DNS name missing"], _latency_ms(t0)
    if server.strip():
        rc, out = _run_cmd(["nslookup", name, server.strip()], timeout_sec=5)
    else:
        rc, out = _run_cmd(["nslookup", name], timeout_sec=5)
    ok = rc == 0 and ("Address" in out or "Name:" in out)
    if ok:
        return "up", [f"DNS resolve OK: {name}"], _latency_ms(t0)
    return "down", [f"DNS resolve failed: {name}"], _latency_ms(t0)


def _check_monitor(monitor: Dict[str, Any], debug: bool = False) -> Tuple[str, str, float]:
    mode = str(monitor.get("check_mode", "both")).lower()
    if mode not in CHECK_MODES:
        mode = "both"
    sections: List[str] = []
    worst = "up"
    max_latency = 0.0
    if mode in ("mount",):
        mounts_data = monitor.get("mounts", [])
        mounts = [(x.get("device", "?"), x.get("mount_point", ""), x.get("fstype", "?")) for x in mounts_data if x.get("mount_point")]
        if not mounts:
            mounts = get_mounts()
        st, lines, lat = check_mounts_status(mounts, debug=debug)
        worst = st
        max_latency = max(max_latency, lat)
        sections.append("Mounts:\n" + "\n".join(f"  - {line}" for line in lines))
    elif mode in ("smart", "storage", "both"):
        if mode in ("smart", "both"):
            st, lines, lat = check_smart([str(x) for x in monitor.get("devices", [])], debug=debug)
            if _severity(st) > _severity(worst):
                worst = st
            max_latency = max(max_latency, lat)
            sections.append("SMART:\n" + "\n".join(f"  - {line}" for line in lines))
        if mode in ("storage", "both"):
            st, lines, lat = check_storage(debug=debug)
            if _severity(st) > _severity(worst):
                worst = st
            max_latency = max(max_latency, lat)
            sections.append("Storage:\n" + "\n".join(f"  - {line}" for line in lines))
    elif mode == "ping":
        st, lines, lat = check_ping(str(monitor.get("probe_host", "")))
        worst, max_latency = st, lat
        sections.append("Ping:\n" + "\n".join(f"  - {line}" for line in lines))
    elif mode == "port":
        st, lines, lat = check_port(str(monitor.get("probe_host", "")), int(monitor.get("probe_port", 443) or 443))
        worst, max_latency = st, lat
        sections.append("Port:\n" + "\n".join(f"  - {line}" for line in lines))
    elif mode == "dns":
        st, lines, lat = check_dns(str(monitor.get("dns_name", "")), str(monitor.get("dns_server", "")))
        worst, max_latency = st, lat
        sections.append("DNS:\n" + "\n".join(f"  - {line}" for line in lines))
    msg = f"Monitor {monitor.get('name', '?')} ({mode}) = {worst} @ {now_s()}\n" + "\n".join(sections)
    return worst, msg, max_latency


def push_to_kuma(url: str, status: str, message: str, ping_ms: float, debug: bool = False) -> bool:
    base_url = normalize_kuma_url(url)
    full_url = f"{base_url}?status={status}&msg={quote(message)}&ping={ping_ms}"
    if debug:
        print(f"    [push] GET {base_url}?status=...&msg=...&ping={ping_ms:.2f}")
    try:
        parsed = urlparse(full_url)
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
        conn.close()
        return ok
    except Exception as e:
        if debug:
            print(f"    [push] error: {type(e).__name__}: {e}")
        return False


def _record_results(results: List[Dict[str, Any]]) -> None:
    state = {"updated_at": now_s(), "results": results}
    save_json_file(_state_path(), state)
    history = load_json_file(_history_path(), [])
    if not isinstance(history, list):
        history = []
    history.append(state)
    history = history[-100:]
    save_json_file(_history_path(), history)


def _build_live_snapshot() -> Dict[str, Any]:
    cfg = load_config()
    state = load_json_file(_state_path(), {"updated_at": "", "results": []})
    return {
        "version": APP_VERSION,
        "instance_id": cfg.get("instance_id"),
        "instance_name": cfg.get("instance_name"),
        "role": cfg.get("peer_role"),
        "updated_at": state.get("updated_at"),
        "monitors": cfg.get("monitors", []),
        "state": state.get("results", []),
    }


def _peer_dirs() -> Path:
    p = get_runtime_data_dir() / "peers"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _save_peer_snapshot(peer_id: str, data: Dict[str, Any]) -> None:
    save_json_file(_peer_dirs() / f"{peer_id}.json", data)


def _load_all_peer_snapshots() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for f in _peer_dirs().glob("*.json"):
        data = load_json_file(f, {})
        if isinstance(data, dict):
            out.append(data)
    return out


def _parse_base_url(raw: str, default_port: int) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    p = urlparse(raw)
    host = p.hostname or ""
    if not host:
        return ""
    port = p.port or default_port
    return f"{p.scheme}://{host}:{port}"


def _peer_http_request(base_url: str, token: str, method: str, path: str, payload: Optional[Dict[str, Any]] = None, timeout: int = 10) -> Tuple[int, str]:
    base = _parse_base_url(base_url, 8787)
    if not base:
        return 0, "invalid peer URL"
    parsed = urlparse(base)
    host = parsed.hostname or ""
    port = parsed.port or 8787
    headers = {"Accept": "application/json"}
    body = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    try:
        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        text = resp.read().decode("utf-8", errors="replace")
        status = resp.status
        conn.close()
        return status, text
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


def maybe_push_agent_snapshot(cfg: Dict[str, Any], results: List[Dict[str, Any]]) -> None:
    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
    if role != "agent":
        return
    master = str(cfg.get("peer_master_url", "") or "").strip()
    token = str(cfg.get("peering_token", "") or "").strip()
    if not master or not token:
        append_ui_log("agent-push skipped | master URL or token missing")
        return
    payload = _build_live_snapshot()
    payload["state"] = results
    status, body = _peer_http_request(master, token, "POST", "/api/peer/push", payload=payload, timeout=12)
    if 200 <= status < 300:
        append_ui_log("agent-push | success")
    else:
        append_ui_log(f"agent-push | failed status={status} body={body[:160]}")


def pull_master_snapshots(cfg: Dict[str, Any]) -> None:
    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
    if role != "master":
        return
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return
    for peer in _load_all_peer_snapshots():
        peer_url = str(peer.get("agent_url", "") or "").strip()
        peer_id = str(peer.get("instance_id", "") or "").strip()
        if not peer_url or not peer_id:
            continue
        status, body = _peer_http_request(peer_url, token, "GET", "/api/peer/snapshot", timeout=8)
        if 200 <= status < 300:
            try:
                snap = json.loads(body)
                _save_peer_snapshot(peer_id, snap)
            except json.JSONDecodeError:
                pass


def run_check_once(debug: Optional[bool] = None, interactive: bool = True) -> List[Dict[str, Any]]:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    dbg = debug if debug is not None else bool(cfg.get("debug", False))
    results: List[Dict[str, Any]] = []
    if interactive:
        print("\n--- Run check ---")
    if not monitors:
        print("  No monitors configured.")
    for m in monitors:
        name = str(m.get("name", "?"))
        url = str(m.get("kuma_url", "") or "")
        status, msg, ping = _check_monitor(m, debug=dbg)
        push_ok = False
        if url:
            push_ok = push_to_kuma(url, status, msg, ping, debug=dbg)
        result = {
            "name": name,
            "check_mode": m.get("check_mode", "both"),
            "status": status,
            "ping_ms": ping,
            "push_ok": push_ok,
            "timestamp": now_s(),
            "message": msg,
        }
        results.append(result)
        print(f"  {'✓' if push_ok else '✗'} {name}: {status} (ping={ping:.2f}ms) — push {'OK' if push_ok else 'FAILED'}")
    _record_results(results)
    maybe_push_agent_snapshot(cfg, results)
    pull_master_snapshots(cfg)
    if interactive:
        print("\n  (Press Enter to go back)")
        input()
    return results


def prompt(text: str, default: Optional[str] = None) -> str:
    if default is not None:
        val = input(f"{text} [{default}]: ").strip()
        return val if val else default
    return input(f"{text}: ").strip()


def prompt_with_back(text: str, default: Optional[str] = None) -> Optional[str]:
    val = prompt(text, default)
    return None if (val and val.strip().lower() in BACK_KEYS) else (val or "")


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
            if not vals or any(v < 1 or v > max_n for v in vals):
                raise ValueError
            return sorted(set(vals))
        except ValueError:
            print("Enter numbers like 1,3 or use 'a' for all.")


def add_monitor() -> None:
    print("\n--- Add monitor ---")
    mode = prompt_with_back("Check mode: mount / smart / storage / both / ping / port / dns", "both")
    if mode is None:
        return
    mode = (mode or "both").lower()
    if mode not in CHECK_MODES:
        print("Invalid mode.")
        return
    monitor: Dict[str, Any] = {"check_mode": mode}
    if mode == "mount":
        mounts = get_mounts()
        if not mounts:
            print("No mounts found.")
            return
        for i, (_dev, mpoint, fstype) in enumerate(mounts, 1):
            print(f"  [{i}] {mpoint} ({fstype})")
        idxs = prompt_multi_indices(len(mounts), "Select mount(s)")
        if idxs is None:
            return
        monitor["mounts"] = [{"device": mounts[i - 1][0], "mount_point": mounts[i - 1][1], "fstype": mounts[i - 1][2]} for i in idxs]
    if mode in ("smart", "both"):
        devs = list_block_devices()
        if devs:
            print("\nDetected disks:")
            for i, d in enumerate(devs, 1):
                print(f"  [{i}] {d}")
            idxs = prompt_multi_indices(len(devs), "Select disk(s) for SMART")
            if idxs is None:
                return
            monitor["devices"] = [devs[i - 1] for i in idxs]
    if mode in ("ping", "port"):
        host = prompt_with_back("Probe target host/IP", "")
        if host is None or not host:
            print("Probe host required.")
            return
        monitor["probe_host"] = host
    if mode == "port":
        p = prompt_with_back("Probe TCP port", "443")
        if p is None:
            return
        try:
            monitor["probe_port"] = int(p or "443")
        except ValueError:
            monitor["probe_port"] = 443
    if mode == "dns":
        dname = prompt_with_back("DNS hostname/domain", "")
        if dname is None or not dname:
            print("DNS name required.")
            return
        dserver = prompt_with_back("DNS server (optional)", "")
        if dserver is None:
            return
        monitor["dns_name"] = dname
        monitor["dns_server"] = dserver

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
    monitor["kuma_url"] = kuma_url
    name = prompt_with_back("Monitor name", f"{mode}-host-check")
    if name is None:
        return
    monitor["name"] = name
    print(f"\nName: {name}\nMode: {mode}\nURL: {kuma_url}")
    if not confirm_save("Add monitor"):
        print("Discarded.")
        return
    cfg = load_config()
    cfg.setdefault("monitors", []).append(monitor)
    save_config(cfg)
    append_ui_log(f"monitor-add | {name} mode={mode}")
    print(f"✓ Added monitor '{name}'.")


def list_configured() -> None:
    cfg = load_config()
    print("\n--- Configured monitors ---")
    for i, m in enumerate(cfg.get("monitors", []), 1):
        print(f"  [{i}] {m.get('name', '?')} ({m.get('check_mode', 'both')})")
        print(f"      URL: {m.get('kuma_url', '')}")
    if not cfg.get("monitors"):
        print("  No monitors configured.")
    print("\n  (Press Enter to go back)")
    input()


def remove_monitor() -> None:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    if not monitors:
        print("No monitors configured.")
        return
    print("\n--- Remove monitor ---")
    for i, m in enumerate(monitors, 1):
        print(f"  [{i}] {m.get('name', '?')} ({m.get('check_mode', 'both')})")
    raw = prompt("Number to remove (0=back)", "")
    if not raw or raw.lower() in BACK_KEYS:
        return
    try:
        idx = int(raw)
        if not (1 <= idx <= len(monitors)):
            raise ValueError
    except ValueError:
        print("Invalid number.")
        return
    target = monitors[idx - 1]
    if not confirm_save(f"Remove monitor '{target.get('name', '?')}'"):
        print("Discarded.")
        return
    monitors.pop(idx - 1)
    cfg["monitors"] = monitors
    save_config(cfg)
    append_ui_log(f"monitor-remove | {target.get('name', '?')}")
    print("✓ Removed.")


def test_push() -> None:
    cfg = load_config()
    mons = cfg.get("monitors", [])
    if not mons:
        print("No monitors configured.")
        return
    now = now_s()
    msg = f"Test push @ {now} — {APP_DISPLAY_NAME} connectivity check"
    for m in mons:
        ok = push_to_kuma(str(m.get("kuma_url", "")), "up", msg, 0, debug=True)
        print(f"  {'✓' if ok else '✗'} {m.get('name', '?')}: push {'OK' if ok else 'FAILED'}")


def manage_schedule() -> None:
    cfg = load_config()
    print("\n--- Scheduler backend ---")
    print(f"Current backend: {cfg.get('scheduler_backend', 'systemd')}")
    print(f"Cron enabled: {cfg.get('cron_enabled', False)} every {cfg.get('cron_interval_minutes', 5)} min")
    print("a) Use systemd (recommended)")
    print("b) Use cron fallback")
    print("c) Back")
    choice = prompt("Choice", "c").strip().lower()
    if choice == "a":
        cfg["scheduler_backend"] = "systemd"
        cfg["cron_enabled"] = False
        save_config(cfg)
        print("✓ Switched to systemd mode. Use installer helper scripts to install/update units.")
    elif choice == "b":
        raw = prompt_with_back("Cron interval minutes", str(cfg.get("cron_interval_minutes", 5)))
        if raw is None:
            return
        try:
            interval = max(INTERVAL_MIN, min(INTERVAL_MAX, int(raw)))
        except ValueError:
            interval = 5
        cfg["scheduler_backend"] = "cron"
        cfg["cron_enabled"] = True
        cfg["cron_interval_minutes"] = interval
        save_config(cfg)
        applied = apply_cron_schedule(cfg)
        print("✓ Cron mode enabled." if applied else "⚠ Cron entry could not be applied automatically.")


def _agent_only_ready(cfg: Dict[str, Any]) -> Tuple[bool, str]:
    if cfg.get("web_enabled", True):
        return True, ""
    role = str(cfg.get("peer_role", "standalone")).lower()
    if role != "agent":
        return False, "Webserver is disabled. This installation is agent-only and requires peer_role=agent."
    if not str(cfg.get("peer_master_url", "")).strip() or not str(cfg.get("peering_token", "")).strip():
        return False, "Webserver is disabled. Agent mode requires peer_master_url and peering_token."
    return True, ""


def main_menu() -> str:
    cfg = load_config()
    print("\n" + "=" * 68)
    print(f" {APP_DISPLAY_NAME} — mount + unix-storage + peering")
    print("=" * 68)
    print(f" Role: {cfg.get('peer_role')} | Web UI: {'enabled' if cfg.get('web_enabled') else 'disabled'} | Scheduler: {cfg.get('scheduler_backend')}")
    if not cfg.get("web_enabled", True):
        print(" NOTICE: Web UI disabled. Menu is agent-only and requires a master connection.")
    print("  1) Add monitor")
    print("  2) Run check")
    print("  3) List monitors")
    print("  4) Remove monitor")
    print("  5) Test push")
    print("  6) Scheduler backend")
    print("  7) Toggle debug")
    print("  8) Exit")
    return prompt("Choice", "1").strip() or "1"


def interactive_menu(agent_only: bool = False) -> int:
    cfg = load_config()
    if agent_only:
        ok, reason = _agent_only_ready(cfg)
        if not ok:
            print(reason)
            print("Re-run installer and configure master URL + peering token.")
            return 2
    while True:
        choice = main_menu()
        if choice == "1":
            add_monitor()
        elif choice == "2":
            run_check_once()
        elif choice == "3":
            list_configured()
        elif choice == "4":
            remove_monitor()
        elif choice == "5":
            test_push()
        elif choice == "6":
            manage_schedule()
        elif choice == "7":
            cfg = load_config()
            cfg["debug"] = not bool(cfg.get("debug", False))
            save_config(cfg)
            print(f"Debug mode: {'ON' if cfg['debug'] else 'OFF'}")
        elif choice == "8":
            print("Bye.")
            return 0
        else:
            print("Invalid choice.")


def _html_dashboard(cfg: Dict[str, Any]) -> str:
    state = load_json_file(_state_path(), {"updated_at": "-", "results": []})
    peers = _load_all_peer_snapshots()
    mons = cfg.get("monitors", [])
    role = str(cfg.get("peer_role", "standalone"))
    lines = [
        f"<html><head><title>{APP_DISPLAY_NAME}</title><style>",
        "body{font-family:Arial,sans-serif;margin:24px;background:#10151f;color:#d8e1ef}",
        ".box{background:#1b2333;border:1px solid #2e3a54;border-radius:10px;padding:14px;margin-bottom:14px}",
        "input,select{padding:6px;background:#0f1624;color:#d8e1ef;border:1px solid #425270;border-radius:6px}",
        "button{padding:7px 10px;background:#2d6cdf;border:0;color:white;border-radius:6px;cursor:pointer}",
        "code{color:#91e6b3}",
        "</style></head><body>",
        f"<h1>{APP_DISPLAY_NAME}</h1>",
        f"<div class='box'><b>Role:</b> {role} | <b>Web UI:</b> {'enabled' if cfg.get('web_enabled') else 'disabled'} | <b>Updated:</b> {state.get('updated_at', '-')}</div>",
    ]
    if not cfg.get("web_enabled", True):
        lines.append("<div class='box'><b>Agent-only notice:</b> Web UI is disabled for this node. Use master-connected agent menu mode only.</div>")
    lines.append("<div class='box'><h3>Monitors</h3>")
    if mons:
        lines.append("<ul>")
        for m in mons:
            lines.append(f"<li><b>{m.get('name','?')}</b> ({m.get('check_mode','both')})</li>")
        lines.append("</ul>")
    else:
        lines.append("<p>No monitors configured.</p>")
    lines.append("</div>")
    lines.append(
        "<div class='box'><h3>Actions</h3>"
        "<form method='post' action='/run-check'><button type='submit'>Run checks now</button></form>"
        "<br><form method='post' action='/peer/save-settings'>"
        "<label>Role: <select name='peer_role'><option>standalone</option><option>agent</option><option>master</option></select></label><br><br>"
        "<label>Master URL: <input name='peer_master_url' placeholder='http://master-host:8787'></label><br><br>"
        "<label>Peering token: <input name='peering_token' placeholder='shared token'></label><br><br>"
        "<button type='submit'>Save peering settings</button></form></div>"
    )
    lines.append("<div class='box'><h3>Peer snapshots (master view)</h3>")
    if peers:
        lines.append("<ul>")
        for p in peers:
            lines.append(f"<li>{p.get('instance_name', p.get('instance_id','peer'))} ({p.get('role','agent')})</li>")
        lines.append("</ul>")
    else:
        lines.append("<p>No peer snapshots stored yet.</p>")
    lines.append("</div>")
    lines.append("<div class='box'><h3>API</h3><p><code>/api/peer/health</code> <code>/api/peer/snapshot</code> <code>/api/peer/push</code> <code>/api/peer/create-monitor</code></p></div>")
    lines.append("</body></html>")
    return "".join(lines)


def _read_request_json(handler: BaseHTTPRequestHandler) -> Dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length).decode("utf-8", errors="replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def _auth_ok(handler: BaseHTTPRequestHandler, cfg: Dict[str, Any]) -> bool:
    expected = str(cfg.get("peering_token", "") or "").strip()
    if not expected:
        return False
    hdr = handler.headers.get("Authorization", "")
    if not hdr.startswith("Bearer "):
        return False
    return hdr.split(" ", 1)[1].strip() == expected


def _reply_json(handler: BaseHTTPRequestHandler, obj: Dict[str, Any], status: int = 200) -> None:
    payload = json.dumps(obj).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def _reply_text(handler: BaseHTTPRequestHandler, text: str, status: int = 200, content_type: str = "text/plain; charset=utf-8") -> None:
    payload = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def make_handler():
    class Handler(BaseHTTPRequestHandler):
        server_version = f"{APP_NAME}/{APP_VERSION}"

        def log_message(self, fmt: str, *args: Any) -> None:
            append_ui_log(f"http | {self.address_string()} | " + (fmt % args))

        def do_GET(self) -> None:  # noqa: N802
            cfg = load_config()
            parsed = urlparse(self.path)
            if parsed.path == "/":
                _reply_text(self, _html_dashboard(cfg), 200, "text/html; charset=utf-8")
                return
            if parsed.path == "/status-json":
                _reply_json(self, _build_live_snapshot(), 200)
                return
            if parsed.path == "/api/peer/health":
                if not _auth_ok(self, cfg):
                    _reply_json(self, {"status": "forbidden"}, 403)
                    return
                _reply_json(
                    self,
                    {
                        "status": "ok",
                        "instance_id": cfg.get("instance_id"),
                        "instance_name": cfg.get("instance_name"),
                        "role": cfg.get("peer_role"),
                        "version": APP_VERSION,
                    },
                    200,
                )
                return
            if parsed.path == "/api/peer/snapshot":
                if not _auth_ok(self, cfg):
                    _reply_json(self, {"status": "forbidden"}, 403)
                    return
                _reply_json(self, _build_live_snapshot(), 200)
                return
            if parsed.path == "/api/peer/config":
                if not _auth_ok(self, cfg):
                    _reply_json(self, {"status": "forbidden"}, 403)
                    return
                _reply_json(
                    self,
                    {
                        "instance_id": cfg.get("instance_id"),
                        "instance_name": cfg.get("instance_name"),
                        "peer_role": cfg.get("peer_role"),
                        "monitor_count": len(cfg.get("monitors", [])),
                    },
                    200,
                )
                return
            if parsed.path == "/api/peer/diag":
                if not _auth_ok(self, cfg):
                    _reply_json(self, {"status": "forbidden"}, 403)
                    return
                q = parse_qs(parsed.query or "")
                view = (q.get("view", ["logs"])[0] or "logs").strip().lower()
                if view == "config":
                    _reply_json(self, {"config": load_config()}, 200)
                    return
                if view == "history":
                    _reply_json(self, {"history": load_json_file(_history_path(), [])}, 200)
                    return
                logs = _log_path().read_text(encoding="utf-8", errors="ignore") if _log_path().exists() else ""
                _reply_json(self, {"logs": logs[-8000:]}, 200)
                return
            _reply_json(self, {"status": "not_found"}, 404)

        def do_POST(self) -> None:  # noqa: N802
            cfg = load_config()
            if self.path == "/run-check":
                run_check_once(debug=None, interactive=False)
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
                return
            if self.path == "/peer/save-settings":
                length = int(self.headers.get("Content-Length", "0") or "0")
                raw = self.rfile.read(length).decode("utf-8", errors="replace")
                form = parse_qs(raw)
                role = (form.get("peer_role", ["standalone"])[0] or "standalone").strip().lower()
                if role not in PEER_ROLES:
                    role = "standalone"
                cfg["peer_role"] = role
                cfg["peer_master_url"] = (form.get("peer_master_url", [""])[0] or "").strip()
                token = (form.get("peering_token", [""])[0] or "").strip()
                if token:
                    cfg["peering_token"] = token
                save_config(cfg)
                append_ui_log(f"peer-settings | role={role}")
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
                return
            if self.path == "/api/peer/push":
                if not _auth_ok(self, cfg):
                    _reply_json(self, {"status": "forbidden"}, 403)
                    return
                data = _read_request_json(self)
                peer_id = str(data.get("instance_id", "") or "").strip() or uuid.uuid4().hex
                _save_peer_snapshot(peer_id, data)
                append_ui_log(f"peer-push | {peer_id}")
                _reply_json(self, {"status": "ok"}, 200)
                return
            if self.path == "/api/peer/register":
                if not _auth_ok(self, cfg):
                    _reply_json(self, {"status": "forbidden"}, 403)
                    return
                data = _read_request_json(self)
                peer_id = str(data.get("instance_id", "") or "").strip() or uuid.uuid4().hex
                current = load_json_file(_peer_dirs() / f"{peer_id}.json", {})
                current.update(
                    {
                        "instance_id": peer_id,
                        "instance_name": data.get("instance_name", peer_id),
                        "agent_url": data.get("agent_url", ""),
                        "role": "agent",
                        "updated_at": now_s(),
                    }
                )
                _save_peer_snapshot(peer_id, current)
                append_ui_log(f"peer-register | {current.get('instance_name')}")
                _reply_json(self, {"status": "ok", "registered": True}, 200)
                return
            if self.path == "/api/peer/create-monitor":
                if not _auth_ok(self, cfg):
                    _reply_json(self, {"status": "forbidden"}, 403)
                    return
                data = _read_request_json(self)
                m_name = str(data.get("name", "") or "").strip()
                m_mode = str(data.get("check_mode", "both") or "both").strip().lower()
                m_url = str(data.get("kuma_url", "") or "").strip()
                if not m_name or m_mode not in CHECK_MODES:
                    _reply_json(self, {"status": "error", "message": "invalid name/mode"}, 400)
                    return
                if not m_url:
                    _reply_json(self, {"status": "error", "message": "missing kuma_url"}, 400)
                    return
                if not m_url.startswith(("http://", "https://")):
                    m_url = "https://" + m_url
                m_url = normalize_kuma_url(m_url)
                err = validate_kuma_url(m_url)
                if err:
                    _reply_json(self, {"status": "error", "message": err}, 400)
                    return
                monitor = {
                    "name": m_name,
                    "check_mode": m_mode,
                    "kuma_url": m_url,
                    "devices": data.get("devices", []),
                    "mounts": data.get("mounts", []),
                    "probe_host": data.get("probe_host", ""),
                    "probe_port": int(data.get("probe_port", 443) or 443),
                    "dns_name": data.get("dns_name", ""),
                    "dns_server": data.get("dns_server", ""),
                }
                cfg.setdefault("monitors", []).append(monitor)
                save_config(cfg)
                append_ui_log(f"peer-create-monitor | {m_name} mode={m_mode}")
                _reply_json(self, {"status": "ok", "created": True}, 201)
                return
            _reply_json(self, {"status": "not_found"}, 404)

    return Handler


def run_ui_server(host: str, port: int) -> int:
    cfg = load_config()
    if not cfg.get("web_enabled", True):
        print("Web UI disabled by configuration.")
        print("This node is intended for agent-only mode with a master connection.")
        return 2
    handler = make_handler()
    srv = ThreadingHTTPServer((host, port), handler)
    append_ui_log(f"ui-start | http://{host}:{port}")
    print(f"UI listening on http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    append_ui_log("ui-stop")
    return 0


def run_scheduled_loop() -> int:
    print("Starting scheduled loop. Press Ctrl+C to stop.")
    while True:
        cfg = load_config()
        debug = bool(cfg.get("debug", False))
        run_check_once(debug=debug, interactive=False)
        sleep_s = int(cfg.get("cron_interval_minutes", 5) or 5) * 60
        sleep_s = max(60, sleep_s)
        time.sleep(sleep_s)


def ensure_agent_registration_background() -> None:
    cfg = load_config()
    if str(cfg.get("peer_role", "")).lower() != "agent":
        return
    master = str(cfg.get("peer_master_url", "")).strip()
    token = str(cfg.get("peering_token", "")).strip()
    if not master or not token:
        return
    payload = {
        "instance_id": cfg.get("instance_id"),
        "instance_name": cfg.get("instance_name"),
        "agent_url": _parse_base_url(f"http://{cfg.get('ui_host', '127.0.0.1')}:{int(cfg.get('ui_port', 8787) or 8787)}", 8787),
    }

    def _worker() -> None:
        status, body = _peer_http_request(master, token, "POST", "/api/peer/register", payload=payload, timeout=8)
        if 200 <= status < 300:
            append_ui_log("peer-register-client | success")
        else:
            append_ui_log(f"peer-register-client | failed status={status} body={body[:140]}")

    threading.Thread(target=_worker, daemon=True).start()


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=f"{APP_DISPLAY_NAME} for Uptime Kuma")
    p.add_argument("--run", action="store_true", help="Run checks once (legacy alias)")
    p.add_argument("--run-scheduled", action="store_true", help="Run checks once (scheduler target)")
    p.add_argument("--run-scheduled-loop", action="store_true", help="Run checks in loop")
    p.add_argument("--ui", action="store_true", help="Start web UI server")
    p.add_argument("--host", default=None, help="UI host")
    p.add_argument("--port", type=int, default=None, help="UI port")
    p.add_argument("--agent-menu", action="store_true", help="Run interactive menu in agent-only mode")
    p.add_argument("--debug", "-d", action="store_true", help="Enable debug for this run")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.run or args.run_scheduled:
        run_check_once(debug=args.debug, interactive=False)
        return 0
    if args.run_scheduled_loop:
        return run_scheduled_loop()
    if args.ui:
        cfg = load_config()
        host = args.host or str(cfg.get("ui_host", "0.0.0.0"))
        port = int(args.port or cfg.get("ui_port", 8787) or 8787)
        ensure_agent_registration_background()
        return run_ui_server(host, port)
    if args.agent_menu:
        return interactive_menu(agent_only=True)
    cfg = load_config()
    if not cfg.get("web_enabled", True):
        ok, reason = _agent_only_ready(cfg)
        if not ok:
            print(reason)
            print("Use: python3 unix-monitor.py --agent-menu")
            return 2
    return interactive_menu(agent_only=not cfg.get("web_enabled", True))


if __name__ == "__main__":
    sys.exit(main())
