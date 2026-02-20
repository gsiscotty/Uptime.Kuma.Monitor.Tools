#!/usr/bin/env python3

#########################################
# Author: Konrad von Burg               #
# Date: 2026-02-19                      #
# Description: Interactive menu script  #
# to monitor Synology NAS storage and   #
# SMART health and report to Kuma.      #
# Version: 1.0.0                        #
# Copyright (c) 2026 EasySystems GmbH   #
#                                       #
# Usage:                                #
#   python3 synology-monitor.py         #
#   python3 synology-monitor.py --run   #
#   python3 synology-monitor.py --run -d
#########################################

from __future__ import annotations

import sys as _sys

if _sys.version_info < (3, 8):
    print("ERROR: Python 3.8 or newer is required.", file=_sys.stderr)
    _sys.exit(1)

import http.client
import html
import json
import os
import base64
import cgi
import hashlib
import hmac
import re
import secrets
import ssl
import stat
import subprocess
import sys
import time
from io import BytesIO
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse
try:
    import pyotp  # type: ignore[import-not-found]
except Exception:
    pyotp = None
try:
    import qrcode  # type: ignore[import-not-found]
except Exception:
    qrcode = None
try:
    from werkzeug.security import check_password_hash, generate_password_hash  # type: ignore[import-not-found]
except Exception:
    def generate_password_hash(password: str) -> str:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200000).hex()
        return f"pbkdf2_sha256${salt}${digest}"

    def check_password_hash(stored: str, password: str) -> bool:
        try:
            alg, salt, digest = stored.split("$", 2)
            if alg != "pbkdf2_sha256":
                return False
            test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200000).hex()
            return hmac.compare_digest(test, digest)
        except Exception:
            return False


CONFIG_FILE_MODE = 0o600
CRON_MARKER = "# synology-monitor.py - do not edit this line manually"
INTERVAL_MIN = 1
INTERVAL_MAX = 1440
CHECK_MODES = ("smart", "storage", "both")
BACK_KEYS = ("0", "b", "back", "q", "quit")
CHANGES_NOTICE = "  Changes are not saved until you confirm (Save/Apply)."
ALLOWED_SCHEMES = ("https", "http")
KUMA_PUSH_PATH_PATTERN = re.compile(r"^/api/push/[A-Za-z0-9_-]+$")
UI_LOG_MAX_LINES = 200
UI_LOG_MSG_MAX_CHARS = 6000
NAS_VOLUME_PATTERN = re.compile(r"^/volume[0-9]+$")
SMART_CACHE_MAX_AGE_SEC = 20 * 60
TASK_STATUS_MAX_DETAIL = 2000
HISTORY_MAX_ENTRIES = 500
AUTH_FILE_MODE = 0o600
AUTH_COOKIE_NAME = "synology_auth"
AUTH_CHALLENGE_COOKIE_NAME = "synology_auth_challenge"
AUTH_SESSION_TTL_SEC = 1800
AUTH_CHALLENGE_TTL_SEC = 300
AUTH_MAX_LOGIN_ATTEMPTS = 5
AUTH_LOCKOUT_DURATION_SEC = 15 * 60
BRAND_NAME = "EasySystems GmbH"
PRODUCT_NAME = "EasySystems GmbH - Kuma Monitor Addon"
BRAND_URL = "https://www.easysystems.ch/de"
BRAND_LOGO_URL = "https://www.easysystems.ch/img/logo-blue.png"
BRAND_AUTHOR = "Konrad von Burg"
BRAND_COPYRIGHT = "Copyright (c) 2026 EasySystems GmbH. All rights reserved."
PRODUCT_DESC = (
    "Checks Synology NAS SMART and storage health, provides guided elevated-access setup and diagnostics, "
    "and pushes monitor status to Uptime Kuma."
)


def get_script_path() -> Path:
    return Path(__file__).resolve()


def get_auth_state_path() -> Path:
    return get_runtime_data_dir() / "synology-auth.json"


def _default_auth_state() -> Dict[str, Any]:
    return {
        "auth_initialized": False,
        "password_hash": "",
        "totp_secret": "",
        "recovery_hashes": [],
        "failed_attempts": 0,
        "lockout_until": 0,
        "session_secret": secrets.token_hex(32),
    }


def _load_auth_state() -> Dict[str, Any]:
    p = get_auth_state_path()
    if not p.exists():
        data = _default_auth_state()
        _save_auth_state(data)
        return data
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("auth state invalid")
    except Exception:
        data = _default_auth_state()
        _save_auth_state(data)
    if "session_secret" not in data or not str(data.get("session_secret", "")).strip():
        data["session_secret"] = secrets.token_hex(32)
        _save_auth_state(data)
    return data


def _save_auth_state(data: Dict[str, Any]) -> None:
    p = get_auth_state_path()
    tmp = p.parent / ".synology-auth.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, AUTH_FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(str(tmp), str(p))
        p.chmod(AUTH_FILE_MODE)
    except OSError:
        pass


def _hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode("utf-8")).hexdigest()


def _generate_recovery_codes(count: int = 10) -> List[str]:
    out = []
    for _ in range(count):
        raw = secrets.token_hex(4).upper()
        out.append(f"{raw[:4]}-{raw[4:]}")
    return out


def _issue_recovery_hashes(codes: List[str]) -> List[Dict[str, Any]]:
    return [{"hash": _hash_recovery_code(c), "used": False} for c in codes]


def _totp_available() -> Tuple[bool, str]:
    # TOTP works with pyotp when available, but we keep an internal fallback
    # so DSM deployments do not require extra pip installation.
    return True, ""


def _generate_totp_secret() -> str:
    if pyotp is not None:
        return str(pyotp.random_base32())
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(alphabet) for _ in range(32))


def _build_totp_uri(secret: str, account_name: str = "synology-admin") -> str:
    if not secret:
        return ""
    if pyotp is not None:
        return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=PRODUCT_NAME)
    label = quote(f"{PRODUCT_NAME}:{account_name}")
    issuer = quote(PRODUCT_NAME)
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def _totp_code_at(secret: str, timestamp: int, period: int = 30) -> Optional[str]:
    try:
        padded = secret.strip().upper() + "=" * (-len(secret.strip()) % 8)
        key = base64.b32decode(padded, casefold=True)
    except Exception:
        return None
    counter = int(timestamp // period)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code_int = (
        ((digest[off] & 0x7F) << 24)
        | ((digest[off + 1] & 0xFF) << 16)
        | ((digest[off + 2] & 0xFF) << 8)
        | (digest[off + 3] & 0xFF)
    )
    return f"{code_int % 1000000:06d}"


def _build_qr_data_uri(uri: str) -> str:
    if not uri or qrcode is None:
        return ""
    qr = qrcode.QRCode(version=1, box_size=8, border=3)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def _verify_totp_token(secret: str, token: str) -> bool:
    if not secret:
        return False
    tok = re.sub(r"\s+", "", token or "")
    if not re.match(r"^\d{6}$", tok):
        return False
    if pyotp is not None:
        return bool(pyotp.TOTP(secret).verify(tok, valid_window=1))
    now = int(time.time())
    for window in (-1, 0, 1):
        code = _totp_code_at(secret, now + (window * 30))
        if code and hmac.compare_digest(code, tok):
            return True
    return False


def _is_locked(auth: Dict[str, Any]) -> Tuple[bool, int]:
    now = int(time.time())
    until = int(auth.get("lockout_until", 0) or 0)
    if until > now:
        return True, max(0, until - now)
    return False, 0


def _register_auth_failure(auth: Dict[str, Any]) -> None:
    attempts = int(auth.get("failed_attempts", 0) or 0) + 1
    auth["failed_attempts"] = attempts
    if attempts >= AUTH_MAX_LOGIN_ATTEMPTS:
        auth["lockout_until"] = int(time.time()) + AUTH_LOCKOUT_DURATION_SEC
        auth["failed_attempts"] = 0
    _save_auth_state(auth)


def _register_auth_success(auth: Dict[str, Any]) -> None:
    auth["failed_attempts"] = 0
    auth["lockout_until"] = 0
    _save_auth_state(auth)


def _sign_payload(payload: Dict[str, Any], secret: str) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    sig = hmac.new(secret.encode("utf-8"), b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def _verify_signed_payload(token: str, secret: str) -> Optional[Dict[str, Any]]:
    try:
        b64, sig = token.split(".", 1)
    except ValueError:
        return None
    expected = hmac.new(secret.encode("utf-8"), b64.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        padded = b64 + "=" * (-len(b64) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    exp = int(data.get("exp", 0) or 0)
    if exp and exp < int(time.time()):
        return None
    return data


def _auth_initialized(auth: Optional[Dict[str, Any]] = None) -> bool:
    state = auth or _load_auth_state()
    return bool(state.get("auth_initialized")) and bool(state.get("password_hash")) and bool(state.get("totp_secret"))


def _consume_recovery_code(auth: Dict[str, Any], code: str) -> bool:
    target = _hash_recovery_code(code)
    hashes = auth.get("recovery_hashes", [])
    if not isinstance(hashes, list):
        return False
    for row in hashes:
        if not isinstance(row, dict):
            continue
        if bool(row.get("used")):
            continue
        if hmac.compare_digest(str(row.get("hash", "")), target):
            row["used"] = True
            _save_auth_state(auth)
            return True
    return False


def _count_unused_recovery(auth: Dict[str, Any]) -> int:
    hashes = auth.get("recovery_hashes", [])
    if not isinstance(hashes, list):
        return 0
    return len([x for x in hashes if isinstance(x, dict) and not bool(x.get("used"))])


def get_config_path() -> Path:
    script_dir = get_script_path().parent
    home_config = Path.home() / ".config" / "synology-monitor.json"
    package_var = Path("/var/packages/synology-monitor/var/synology-monitor.json")
    if package_var.exists():
        return package_var
    script_local = script_dir / "synology-monitor.json"
    if script_local.exists():
        return script_local
    if home_config.exists():
        return home_config
    if package_var.parent.exists() and os.access(str(package_var.parent), os.W_OK):
        return package_var
    if os.access(str(script_dir), os.W_OK):
        return script_local
    home_config.parent.mkdir(parents=True, exist_ok=True)
    return home_config


def _legacy_config_candidates(active: Path) -> List[Path]:
    script_local = get_script_path().parent / "synology-monitor.json"
    home_config = Path.home() / ".config" / "synology-monitor.json"
    candidates = [script_local, home_config]
    return [p for p in candidates if p != active and p.exists()]


def _read_json_file(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _migrate_config_if_needed(active_path: Path) -> bool:
    if active_path.exists():
        return False
    for cand in _legacy_config_candidates(active_path):
        data = _read_json_file(cand)
        if data and data.get("monitors"):
            try:
                active_path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(str(active_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, CONFIG_FILE_MODE)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                append_ui_log(f"config-migrate | imported monitors from {cand}")
                return True
            except OSError:
                continue
    return False


def get_runtime_data_dir() -> Path:
    script_dir = get_script_path().parent
    package_var_dir = Path("/var/packages/synology-monitor/var")
    home_dir = Path.home() / ".config" / "synology-monitor"
    candidates = [package_var_dir, script_dir, home_dir]
    for d in candidates:
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        if d.exists() and os.access(str(d), os.R_OK | os.W_OK):
            return d
    return script_dir


def get_ui_log_path() -> Path:
    return get_runtime_data_dir() / "synology-monitor-ui.log"


def append_ui_log(message: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    if len(message) > UI_LOG_MSG_MAX_CHARS:
        message = message[: UI_LOG_MSG_MAX_CHARS - 3] + "..."
    line = f"{ts} | {message}\n"
    path = get_ui_log_path()
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
        if path.exists():
            current = stat.S_IMODE(path.stat().st_mode)
            if current != CONFIG_FILE_MODE:
                path.chmod(CONFIG_FILE_MODE)
    except OSError:
        pass


def read_ui_log(max_lines: int = UI_LOG_MAX_LINES, log_filter: str = "all") -> str:
    path = get_ui_log_path()
    if not path.exists():
        return "No log entries yet."
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        filt = (log_filter or "all").strip().lower()
        if filt in ("smart", "storage"):
            key = "smart" if filt == "smart" else "storage"
            lines = [ln for ln in lines if key in ln.lower()]
        tail = lines[-max_lines:]
        return "".join(tail).strip() or "No log entries yet."
    except OSError as e:
        return f"Failed to read log: {type(e).__name__}: {e}"


def clear_ui_log() -> None:
    path = get_ui_log_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("")
        path.chmod(CONFIG_FILE_MODE)
    except OSError:
        pass


def get_smart_cache_path() -> Path:
    return get_runtime_data_dir() / "synology-smart-cache.json"


def get_system_log_cache_path() -> Path:
    return get_runtime_data_dir() / "synology-system-log-cache.json"


def _write_smart_cache(payload: Dict[str, Any]) -> None:
    path = get_smart_cache_path()
    tmp = path.parent / ".synology-smart-cache.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(str(tmp), str(path))
        path.chmod(0o644)
    except OSError:
        pass


def _write_system_log_cache(payload: Dict[str, Any]) -> None:
    path = get_system_log_cache_path()
    tmp = path.parent / ".synology-system-log-cache.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(str(tmp), str(path))
        path.chmod(0o644)
    except OSError:
        pass


def _read_smart_cache() -> Optional[Dict[str, Any]]:
    path = get_smart_cache_path()
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _read_system_log_cache() -> Optional[Dict[str, Any]]:
    path = get_system_log_cache_path()
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def get_smart_helper_script_path() -> Path:
    return get_script_path().parent / "smart-helper.sh"


def get_task_guide_images() -> Dict[str, Path]:
    base = get_script_path().parent
    return {
        "task-scheduler-guide.png": base / "task-scheduler-guide.png",
        "task-step-general.png": base / "task-step-general.png",
        "task-step-schedule.png": base / "task-step-schedule.png",
        "task-step-command.png": base / "task-step-command.png",
    }


def get_task_status_path() -> Path:
    return get_runtime_data_dir() / "synology-task-status.json"


def _write_task_status(payload: Dict[str, Any]) -> None:
    path = get_task_status_path()
    tmp = path.parent / ".synology-task-status.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(str(tmp), str(path))
        path.chmod(0o644)
    except OSError:
        pass


def _read_task_status() -> Optional[Dict[str, Any]]:
    path = get_task_status_path()
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _detect_task_hint() -> str:
    helper = str(get_smart_helper_script_path())
    for crontab_path in ("/etc/crontab", "/etc/crontab.user"):
        try:
            text = Path(crontab_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if helper in text:
            return f"Found helper reference in {crontab_path}"
    return "No task hint detected in system crontab files"


def get_history_path() -> Path:
    return get_runtime_data_dir() / "synology-monitor-history.json"


def get_monitor_state_path() -> Path:
    return get_runtime_data_dir() / "synology-monitor-state.json"


def get_schedule_state_path() -> Path:
    return get_runtime_data_dir() / "synology-schedule-state.json"


def _load_monitor_state() -> Dict[str, Dict[str, Any]]:
    p = get_monitor_state_path()
    if not p.exists():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        out: Dict[str, Dict[str, Any]] = {}
        for k, v in data.items():
            if isinstance(k, str) and isinstance(v, dict):
                out[k] = v
        return out
    except (OSError, json.JSONDecodeError):
        return {}


def _save_monitor_state(state: Dict[str, Dict[str, Any]]) -> None:
    p = get_monitor_state_path()
    tmp = p.parent / ".synology-monitor-state.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(str(tmp), str(p))
        p.chmod(0o644)
    except OSError:
        pass


def _set_monitor_state(name: str, banner: str, output: str, level: str = "ok") -> None:
    state = _load_monitor_state()
    state[name] = {
        "banner": banner,
        "output": output,
        "level": "err" if level == "err" else "ok",
        "updated_at": int(time.time()),
    }
    _save_monitor_state(state)


def _is_scheduled_due(interval_minutes: int) -> bool:
    if interval_minutes < 1:
        interval_minutes = 1
    p = get_schedule_state_path()
    now = int(time.time())
    try:
        if p.exists():
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            last_run = int(data.get("last_run_ts", 0) or 0)
            if now - last_run < interval_minutes * 60:
                return False
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        pass
    return True


def _touch_scheduled_run() -> None:
    p = get_schedule_state_path()
    tmp = p.parent / ".synology-schedule-state.json.tmp"
    payload = {"last_run_ts": int(time.time())}
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(str(tmp), str(p))
        p.chmod(0o644)
    except OSError:
        pass


def _read_schedule_state() -> Dict[str, Any]:
    p = get_schedule_state_path()
    if not p.exists():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _scheduler_pid_path() -> Path:
    return Path("/var/packages/synology-monitor/target/scheduler.pid")


def _scheduler_service_path() -> Path:
    return Path("/var/packages/synology-monitor/scripts/start-stop-status")


def _scheduler_status_text(cfg: Dict[str, Any]) -> str:
    interval = int(cfg.get("cron_interval_minutes", 60) or 60)
    cron_enabled = bool(cfg.get("cron_enabled", False))
    pid_path = _scheduler_pid_path()
    pid_text = "missing"
    running = False
    if pid_path.exists():
        try:
            pid = int(pid_path.read_text(encoding="utf-8", errors="ignore").strip() or "0")
            pid_text = str(pid) if pid > 0 else "invalid"
            if pid > 0:
                try:
                    os.kill(pid, 0)
                    running = True
                except OSError:
                    running = False
        except (OSError, ValueError):
            pid_text = "invalid"
    state = _read_schedule_state()
    last_ts = int(state.get("last_run_ts", 0) or 0)
    last_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_ts)) if last_ts else "never"
    due_text = "yes" if _is_scheduled_due(interval) else "no"
    helper_ok, helper_msg = get_smart_helper_status()
    lines = [
        f"Scheduler process: {'running' if running else 'not running'} (pid={pid_text})",
        f"Automatic checks enabled: {'yes' if cron_enabled else 'no'}",
        f"Configured interval: {interval} minute(s)",
        f"Last scheduled run: {last_text}",
        f"Due now: {due_text}",
        f"SMART elevated cache: {'active' if helper_ok else 'inactive'} | {helper_msg}",
        f"Scheduler service script: {_scheduler_service_path()}",
    ]
    return "\n".join(lines)


def _load_history() -> List[Dict[str, Any]]:
    p = get_history_path()
    if not p.exists():
        return []
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        return []
    except (OSError, json.JSONDecodeError):
        return []


def _save_history(entries: List[Dict[str, Any]]) -> None:
    p = get_history_path()
    tmp = p.parent / ".synology-monitor-history.json.tmp"
    trimmed = entries[-HISTORY_MAX_ENTRIES:]
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(trimmed, f, indent=2)
        os.replace(str(tmp), str(p))
        p.chmod(0o644)
    except OSError:
        pass


def _prune_ui_log_for_monitor(name: str) -> None:
    path = get_ui_log_path()
    if not path.exists():
        return
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        keep: List[str] = []
        needle = name.strip()
        for ln in lines:
            low = ln.lower()
            # Remove monitor-specific lines while keeping global diagnostics.
            if f"| {needle} |" in ln or f"{needle}:" in ln:
                continue
            if "delete-monitor" in low and needle in ln:
                continue
            keep.append(ln)
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(keep[-UI_LOG_MAX_LINES * 3 :])
        path.chmod(CONFIG_FILE_MODE)
    except OSError:
        pass


def _delete_monitor_runtime_data(name: str) -> None:
    # Remove history entries for this monitor so "last run" does not carry over.
    entries = _load_history()
    filtered = [e for e in entries if str(e.get("monitor", "")) != name]
    if len(filtered) != len(entries):
        _save_history(filtered)

    # Remove persistent monitor card status/result banner.
    state = _load_monitor_state()
    if name in state:
        state.pop(name, None)
        _save_monitor_state(state)

    # Remove monitor-related lines from UI log.
    _prune_ui_log_for_monitor(name)


def _record_history(monitor_name: str, mode: str, status: str, ping_ms: float) -> None:
    now = int(time.time())
    entries = _load_history()
    channels = ["smart", "storage"] if mode == "both" else [mode]
    for channel in channels:
        entries.append(
            {
                "ts": now,
                "monitor": monitor_name,
                "mode": mode,
                "channel": channel,
                "status": status,
                "ping_ms": round(float(ping_ms), 2),
            }
        )
    _save_history(entries)


def _tail_text_file(path: Path, max_lines: int = 120) -> str:
    if not path.exists():
        return f"{path}: missing"
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        tail = "".join(lines[-max_lines:]).strip()
        return tail if tail else f"{path}: empty"
    except OSError as e:
        return f"{path}: {type(e).__name__}: {e}"


def _extract_error_lines(text: str, max_lines: int = 80) -> str:
    patt = re.compile(r"(error|fail|failed|warning|warn|traceback|permission denied|exception)", re.IGNORECASE)
    lines = [ln for ln in (text or "").splitlines() if patt.search(ln)]
    if not lines:
        return "No error/warning lines found."
    return "\n".join(lines[-max_lines:])


def _build_task_diag_text(cfg: Dict[str, Any]) -> str:
    interval = int(cfg.get("cron_interval_minutes", 60) or 60)
    cron_enabled = bool(cfg.get("cron_enabled", False))
    sched_state = _read_schedule_state()
    last_sched = int(sched_state.get("last_run_ts", 0) or 0)
    last_sched_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_sched)) if last_sched else "never"

    pid_path = _scheduler_pid_path()
    pid_val = 0
    running = False
    if pid_path.exists():
        try:
            pid_val = int(pid_path.read_text(encoding="utf-8", errors="ignore").strip() or "0")
            if pid_val > 0:
                try:
                    os.kill(pid_val, 0)
                    running = True
                except OSError:
                    running = False
        except (OSError, ValueError):
            pid_val = 0

    helper_ok, helper_msg = get_smart_helper_status()
    cache = _read_smart_cache() or {}
    helper_checked = int(cache.get("checked_at", 0) or 0)
    helper_checked_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(helper_checked)) if helper_checked else "never"

    rc, out = _run_cmd(["crontab", "-l"], timeout_sec=8)
    if rc == 0:
        cron_lines = [ln for ln in out.splitlines() if "synology-monitor" in ln]
        cron_text = "\n".join(cron_lines) if cron_lines else "(no synology-monitor crontab entries)"
    else:
        cron_text = f"(crontab unavailable rc={rc})"

    auto_task = _read_task_status()
    auto_task_text = json.dumps(auto_task, indent=2) if auto_task else "No auto-create task attempts recorded."

    helper_log = Path("/var/packages/synology-monitor/target/smart-helper.log")
    sched_log = Path("/var/packages/synology-monitor/target/monitor-scheduler.log")
    return (
        "Automation Overview\n"
        f"- automatic checks enabled: {'yes' if cron_enabled else 'no'}\n"
        f"- configured interval: {interval} minute(s)\n"
        f"- scheduler process: {'running' if running else 'not running'} (pid={pid_val or 'n/a'})\n"
        f"- last scheduled run: {last_sched_text}\n"
        f"- helper cache status: {'active' if helper_ok else 'inactive'}\n"
        f"- helper cache last refresh: {helper_checked_text}\n"
        f"- helper message: {helper_msg}\n\n"
        "Crontab entries (synology-monitor)\n"
        f"{cron_text}\n\n"
        "Auto-create task status\n"
        f"{auto_task_text}\n\n"
        "Scheduler log (tail)\n"
        f"{_tail_text_file(sched_log)}\n\n"
        "SMART helper log (tail)\n"
        f"{_tail_text_file(helper_log)}"
    )


def _build_system_diag_text() -> str:
    ui_log = _tail_text_file(get_ui_log_path(), max_lines=200)
    helper_log = _tail_text_file(Path("/var/packages/synology-monitor/target/smart-helper.log"), max_lines=160)
    sched_log = _tail_text_file(Path("/var/packages/synology-monitor/target/monitor-scheduler.log"), max_lines=160)
    sys_cache = _read_system_log_cache() or {}
    cache_checked = int(sys_cache.get("checked_at", 0) or 0)
    cache_checked_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cache_checked)) if cache_checked else "never"
    cache_age = max(0, int(time.time()) - cache_checked) if cache_checked else -1
    system_log_text = ""
    if sys_cache:
        src = str(sys_cache.get("source", "unknown"))
        errs = str(sys_cache.get("errors", "") or "No error/warning lines found.")
        system_log_text = f"Cached by root helper @ {cache_checked_text} (age={cache_age}s)\nSource: {src}\n{errs}"
    else:
        system_log_text = "No root system-log cache yet. Run system-log helper once or wait for scheduler."

    return (
        "Package UI log (tail)\n"
        f"{ui_log}\n\n"
        "Scheduler errors/warnings (filtered)\n"
        f"{_extract_error_lines(sched_log, max_lines=80)}\n\n"
        "SMART helper errors/warnings (filtered)\n"
        f"{_extract_error_lines(helper_log, max_lines=80)}\n\n"
        "System log errors/warnings (filtered)\n"
        f"{system_log_text}"
    )


def _build_diag_text(cfg: Dict[str, Any], history: List[Dict[str, Any]], diag_view: str, log_filter: str) -> str:
    view = (diag_view or "logs").strip().lower()
    if view == "task":
        return _build_task_diag_text(cfg)
    if view == "config":
        return json.dumps(cfg, indent=2)
    if view == "cache":
        cache = _read_smart_cache()
        return json.dumps(cache, indent=2) if cache else "No SMART helper cache yet."
    if view == "history":
        return json.dumps(history[-120:], indent=2) if history else "No run history yet."
    if view == "paths":
        details = {
            "config_path": str(get_config_path()),
            "ui_log_path": str(get_ui_log_path()),
            "smart_cache_path": str(get_smart_cache_path()),
            "system_log_cache_path": str(get_system_log_cache_path()),
            "task_status_path": str(get_task_status_path()),
            "helper_script_path": str(get_smart_helper_script_path()),
            "task_hint": _detect_task_hint(),
        }
        return json.dumps(details, indent=2)
    if view == "system":
        return _build_system_diag_text()
    return read_ui_log(log_filter=log_filter)


def _build_live_snapshot() -> Dict[str, Any]:
    cfg = load_config()
    history = _load_history()
    state = _load_monitor_state()

    channel_data: Dict[str, Dict[str, Any]] = {}
    for channel in ("smart", "storage"):
        items = [e for e in history if str(e.get("channel")) == channel]
        latest = items[-1] if items else {}
        st = str(latest.get("status", "unknown"))
        pct = {"up": 100, "warning": 55, "down": 15}.get(st, 0)
        ts = int(latest.get("ts", 0) or 0)
        channel_data[channel] = {
            "status": st,
            "pct": pct,
            "ts": ts,
            "history_statuses": [str(x.get("status", "unknown")) for x in items[-20:]],
        }

    monitor_latest: Dict[str, Dict[str, Any]] = {}
    for e in history:
        name = str(e.get("monitor", ""))
        if name:
            monitor_latest[name] = e

    monitors: List[Dict[str, Any]] = []
    for m in cfg.get("monitors", []):
        name = str(m.get("name", "?"))
        mode = str(m.get("check_mode", "both"))
        latest = monitor_latest.get(name, {})
        st = str(latest.get("status", "unknown"))
        ping = latest.get("ping_ms", "n/a")
        ts = int(latest.get("ts", 0) or 0)
        s = state.get(name, {})
        monitors.append(
            {
                "name": name,
                "mode": mode,
                "status": st,
                "ping_ms": ping,
                "ts": ts,
                "banner": str(s.get("banner", "") or ""),
                "output": str(s.get("output", "") or ""),
                "level": "err" if str(s.get("level", "ok")) == "err" else "ok",
            }
        )

    return {"generated_at": int(time.time()), "channels": channel_data, "monitors": monitors}


def get_smart_helper_status() -> Tuple[bool, str]:
    if os.geteuid() == 0:
        return True, "Package is running as root."
    cache = _read_smart_cache()
    if not cache:
        return False, "No root helper cache found yet."
    checked_at = int(cache.get("checked_at", 0) or 0)
    age = max(0, int(time.time()) - checked_at)
    if age <= SMART_CACHE_MAX_AGE_SEC:
        return True, f"Root helper cache is active (age {age}s)."
    return False, f"Root helper cache is stale (age {age}s)."


def _ui_auto_create_task_beta() -> str:
    helper_script = str(get_smart_helper_script_path())
    if not Path(helper_script).exists():
        msg = f"Helper script not found: {helper_script}"
        append_ui_log(f"auto-task | failed | {msg}")
        _write_task_status(
            {
                "attempted_at": int(time.time()),
                "success": False,
                "summary": msg,
                "detail": msg,
            }
        )
        return msg

    attempts: List[str] = []
    success = False
    summary = "Auto-create task failed; use manual Task Scheduler setup."

    # Attempt 1: create non-root cron entry for current package user.
    cron_line = f"*/5 * * * * {helper_script} # synology-monitor smart helper beta"
    rc, out = _run_cmd(["crontab", "-l"], timeout_sec=8)
    if rc == 127:
        attempts.append("crontab: command not found")
    else:
        current = out if rc == 0 else ""
        if cron_line not in current:
            new_cron = (current.rstrip() + "\n" + cron_line + "\n").lstrip("\n")
            try:
                p = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
                p.communicate(new_cron)
                if p.returncode == 0:
                    success = True
                    summary = "Created package-user cron task. Change user to root in DSM Task Scheduler if needed."
                    attempts.append("crontab: created package-user cron entry")
                else:
                    attempts.append("crontab: failed to install entry")
            except OSError as e:
                attempts.append(f"crontab: failed to execute ({type(e).__name__}: {e})")
        else:
            success = True
            summary = "Cron entry already exists for helper script."
            attempts.append("crontab: entry already exists")

    # Attempt 2: probe TaskScheduler API availability for diagnostics (best-effort).
    rc, out = _run_cmd(
        ["synowebapi", "--exec", "api=SYNO.Core.TaskScheduler", "version=1", "method=list"],
        timeout_sec=10,
    )
    probe_line = f"synowebapi probe rc={rc}"
    if out.strip():
        probe_line += f" detail={out.strip().replace(chr(10), ' ')[:300]}"
    attempts.append(probe_line)

    detail = " | ".join(attempts)
    if len(detail) > TASK_STATUS_MAX_DETAIL:
        detail = detail[: TASK_STATUS_MAX_DETAIL - 3] + "..."
    _write_task_status(
        {
            "attempted_at": int(time.time()),
            "success": success,
            "summary": summary,
            "detail": detail,
        }
    )
    append_ui_log(f"auto-task | {'success' if success else 'failed'} | {summary}")
    append_ui_log(f"auto-task-detail | {detail}")
    return summary + "\n" + detail


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


def kuma_token_label(url: str) -> str:
    parsed = urlparse(url.strip())
    m = re.match(r"^/api/push/([A-Za-z0-9_-]+)$", parsed.path or "")
    if not m:
        return "(invalid token path)"
    token = m.group(1)
    if len(token) <= 10:
        return token
    return f"{token[:5]}...{token[-4:]}"


def load_config() -> Dict[str, Any]:
    path = get_config_path()
    if not path.exists():
        _migrate_config_if_needed(path)
    if not path.exists():
        return {"monitors": []}
    _enforce_config_permissions(path)
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  Config error: {e}")
        return {"monitors": []}

    changed = False
    monitors = [m for m in cfg.get("monitors", []) if isinstance(m, dict)]
    for monitor in monitors:
        cleaned = normalize_kuma_url(monitor.get("kuma_url", ""))
        if cleaned != monitor.get("kuma_url", ""):
            monitor["kuma_url"] = cleaned
            changed = True
        mode = str(monitor.get("check_mode", "both")).lower()
        if mode not in CHECK_MODES:
            monitor["check_mode"] = "both"
            changed = True

    # Normalize legacy duplicate monitor names: keep the newest definition by name.
    seen: set[str] = set()
    dedup_rev: List[Dict[str, Any]] = []
    for m in reversed(monitors):
        name = str(m.get("name", "")).strip()
        if not name:
            name = f"{str(m.get('check_mode', 'both')).lower()}-synology-check"
            m["name"] = name
            changed = True
        if name in seen:
            changed = True
            continue
        seen.add(name)
        dedup_rev.append(m)
    deduped = list(reversed(dedup_rev))
    if deduped != monitors:
        cfg["monitors"] = deduped
        changed = True

    if changed:
        save_config(cfg, reapply_cron=False)
    return cfg


def save_config(cfg: Dict[str, Any], reapply_cron: bool = True) -> None:
    path = get_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / ".synology-monitor.json.tmp"
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


def _has_synology_tools() -> Tuple[bool, str]:
    rc, _ = _run_cmd(["synospace", "--help"], timeout_sec=6)
    if rc == 127:
        return False, "synospace not found (run this on a Synology NAS)"
    return True, ""


def _check_storage_fallback(debug: bool = False) -> Tuple[str, List[str]]:
    status = "up"
    lines: List[str] = []
    fs_stats: List[Tuple[int, str, str]] = []

    rc, out = _run_cmd(["df", "-P"], timeout_sec=10)
    if rc != 0:
        return "down", [f"Fallback df failed: {out.strip()}"]

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
        fs_stats.append((pct, mpoint, fs))
        if pct >= 98:
            status = "down"
            lines.append(f"FS {mpoint} ({fs}): {pct}% used (critical)")
        elif pct >= 90 and _severity(status) < _severity("warning"):
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

    fs_count = len(fs_stats)
    if fs_stats:
        top_pct, top_mp, top_fs = sorted(fs_stats, reverse=True)[0]
        lines.insert(0, f"Fallback probe: scanned {fs_count} filesystems, max usage {top_pct}% on {top_mp} ({top_fs})")
        nas_volumes = sorted([(pct, mpoint, fs) for (pct, mpoint, fs) in fs_stats if NAS_VOLUME_PATTERN.match(mpoint)], key=lambda x: x[1])
        other_mounts = sorted([(pct, mpoint, fs) for (pct, mpoint, fs) in fs_stats if not NAS_VOLUME_PATTERN.match(mpoint)], key=lambda x: x[1])

        if nas_volumes:
            lines.append("NAS volumes checked:")
            for pct, mpoint, fs in nas_volumes:
                lines.append(f"  {mpoint} ({fs}) used={pct}%")
        else:
            lines.append("NAS volumes checked: none detected")

        if other_mounts:
            lines.append("Other mounts checked:")
            for pct, mpoint, fs in other_mounts:
                lines.append(f"  {mpoint} ({fs}) used={pct}%")
    else:
        lines.insert(0, "Fallback probe: no usable filesystems from df output")

    if not lines:
        lines.append("Fallback storage checks OK (usage/RAID)")
    if debug:
        print(f"    [storage:fallback] status={status}")
    return status, lines


def _detect_synology_devices() -> Dict[str, List[str]]:
    sata_devices = sorted(str(p) for p in Path("/dev").glob("sata[0-9]*") if p.is_block_device())
    if sata_devices:
        block_devices: List[str] = []
    else:
        block_devices = sorted(
            str(p) for p in Path("/dev").glob("sd*") if re.match(r"^/dev/sd[a-z]$", str(p))
        )
    scsi_devices = sorted(str(p) for p in Path("/dev").glob("sg*") if re.match(r"^/dev/sg[0-9]+$", str(p)))
    return {
        "sata": sata_devices,
        "block": block_devices,
        "scsi": scsi_devices,
    }


def _detect_nvme_devices() -> List[str]:
    rc, out = _run_cmd(["nvme", "list"], timeout_sec=8)
    if rc != 0:
        return []
    devs = []
    for line in out.splitlines():
        first = line.strip().split()[0] if line.strip() else ""
        if re.match(r"^/dev/nvme[0-9]+n[0-9]+$", first):
            devs.append(first)
    return sorted(set(devs))


def _missing_letter_devices(devices: List[str], first_expected: str) -> List[str]:
    present = set(devices)
    missing: List[str] = []
    letters = sorted([d[-1] for d in devices if re.match(r"^/dev/sd[a-z]$", d)])
    if not letters:
        return missing
    first = min(letters)
    last = max(letters)
    for code in range(ord(first), ord(last) + 1):
        dev = f"/dev/sd{chr(code)}"
        if dev == first_expected:
            continue
        if dev not in present:
            missing.append(dev)
    return missing


def _missing_numeric_devices(devices: List[str], prefix: str) -> List[str]:
    nums = sorted(int(re.search(r"(\d+)$", d).group(1)) for d in devices if re.search(r"(\d+)$", d))
    if not nums:
        return []
    missing = []
    for n in range(min(nums), max(nums) + 1):
        dev = f"{prefix}{n}"
        if dev not in devices:
            missing.append(dev)
    return missing


def check_smart(configured_devices: List[str], debug: bool = False) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    if os.name != "posix" or not sys.platform.startswith("linux"):
        return "down", ["SMART check supports Linux hosts only"], _latency_ms(t0)
    is_root = os.geteuid() == 0

    if not is_root:
        cache = _read_smart_cache()
        if cache:
            checked_at = int(cache.get("checked_at", 0) or 0)
            age = max(0, int(time.time()) - checked_at)
            if age <= SMART_CACHE_MAX_AGE_SEC:
                c_status = str(cache.get("status", "warning"))
                c_lines = [str(x) for x in cache.get("lines", []) if str(x).strip()]
                if not c_lines:
                    c_lines = ["SMART cache present but empty."]
                c_lines.insert(0, f"Using root SMART helper cache (age={age}s)")
                append_ui_log(f"smart-check | using root helper cache | age_sec={age} | status={c_status}")
                return c_status, c_lines, _latency_ms(t0)
            append_ui_log(f"smart-check | helper cache stale | age_sec={age}")
        else:
            append_ui_log("smart-check | helper cache missing")

    rc, out = _run_cmd(["smartctl", "--version"], timeout_sec=6)
    if rc != 0:
        return "down", [f"smartctl unavailable: {out.strip()}"], _latency_ms(t0)

    detected = _detect_synology_devices()
    auto_devices = detected["sata"] + detected["block"] + detected["scsi"]
    target_devices = configured_devices if configured_devices else auto_devices
    nvme_devices = _detect_nvme_devices()
    status = "up"
    lines: List[str] = []
    checked_any = 0
    permission_blocked = 0
    failed_any = 0

    if not is_root:
        lines.append("SMART running without root; some devices may be inaccessible")
        append_ui_log("smart-check | non-root execution detected")

    if not target_devices and not nvme_devices:
        return "down", ["No SATA/block/SCSI/NVMe devices detected"], _latency_ms(t0)

    # Preserve original Synology behavior: detect sequence gaps that often mean missing disks.
    for missing in _missing_letter_devices(detected["block"], "/dev/sda"):
        lines.append(f"Disk {missing}: MISSING (expected but not detected)")
        status = "down"
    for missing in _missing_numeric_devices(detected["scsi"], "/dev/sg"):
        if missing != "/dev/sg0":
            lines.append(f"Disk {missing}: MISSING (expected but not detected)")
            status = "down"

    for dev in target_devices:
        rc, info = _run_cmd(["smartctl", "-H", dev], timeout_sec=20)
        if re.search(r"permission denied|operation not permitted", info, flags=re.IGNORECASE):
            permission_blocked += 1
            lines.append(f"Disk {dev}: permission denied")
            append_ui_log(f"smart-check | {dev} | permission denied")
            continue
        ok = bool(re.search(r"\bPASSED\b|SMART Health Status:\s*OK", info, flags=re.IGNORECASE))
        if debug:
            print(f"    [smart] {dev}: rc={rc} ok={ok}")
        checked_any += 1
        if ok:
            lines.append(f"Disk {dev}: PASSED (healthy)")
        else:
            failed_any += 1
            msg = info.strip().splitlines()[-1] if info.strip() else "health check failed"
            lines.append(f"Disk {dev}: FAILED ({msg})")
            append_ui_log(f"smart-check | {dev} | FAILED | detail={msg}")

    if nvme_devices:
        rc, _ = _run_cmd(["nvme", "version"], timeout_sec=6)
        if rc != 0:
            status = "down"
            lines.append("NVMe tool unavailable: install nvme-cli")
        else:
            for dev in nvme_devices:
                rc, info = _run_cmd(["nvme", "smart-log", dev], timeout_sec=15)
                if re.search(r"permission denied|operation not permitted", info, flags=re.IGNORECASE):
                    permission_blocked += 1
                    lines.append(f"NVMe {dev}: permission denied")
                    append_ui_log(f"smart-check | {dev} | permission denied")
                    continue
                match = re.search(r"critical_warning\s*:\s*([0-9xa-fA-F]+)", info)
                critical = (match.group(1).lower() if match else "unknown")
                healthy = critical in ("0", "0x0")
                if debug:
                    print(f"    [nvme] {dev}: rc={rc} critical_warning={critical}")
                checked_any += 1
                if rc == 0 and healthy:
                    lines.append(f"NVMe {dev}: PASSED (healthy)")
                else:
                    failed_any += 1
                    lines.append(f"NVMe {dev}: FAILED (critical_warning={critical})")
                    append_ui_log(f"smart-check | {dev} | FAILED | critical_warning={critical}")

    if failed_any > 0:
        status = "down"
    elif permission_blocked > 0:
        status = "warning"
        lines.append("SMART partially unavailable due to permissions")
    elif checked_any == 0:
        status = "warning"
        lines.append("No SMART data collected")

    if not lines:
        lines.append("SMART checks OK")
    return status, lines, _latency_ms(t0)


def run_smart_helper() -> int:
    if os.geteuid() != 0:
        print("ERROR: --run-smart-helper requires root")
        append_ui_log("smart-helper | failed | requires root")
        return 1
    status, lines, _ = check_smart([], debug=False)
    payload = {
        "checked_at": int(time.time()),
        "status": status,
        "lines": lines,
    }
    _write_smart_cache(payload)
    append_ui_log(f"smart-helper | cache updated | status={status} | lines={len(lines)}")
    print(f"SMART helper cache updated: status={status}, lines={len(lines)}")
    return 0


def run_system_log_helper() -> int:
    if os.geteuid() != 0:
        print("ERROR: --run-system-log-helper requires root")
        append_ui_log("system-log-helper | failed | requires root")
        return 1
    source = ""
    raw = ""
    for p in (Path("/var/log/messages"), Path("/var/log/syslog")):
        if p.exists():
            source = str(p)
            raw = _tail_text_file(p, max_lines=400)
            break
    if not source:
        source = "(none)"
        raw = "No system log file found."
    errors = _extract_error_lines(raw, max_lines=140)
    payload = {
        "checked_at": int(time.time()),
        "source": source,
        "errors": errors,
    }
    _write_system_log_cache(payload)
    append_ui_log("system-log-helper | cache updated")
    print("System log helper cache updated.")
    return 0


def check_storage(debug: bool = False) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    ok_tools, err = _has_synology_tools()
    if not ok_tools:
        append_ui_log(f"storage-check | synospace unavailable | reason={err}")
        fb_status, fb_lines = _check_storage_fallback(debug=debug)
        fb_lines.insert(0, f"Synology storage command unavailable: {err}")
        return fb_status, fb_lines, _latency_ms(t0)

    rc, out = _run_cmd(["synospace", "--enum"], timeout_sec=20)
    if rc != 0 or not out.strip():
        err_text = out.strip() or "no output"
        if "PermissionError" in err_text or "Permission denied" in err_text:
            append_ui_log(f"storage-check | synospace permission denied | rc={rc} | detail={err_text}")
            fb_status, fb_lines = _check_storage_fallback(debug=debug)
            fb_lines.insert(0, "synospace permission denied; using fallback storage checks")
            return fb_status, fb_lines, _latency_ms(t0)
        append_ui_log(f"storage-check | synospace failed | rc={rc} | detail={err_text}")
        return "down", [f"Failed to retrieve storage status: {err_text}"], _latency_ms(t0)

    status = "up"
    lines: List[str] = []

    if re.search(r"Status:\s*\[(degraded|repairing|raid_parity_checking)\]", out):
        status = "warning"
        lines.append("Storage pools or volumes are repairing/parity checking")

    rebuild = re.search(r"(raid building mode=\[rebuilding\]\s*\([0-9]+/[0-9]+\))", out)
    if rebuild:
        if _severity(status) < _severity("warning"):
            status = "warning"
        lines.append(f"RAID rebuild in progress: {rebuild.group(1)}")

    if re.search(r"raid status=\[degraded\]", out):
        status = "down"
        lines.append("One or more RAID arrays are degraded")

    if not lines:
        lines.append("All storage pools, volumes, and RAID arrays are healthy")
    append_ui_log(f"storage-check | synospace OK | status={status} | lines={len(lines)}")
    if debug:
        print(f"    [storage] synospace lines: {len(out.splitlines())}")
    return status, lines, _latency_ms(t0)


def check_host(mode: str, devices: List[str], debug: bool = False) -> Tuple[str, str, float]:
    worst = "up"
    max_latency = 0.0
    sections: List[str] = []

    if mode in ("smart", "both"):
        s_status, s_lines, s_lat = check_smart(devices, debug=debug)
        max_latency = max(max_latency, s_lat)
        if _severity(s_status) > _severity(worst):
            worst = s_status
        sections.append("SMART:\n" + "\n".join(f"  - {x}" for x in s_lines))

    if mode in ("storage", "both"):
        st_status, st_lines, st_lat = check_storage(debug=debug)
        max_latency = max(max_latency, st_lat)
        if _severity(st_status) > _severity(worst):
            worst = st_status
        sections.append("Storage:\n" + "\n".join(f"  - {x}" for x in st_lines))

    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    msg = f"Synology check ({mode}) = {worst} @ {now}\n" + "\n".join(sections)
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
        detected = _detect_synology_devices()
        candidates = detected["sata"] + detected["block"] + detected["scsi"]
        if not candidates:
            print("No SATA/block/SCSI devices detected. Script will auto-detect at runtime.")
        else:
            print("\nDetected SMART devices:")
            for i, d in enumerate(candidates, 1):
                print(f"  [{i}] {d}")
            idxs = prompt_multi_indices(len(candidates), "Select device(s) for SMART")
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

    name = prompt_with_back("Monitor name", f"{mode}-synology-check")
    if name is None:
        return
    print(f"\nName: {name}\nMode: {mode}\nDevices: {', '.join(devices) if devices else '(auto)'}\nURL: {kuma_url}")
    if not confirm_save("Add monitor"):
        print("Discarded.")
        return

    cfg = load_config()
    cfg.setdefault("monitors", []).append(
        {"name": name, "check_mode": mode, "devices": devices, "kuma_url": kuma_url}
    )
    save_config(cfg)
    print(f"Added monitor '{name}'.")


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
            print(f"  x {name}: no Kuma URL")
            continue
        status, msg, lat = check_host(mode, devices, debug=dbg)
        ok = push_to_kuma(url, status, msg, lat, debug=dbg)
        _record_history(str(name), mode, status, lat)
        line = f"{'ok' if ok else 'x'} {name}: {status} (ping={lat:.2f}ms) push {'OK' if ok else 'FAILED'}"
        _set_monitor_state(
            str(name),
            "Automatic monitor check completed" if ok else "Automatic monitor check completed with errors",
            line,
            level="ok" if ok else "err",
        )
        append_ui_log(
            f"scheduled-check | {name} | mode={mode} | status={status} | ping_ms={lat:.2f} | push={'OK' if ok else 'FAILED'}"
        )
        print(f"  {'ok' if ok else 'x'} {name}: {status} (ping={lat:.2f}ms) push {'OK' if ok else 'FAILED'}")
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
        print(f"      Devices: {', '.join(m.get('devices', [])) or '(auto)'}")
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
    print("Removed.")


def manage_cron() -> None:
    cfg = load_config()
    enabled = cfg.get("cron_enabled", False)
    interval = int(cfg.get("cron_interval_minutes", 60))
    content, ok = get_current_crontab()
    has = ok and CRON_MARKER in content
    print("\n--- Automatic checks (cron) ---")
    print(CHANGES_NOTICE)
    if not ok:
        print("  crontab unavailable - manual setup required.")
    print(f"  Status: {'Enabled' if enabled or has else 'Disabled'} (every {interval} min)")
    print("\n  a) Enable automatic checks\n  b) Disable automatic checks\n  c) Change interval\n  d) Back")
    choice = prompt("Choice", "d").strip().lower()
    if choice == "a":
        if not cfg.get("monitors"):
            print("Add at least one monitor first.")
            return
        raw = prompt_with_back(f"Check interval (minutes, min {INTERVAL_MIN})", str(interval))
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
        print("Automatic checks enabled.")
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
        print("Automatic checks disabled.")
    elif choice == "c":
        raw = prompt_with_back(f"New interval (minutes, min {INTERVAL_MIN})", str(interval))
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
        print(f"Interval set to {new_interval} minutes.")


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
    msg = f"Test push @ {now} - {BRAND_NAME} synology-monitor connectivity check"
    for m in targets:
        ok = push_to_kuma(m.get("kuma_url", ""), "up", msg, 0, debug=True)
        print(f"  {'ok' if ok else 'x'} {m.get('name', '?')}: push {'OK' if ok else 'FAILED'}")
    print("\n  (Press Enter to go back)")
    input()


def toggle_debug() -> None:
    cfg = load_config()
    cfg["debug"] = not cfg.get("debug", False)
    save_config(cfg)
    print(f"\n  Debug mode: {'ON' if cfg['debug'] else 'OFF'}")


def _render_setup_html(
    message: str = "",
    error: str = "",
    action_output: str = "",
    log_filter: str = "all",
    edit_target: str = "",
    create_mode: bool = False,
    diag_view: str = "logs",
    show_setup_popup: bool = False,
    monitor_action_name: str = "",
    monitor_action_message: str = "",
    monitor_action_output: str = "",
    automation_message: str = "",
    automation_output: str = "",
    security_message: str = "",
    security_output: str = "",
    ssl_warning: str = "",
    ui_view: str = "overview",
    highlight_channel: str = "",
) -> str:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    interval = int(cfg.get("cron_interval_minutes", 60))
    cron_enabled = bool(cfg.get("cron_enabled", False))
    history = _load_history()
    monitor_state = _load_monitor_state()

    edit_monitor = _find_monitor_by_name(monitors, edit_target) if edit_target else None
    if create_mode and not edit_monitor:
        current_name = "both-synology-check"
        current_mode = "both"
        current_url = ""
    else:
        current_name = (
            str(edit_monitor.get("name", ""))
            if edit_monitor
            else (monitors[0].get("name", "synology-main") if monitors else "synology-main")
        )
        current_mode = (
            str(edit_monitor.get("check_mode", "both"))
            if edit_monitor
            else (monitors[0].get("check_mode", "both") if monitors else "both")
        )
        current_url = (
            str(edit_monitor.get("kuma_url", ""))
            if edit_monitor
            else (monitors[0].get("kuma_url", "") if monitors else "")
        )
    edit_original_name = str(edit_monitor.get("name", "")) if edit_monitor else ""

    status_html = ""
    if message and not monitor_action_name:
        status_html += f"<div class='ok'>{html.escape(message)}</div>"
    if error and not monitor_action_name:
        status_html += f"<div class='err'>{html.escape(error)}</div>"
    if action_output and not monitor_action_name:
        status_html += f"<pre>{html.escape(action_output)}</pre>"
    if ssl_warning:
        status_html = f"<div class='err'>{html.escape(ssl_warning)}</div>" + status_html
    log_text = _build_diag_text(cfg, history, diag_view=diag_view, log_filter=log_filter)
    automation_status = _scheduler_status_text(cfg)
    auth_state = _load_auth_state()
    recovery_unused = _count_unused_recovery(auth_state)

    elevated_ok, elevated_msg = get_smart_helper_status()
    elevated_css = "ok" if elevated_ok else "err"
    helper_script_path = str(get_smart_helper_script_path())
    task_status = _read_task_status()
    task_hint = _detect_task_hint()
    if task_status:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(task_status.get("attempted_at", 0) or 0)))
        task_state = "SUCCESS" if task_status.get("success") else "FAILED"
        task_summary = str(task_status.get("summary", ""))
        task_detail = str(task_status.get("detail", ""))
        task_status_text = f"Last auto-create: {task_state} @ {ts}\n{task_summary}\n{task_detail}\n{task_hint}"
    else:
        task_status_text = f"No auto-create attempt yet.\n{task_hint}"

    setup_open_attr = "" if elevated_ok else " open"
    setup_state_text = "Setup complete - section collapsed by default." if elevated_ok else "Setup required - complete the steps below."
    setup_state_css = "ok" if elevated_ok else "err"

    # Build monitor status map from history.
    monitor_latest: Dict[str, Dict[str, Any]] = {}
    for e in history:
        name = str(e.get("monitor", ""))
        if name:
            monitor_latest[name] = e

    def status_class(status: str) -> str:
        return {"up": "st-up", "warning": "st-warning", "down": "st-down"}.get(status, "st-unknown")

    def status_pct(status: str) -> int:
        return {"up": 100, "warning": 55, "down": 15}.get(status, 0)

    def status_label(status: str) -> str:
        return status.upper() if status in ("up", "warning", "down") else "UNKNOWN"

    # Overview gauges (smart + storage) with clickable filtering and monitor mapping.
    channel_cards: List[str] = []
    for channel in ("smart", "storage"):
        items = [e for e in history if str(e.get("channel")) == channel]
        latest = items[-1] if items else {}
        st = str(latest.get("status", "unknown"))
        pct = status_pct(st)
        last_ts = int(latest.get("ts", 0) or 0)
        ts_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_ts)) if last_ts else "n/a"
        dots = "".join(
            f"<span class='dot {status_class(str(x.get('status', 'unknown')))}' title='{html.escape(str(x.get('status', 'unknown')))}'></span>"
            for x in items[-20:]
        ) or "<span class='muted'>no history</span>"
        mapped = []
        for m in monitors:
            mode = str(m.get("check_mode", "both")).lower()
            if channel == "smart" and mode in ("smart", "both"):
                mapped.append(str(m.get("name", "?")))
            if channel == "storage" and mode in ("storage", "both"):
                mapped.append(str(m.get("name", "?")))
        mapped_count = len(mapped)
        if mapped_count == 0:
            mapped_text = "No monitors assigned"
        elif mapped_count == 1:
            mapped_text = f"Monitor: {mapped[0]}"
        else:
            mapped_text = f"Monitors: {mapped_count} (multiple)"
        mapped_title = ", ".join(mapped) if mapped else "No mapped monitors"
        is_hl = (highlight_channel == channel)
        channel_cards.append(
            f"<div class='overview-card {'hl-channel' if is_hl else ''}' data-channel='{channel}'>"
            f"<h4>{channel.capitalize()} Monitoring</h4>"
            f"<a class='gauge-link' href='/?log_filter={channel}&highlight={channel}'>"
            f"<div class='gauge {status_class(st)}' data-role='gauge' style='--pct:{pct}'>"
            f"<div class='gauge-center'><div class='gauge-value' data-role='gauge-value'>{status_label(st)}</div><div class='gauge-sub' data-role='gauge-sub'>{pct}%</div></div>"
            "</div>"
            "</a>"
            f"<div class='muted' data-role='channel-last'>Last update: {html.escape(ts_text)}</div>"
            f"<div class='muted' title='{html.escape(mapped_title)}'>{html.escape(mapped_text)}</div>"
            f"<div class='history-dots' data-role='channel-dots'>{dots}</div>"
            "</div>"
        )
    overview_html = "".join(channel_cards)

    # Setup steps with integrated screenshots.
    guide_images = get_task_guide_images()
    step_defs: List[Tuple[str, str, str, str]] = [
        ("STEP 1", "Open Task Scheduler", "Control Panel -> Task Scheduler.", "task-scheduler-guide.png"),
        ("STEP 2", "Set User root", "In General tab set user to root.", "task-step-general.png"),
        ("STEP 3", "Set Schedule", "Set repeat schedule (recommended every 5 minutes).", "task-step-schedule.png"),
        ("STEP 4", "Set Command", "Use helper script command shown below.", "task-step-command.png"),
        ("STEP 5", "Run Once", "Run the task once in DSM before access check.", ""),
        ("STEP 6", "Validate", "Press Check elevated access now.", ""),
    ]
    step_cards: List[str] = []
    gallery_urls: List[str] = []
    for step_num, title, desc, img_name in step_defs:
        img_html = ""
        p = guide_images.get(img_name) if img_name else None
        if p and p.exists():
            gallery_index = len(gallery_urls)
            gallery_urls.append(f"/guide-image?name={img_name}")
            img_html = (
                "<div class='guide-card'>"
                f"<a class='screenshot-link' href='#' data-gallery-index='{gallery_index}'>"
                f"<div class='img-wrap zoom-wrap'><img class='zoom-img' src='/guide-image?name={html.escape(img_name)}' alt='{html.escape(title)}'></div>"
                "</a>"
                f"<div class='guide-label'>{html.escape(title)}</div>"
                "</div>"
            )
        step_cards.append(
            "<div class='step-box'>"
            f"<div class='step-num'>{html.escape(step_num)}</div>"
            f"<div class='step-title'>{html.escape(title)}</div>"
            f"<div class='step-desc'>{html.escape(desc)}</div>"
            f"{img_html}"
            "</div>"
        )
    step_cards_html = "".join(step_cards)

    # Monitor cards with inline actions.
    monitor_cards: List[str] = []
    for m in monitors:
        name = str(m.get("name", "?"))
        mode = str(m.get("check_mode", "both"))
        url = str(m.get("kuma_url", ""))
        token_label = kuma_token_label(url)
        latest = monitor_latest.get(name, {})
        st = str(latest.get("status", "unknown"))
        ping = latest.get("ping_ms", "n/a")
        tsv = int(latest.get("ts", 0) or 0)
        ts_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tsv)) if tsv else "never"
        action_payload = monitor_state.get(name, {})
        action_banner = str(action_payload.get("banner", "") or "")
        action_output = str(action_payload.get("output", "") or "")
        action_level = "err" if str(action_payload.get("level", "ok")) == "err" else "ok"
        if monitor_action_name and monitor_action_name == name:
            action_banner = monitor_action_message or action_banner or "Action completed"
            action_output = monitor_action_output or action_output
            action_level = "err" if action_level == "err" else "ok"
        monitor_action_html = (
            f"<div class='{action_level}'>{html.escape(action_banner)}</div>"
            + (f"<pre>{html.escape(action_output)}</pre>" if action_output else "")
            if action_banner or action_output
            else ""
        )
        monitor_cards.append(
            f"<div class='monitor-card {'hl-monitor' if ((highlight_channel=='smart' and str(mode).lower() in ('smart','both')) or (highlight_channel=='storage' and str(mode).lower() in ('storage','both'))) else ''}' data-monitor='{html.escape(name)}' data-mode='{html.escape(str(mode).lower())}'>"
            + f"<div class='monitor-head'><div class='monitor-title'>{html.escape(name)}</div><span class='badge {status_class(st)}'>{status_label(st)}</span></div>"
            + f"<div class='monitor-meta' data-role='monitor-primary'>Mode: {html.escape(mode)} | Last ping: {html.escape(str(ping))} ms | Last run: {html.escape(ts_text)}</div>"
            + f"<div class='monitor-meta token-row'>Token: <code>{html.escape(token_label)}</code></div>"
            + f"<div data-role='monitor-live'>{monitor_action_html}</div>"
            + "<div class='button-row'>"
            + "<form method='post' action='/run-check-monitor'>"
            + f"<input type='hidden' name='monitor_name' value='{html.escape(name)}'>"
            + "<button type='submit'>Run check</button>"
            + "</form>"
            + "<form method='post' action='/test-push-monitor'>"
            + f"<input type='hidden' name='monitor_name' value='{html.escape(name)}'>"
            + "<button type='submit'>Test push</button>"
            + "</form>"
            + "<form method='post' action='/edit-monitor'>"
            + f"<input type='hidden' name='monitor_name' value='{html.escape(name)}'>"
            + "<button type='submit'>Edit</button>"
            + "</form>"
            + "<form method='post' action='/delete-monitor' onsubmit=\"return confirm('Delete monitor?');\">"
            + f"<input type='hidden' name='monitor_name' value='{html.escape(name)}'>"
            + "<button type='submit'>Delete</button>"
            + "</form>"
            + "</div>"
            + "</div>"
        )
    monitors_html = "".join(monitor_cards) if monitor_cards else "<p class='muted'>No monitors configured yet.</p>"

    checked_cron = "checked" if cron_enabled else ""
    filter_label = {"all": "all", "smart": "smart", "storage": "storage"}.get((log_filter or "all").lower(), "all")
    diag_label = {
        "logs": "logs",
        "task": "task",
        "config": "config",
        "cache": "cache",
        "history": "history",
        "paths": "paths",
        "system": "system",
    }.get((diag_view or "logs").lower(), "logs")
    modal_open = bool(create_mode or edit_original_name)
    modal_title = "Edit Monitor" if edit_original_name else "Create Monitor"
    ui_view = (ui_view or "overview").strip().lower()
    if ui_view not in ("overview", "setup", "settings"):
        ui_view = "overview"
    if create_mode or edit_original_name:
        ui_view = "setup"

    stay_popup_field = "<input type='hidden' name='stay_popup' value='1'> " if show_setup_popup else ""
    gallery_urls_json = json.dumps(gallery_urls)
    setup_card = f"""
    <details class="card"{setup_open_attr}>
      <summary>Setup & Elevated Access</summary>
      <div class="{setup_state_css}">{html.escape(setup_state_text)}</div>
      <div class="{elevated_css}">{html.escape(elevated_msg)}</div>
      <h4>Quick Steps</h4>
      <div class="step-grid">
        {step_cards_html}
      </div>
      <div class="muted">Helper script command: <code>{html.escape(helper_script_path)}</code></div>
      <div class="muted"><strong>Update note:</strong> after every package update, run the DSM task once to refresh elevated cache.</div>
      <div class="button-row">
        <form method="post" action="/auto-create-task">{stay_popup_field}<button type="submit">Auto-create task (beta)</button></form>
        <form method="post" action="/check-elevated">{stay_popup_field}<button type="submit">Check elevated access now</button></form>
      </div>
      <pre>{html.escape(task_status_text)}</pre>
    </details>
    """
    setup_popup_card = setup_card.replace(f'<details class="card"{setup_open_attr}>', '<details class="card" open>')

    first_start = (len(monitors) == 0 and len(history) == 0)
    show_guide_button = (not elevated_ok) or first_start
    setup_header_action = (
        "<form method='post' action='/open-setup-popup'><button type='submit'>Elevation access guide</button></form>"
        if show_guide_button
        else ""
    )
    popup_status_html = ""
    if show_setup_popup:
        if message:
            popup_status_html += f"<div class='ok'>{html.escape(message)}</div>"
        if error:
            popup_status_html += f"<div class='err'>{html.escape(error)}</div>"
        if action_output:
            popup_status_html += f"<pre>{html.escape(action_output)}</pre>"
    setup_popup_html = (
        "<div class='modal-backdrop open'><div class='modal'>"
        + popup_status_html
        + setup_popup_card
        + "<a class='close-link' href='/'>Close</a></div></div>"
        if show_setup_popup
        else ""
    )
    nav_html = (
        "<div class='card'><div class='button-row'>"
        + f"<a class='chip {'active' if ui_view=='overview' else ''}' href='/?view=overview&diag_view={diag_label}&log_filter={filter_label}'>Overview</a>"
        + f"<a class='chip {'active' if ui_view=='setup' else ''}' href='/?view=setup'>Monitor Setup</a>"
        + f"<a class='chip {'active' if ui_view=='settings' else ''}' href='/?view=settings'>Settings</a>"
        + "</div></div>"
    )
    overview_view_html = f"""
      <div class="card">
        <h3>Monitoring Overview</h3>
        <div class="overview-grid">{overview_html}</div>
      </div>
      <div class="card">
        <h3>Logs & Diagnostics</h3>
        <div class="button-row">
          <a class="chip {'active' if diag_label=='logs' else ''}" href="/?view=overview&diag_view=logs&log_filter={filter_label}">Logs</a>
          <a class="chip {'active' if diag_label=='task' else ''}" href="/?view=overview&diag_view=task">Task</a>
          <a class="chip {'active' if diag_label=='cache' else ''}" href="/?view=overview&diag_view=cache">Cache</a>
          <a class="chip {'active' if diag_label=='config' else ''}" href="/?view=overview&diag_view=config">Config</a>
          <a class="chip {'active' if diag_label=='history' else ''}" href="/?view=overview&diag_view=history">History</a>
          <a class="chip {'active' if diag_label=='paths' else ''}" href="/?view=overview&diag_view=paths">Paths</a>
          <a class="chip {'active' if diag_label=='system' else ''}" href="/?view=overview&diag_view=system">System</a>
        </div>
        {"<div class='button-row'><a class='chip " + ("active" if filter_label=='all' else "") + "' href='/?view=overview&diag_view=logs&log_filter=all'>All</a><a class='chip " + ("active" if filter_label=='smart' else "") + "' href='/?view=overview&diag_view=logs&log_filter=smart'>Smart</a><a class='chip " + ("active" if filter_label=='storage' else "") + "' href='/?view=overview&diag_view=logs&log_filter=storage'>Storage</a></div>" if diag_label=='logs' else ""}
        <pre>{html.escape(log_text)}</pre>
        <div class="button-row">
          <form method="get" action="/"><input type="hidden" name="view" value="overview"><input type="hidden" name="diag_view" value="{html.escape(diag_label)}"><input type="hidden" name="log_filter" value="{html.escape(filter_label)}"><button type="submit">Refresh logs</button></form>
          <form method="post" action="/clear-logs"><button type="submit">Clear logs</button></form>
        </div>
      </div>
    """
    setup_view_html = f"""
      {setup_card}
      <div class="card">
        <h3>Automation</h3>
        {"<div class='ok'>" + html.escape(automation_message) + "</div>" if automation_message else ""}
        {"<pre>" + html.escape(automation_output) + "</pre>" if automation_output else ""}
        <pre>{html.escape(automation_status)}</pre>
        <div class="button-row">
          <form method="post" action="/run-scheduled-now"><button type="submit">Run scheduled now</button></form>
          <form method="post" action="/repair-automation"><button type="submit">Repair automation</button></form>
          <form method="post" action="/automation-status"><button type="submit">Refresh status</button></form>
        </div>
      </div>
      <div class="card">
        <h3>Setup All Monitors</h3>
        <div class="button-row">{setup_header_action}</div>
        <form method="post" action="/open-create">
          <button type="submit">Create monitor</button>
        </form>
        <div class="muted">Create, edit, and delete monitors from this view.</div>
      </div>
      <div class="card"><h3>Configured Monitors</h3><div class="monitor-grid">{monitors_html}</div></div>
    """
    settings_view_html = f"""
      <div class="card" id="settings">
        <h3>Application Settings & Security</h3>
        {"<div class='ok'>" + html.escape(security_message) + "</div>" if security_message else ""}
        {"<pre>" + html.escape(security_output) + "</pre>" if security_output else ""}
        <div class="muted">Admin account protected by password + mandatory TOTP 2FA. Unused recovery codes: {recovery_unused}</div>
        <form method="post" action="/auth/change-password">
          <label>Change password</label>
          <div class="row">
            <div><input name="current_password" type="password" placeholder="Current password" required></div>
            <div><input name="new_password" type="password" minlength="10" placeholder="New password" required></div>
          </div>
          <input name="new_password_confirm" type="password" minlength="10" placeholder="Confirm new password" required>
          <div class="button-row"><button type="submit">Update password</button></div>
        </form>
        <div class="button-row">
          <form method="post" action="/auth/regenerate-recovery"><button type="submit">Regenerate recovery codes</button></form>
        </div>
        <form method="post" action="/auth/rotate-totp">
          <label>Rotate TOTP secret (verify with current 6-digit code)</label>
          <div class="row">
            <div><input name="token" inputmode="numeric" maxlength="6" placeholder="123456" required></div>
            <div><button type="submit">Rotate TOTP + recovery codes</button></div>
          </div>
        </form>
        <form method="post" action="/auth/import" enctype="multipart/form-data">
          <label>Import settings backup (JSON export)</label>
          <textarea name="import_payload" rows="7" style="width:100%;margin-top:6px;box-sizing:border-box;border:1px solid #30405b;border-radius:8px;background:#0f1726;color:#d7e2f0;padding:8px;"></textarea>
          <label>Or import from JSON file</label>
          <input name="import_file" type="file" accept=".json,application/json">
          <div class="button-row">
            <button type="submit">Import settings</button>
            <a class="close-link" href="/auth/export">Export safe settings</a>
          </div>
        </form>
        <div class="button-row">
          <form method="post" action="/auth/logout"><button type="submit">Log out</button></form>
        </div>
      </div>
      <div class="card">
        <h3>Danger Zone</h3>
        <div class="muted">Restart package services from UI (web UI + scheduler loop).</div>
        <div class="button-row">
          <form method="post" action="/danger-restart" onsubmit="return confirm('Restart addon now? UI will disconnect briefly.');">
            <button type="submit">Restart addon</button>
          </form>
        </div>
      </div>
    """
    active_view_html = overview_view_html if ui_view == "overview" else (setup_view_html if ui_view == "setup" else settings_view_html)
    body_layout = nav_html + active_view_html + setup_popup_html

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{html.escape(PRODUCT_NAME)} - Setup</title>
  <style>
    :root {{
      --bg: #0b1220; --card: #121d2f; --card-soft: #17243a; --border: #2a3d5a; --text: #d7e2f0; --muted: #8fa1b8;
      --blue: #2f80ed; --green: #22c55e; --yellow: #f59e0b; --red: #ef4444; --unknown: #64748b;
    }}
    body {{ font-family: "Inter","Segoe UI",-apple-system,BlinkMacSystemFont,Arial,sans-serif; margin: 12px; background: radial-gradient(circle at 20% 0%, #1e4679 0%, var(--bg) 40%, #070b14 100%); color: var(--text); }}
    .container {{ width: 100%; max-width: 1360px; margin: 0 auto; }}
    .layout {{ display: grid; grid-template-columns: 2.1fr 1fr; gap: 12px; }}
    .main-col, .side-col {{ min-width: 0; }}
    .card {{ background: rgba(18,29,47,0.94); border: 1px solid var(--border); border-radius: 16px; padding: 16px; margin-bottom: 14px; box-shadow: 0 14px 30px rgba(0,0,0,.28); backdrop-filter: blur(4px); }}
    h2 {{ margin: 0 0 6px 0; color: #e7f0ff; font-size: 22px; }}
    h3 {{ margin: 0 0 10px 0; color: #c8dbf8; font-size: 18px; }}
    h4 {{ margin: 0 0 8px 0; color: #b8cae3; font-size: 14px; }}
    label {{ display: block; margin-top: 10px; font-weight: 600; color: #c8d8ee; }}
    input, select {{ width: 100%; padding: 8px; margin-top: 4px; box-sizing: border-box; border: 1px solid #30405b; border-radius: 6px; background: #0f1726; color: var(--text); }}
    .row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
    .button-row {{ display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-top: 14px; margin-bottom: 12px; }}
    .button-row:last-child {{ margin-bottom: 0; }}
    form {{ margin: 0; }}
    button {{ margin: 0; padding: 10px 15px; border: 1px solid #4a94fb; background: linear-gradient(180deg,#4a99ff,#2f80ed); color: #fff; border-radius: 10px; cursor: pointer; font-weight: 700; line-height: 1.2; }}
    .ok {{ background: rgba(34,197,94,0.15); color: #88efb0; padding: 8px; border-radius: 6px; margin-bottom: 8px; border: 1px solid rgba(34,197,94,0.35); }}
    .err {{ background: rgba(239,68,68,0.15); color: #f8a7a7; padding: 8px; border-radius: 6px; margin-bottom: 8px; border: 1px solid rgba(239,68,68,0.35); }}
    code {{ background: #0b1321; padding: 2px 4px; border-radius: 4px; border: 1px solid #2a3952; }}
    pre {{ background: #0b1321; color: #cfe2ff; padding: 10px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; border: 1px solid #283852; }}
    .muted {{ color: var(--muted); font-size: 12px; }}
    details summary {{ cursor: pointer; font-weight: 700; color: #d2e4ff; margin-bottom: 8px; }}
    .guide-card {{ border: 1px solid var(--border); border-radius: 8px; background: var(--card-soft); padding: 6px; }}
    .screenshot-link {{ text-decoration: none; display: block; cursor: zoom-in; }}
    .guide-card .img-wrap {{ border-radius: 6px; overflow: hidden; }}
    .zoom-wrap {{ overflow: hidden; border: 1px solid #30405b; border-radius: 6px; margin-top: 8px; }}
    .zoom-img {{ width: 100%; height: auto; display: block; transform: scale(var(--zoom, 1)); transform-origin: var(--ox, 50%) var(--oy, 50%); transition: transform 120ms linear; }}
    .zoom-wrap:hover .zoom-img {{ --zoom: 2.0; }}
    .guide-label {{ font-size: 12px; color: #a9bcd7; margin-top: 6px; }}
    .step-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; }}
    .step-box {{ border: 1px solid #2f425e; border-left: 4px solid var(--blue); border-radius: 8px; background: #111d2f; padding: 10px; }}
    .step-num {{ font-size: 11px; color: #76b3ff; font-weight: 700; }}
    .step-title {{ font-size: 13px; font-weight: 700; color: #d1e4ff; }}
    .step-desc {{ font-size: 12px; color: #a8bedc; margin-top: 4px; }}
    .overview-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 10px; margin-top: 12px; }}
    .overview-card {{ border: 1px solid var(--border); border-radius: 10px; background: var(--card-soft); padding: 10px; }}
    .overview-card.hl-channel {{ border-color: #4c8ff6; box-shadow: 0 0 0 1px rgba(76,143,246,0.45) inset; }}
    .gauge-link {{ text-decoration: none; }}
    .gauge {{ width: 140px; height: 140px; border-radius: 50%; margin: 8px auto; position: relative; background: conic-gradient(var(--gauge-color, var(--unknown)) calc(var(--pct, 0) * 1%), #263143 0); }}
    .gauge::after {{ content: ""; position: absolute; inset: 14px; border-radius: 50%; background: #0f1726; border: 1px solid #30405a; }}
    .gauge-center {{ position: absolute; inset: 0; display: grid; place-content: center; z-index: 1; text-align: center; }}
    .gauge-value {{ font-size: 12px; font-weight: 700; }}
    .gauge-sub {{ font-size: 11px; color: var(--muted); }}
    .st-up {{ --gauge-color: var(--green); color: #93efb7; }}
    .st-warning {{ --gauge-color: var(--yellow); color: #ffd58a; }}
    .st-down {{ --gauge-color: var(--red); color: #ffafaf; }}
    .st-unknown {{ --gauge-color: var(--unknown); color: #b8c6d8; }}
    .history-dots {{ margin-top: 6px; display: flex; gap: 4px; flex-wrap: wrap; min-height: 12px; }}
    .dot {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}
    .monitor-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 10px; }}
    .monitor-card {{ border: 1px solid var(--border); border-radius: 10px; background: var(--card-soft); padding: 12px; }}
    .monitor-card.hl-monitor {{ border-color: #4c8ff6; box-shadow: 0 0 0 1px rgba(76,143,246,0.45) inset; }}
    .monitor-head {{ display: flex; justify-content: space-between; align-items: center; gap: 8px; }}
    .monitor-title {{ font-weight: 700; color: #d8e8ff; }}
    .badge {{ font-size: 11px; padding: 3px 8px; border-radius: 999px; border: 1px solid transparent; }}
    .badge.st-up {{ background: rgba(34,197,94,.15); border-color: rgba(34,197,94,.35); }}
    .badge.st-warning {{ background: rgba(245,158,11,.16); border-color: rgba(245,158,11,.4); }}
    .badge.st-down {{ background: rgba(239,68,68,.16); border-color: rgba(239,68,68,.4); }}
    .badge.st-unknown {{ background: rgba(100,116,139,.2); border-color: rgba(100,116,139,.4); }}
    .monitor-meta {{ margin-top: 8px; font-size: 12px; color: #9fb2cc; line-height: 1.35; }}
    .monitor-meta.token-row {{ margin-bottom: 10px; }}
    .monitor-meta code {{ display: inline-block; padding: 3px 6px; margin-left: 4px; line-height: 1.2; overflow-wrap: anywhere; }}
    .monitor-card .button-row {{ margin-top: 14px; margin-bottom: 0; }}
    .pulse-hit {{ animation: pulseGlow 900ms ease; }}
    @keyframes pulseGlow {{
      0% {{ box-shadow: 0 0 0 0 rgba(47,128,237,0.65); transform: scale(1); }}
      45% {{ box-shadow: 0 0 0 8px rgba(47,128,237,0.0); transform: scale(1.01); }}
      100% {{ box-shadow: 0 0 0 0 rgba(47,128,237,0.0); transform: scale(1); }}
    }}
    .chip {{ display: inline-block; padding: 6px 12px; border-radius: 10px; border: 1px solid #36517a; color: #b7cff1; text-decoration: none; font-size: 12px; font-weight: 600; }}
    .chip.active {{ background: rgba(47,128,237,.3); border-color: #5aa1ff; color: #d8ebff; }}
    .modal-backdrop {{ position: fixed; inset: 0; background: rgba(5,10,20,.74); display: none; align-items: center; justify-content: center; z-index: 2000; }}
    .modal-backdrop.open {{ display: flex; }}
    .modal {{ width: min(640px, 96vw); max-height: 92vh; overflow: auto; background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px; }}
    .close-link {{ color: #c8dbf8; text-decoration: none; padding: 9px 12px; border: 1px solid #36517a; border-radius: 8px; margin-top: 0; display: inline-block; line-height: 1.2; }}
    .gallery-modal .modal {{ width: min(980px, 96vw); }}
    .gallery-stage {{ text-align: center; border: 1px solid var(--border); border-radius: 10px; background: #0f1726; padding: 10px; }}
    .gallery-stage img {{ max-width: 100%; max-height: 70vh; width: auto; height: auto; border-radius: 8px; }}
    .gallery-controls {{ display: flex; justify-content: center; align-items: center; gap: 10px; margin-top: 12px; }}
    .gallery-caption {{ color: var(--muted); font-size: 12px; text-align: center; margin-top: 8px; }}
    .brand-head {{ position: relative; min-height: 72px; }}
    .top-actions {{ position: absolute; right: 0; top: 0; display:flex; gap:8px; flex-wrap:wrap; }}
    .top-actions .ghost-btn {{
      color: #c8dbf8;
      text-decoration: none;
      padding: 9px 12px;
      border: 1px solid #36517a;
      border-radius: 8px;
      display: inline-block;
      line-height: 1.2;
      background: #141f31;
      font-weight: 600;
      cursor: pointer;
    }}
    .brand-center {{ text-align: center; }}
    .brand-logo {{ max-height: 54px; width: auto; }}
    .brand-summary {{ margin-top: 8px; font-size: 13px; color: var(--muted); }}
    .footer-note {{ margin-top: 10px; color: var(--muted); font-size: 12px; }}
    @media (max-width: 960px) {{
      .layout {{ grid-template-columns: 1fr; }}
    }}
    @media (max-width: 760px) {{
      .row {{ grid-template-columns: 1fr; }}
      .button-row {{ flex-direction: column; align-items: stretch; }}
      button {{ width: 100%; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="brand-head">
        <div class="top-actions">
          <form method="post" action="/auth/logout"><button class="ghost-btn" type="submit">Log out</button></form>
        </div>
        <div class="brand-center">
          <a href="{html.escape(BRAND_URL)}" target="_blank" rel="noopener noreferrer"><img class="brand-logo" src="{html.escape(BRAND_LOGO_URL)}" alt="{html.escape(BRAND_NAME)} logo"></a>
          <div class="brand-summary">Automated Synology SMART and storage monitoring, securely pushed to Uptime Kuma.</div>
        </div>
      </div>
      {status_html}
    </div>
    {body_layout}
    <div class="modal-backdrop {'open' if modal_open else ''}" id="monitor-modal">
      <div class="modal">
        <h3>{html.escape(modal_title)}</h3>
        <form method="post" action="/save">
          <input type="hidden" name="edit_original_name" value="{html.escape(edit_original_name)}">
          <label>Monitor Name</label>
          <input id="name" name="name" value="{html.escape(current_name)}">
          <label>Kuma Push URL</label>
          <input name="kuma_url" value="{html.escape(current_url)}" placeholder="https://kuma.example.com/api/push/TOKEN" required>
          <div class="row">
            <div>
              <label>Check Mode</label>
              <select id="check_mode" name="check_mode">
                <option value="both" {"selected" if current_mode == "both" else ""}>both</option>
                <option value="smart" {"selected" if current_mode == "smart" else ""}>smart</option>
                <option value="storage" {"selected" if current_mode == "storage" else ""}>storage</option>
              </select>
            </div>
            <div>
              <label>Cron Interval (minutes)</label>
              <input name="interval" type="number" min="1" max="1440" value="{interval}">
            </div>
          </div>
          <label><input type="checkbox" name="cron_enabled" value="1" {checked_cron}> Enable automatic checks (cron)</label>
          <label><input type="checkbox" name="replace_all" value="1"> Replace existing monitors with this one</label>
          <div class="button-row">
            <button type="submit">{'Update monitor' if edit_original_name else 'Create monitor'}</button>
            <a class="close-link" href="/">Cancel</a>
          </div>
        </form>
      </div>
    </div>
    <div class="modal-backdrop gallery-modal" id="gallery-modal">
      <div class="modal">
        <h3>Setup Screenshots</h3>
        <div class="gallery-stage"><img id="gallery-image" src="" alt="Setup screenshot"></div>
        <div class="gallery-caption" id="gallery-caption"></div>
        <div class="gallery-controls">
          <button type="button" id="gallery-prev">Previous</button>
          <button type="button" id="gallery-next">Next</button>
          <button type="button" id="gallery-close">Close</button>
        </div>
      </div>
    </div>
    <div class="card footer-note">
      {html.escape(BRAND_COPYRIGHT)} | Author: {html.escape(BRAND_AUTHOR)} |
      <a href="{html.escape(BRAND_URL)}" target="_blank" rel="noopener noreferrer">EasySystems GmbH</a>
    </div>
    <script>
      (function () {{
        var modeEl = document.getElementById("check_mode");
        var nameEl = document.getElementById("name");
        if (modeEl && nameEl) {{
          function autoName() {{
            var selected = modeEl.value || "both";
            var defaultName = selected + "-synology-check";
            var current = (nameEl.value || "").trim();
            var known = ["both-synology-check", "smart-synology-check", "storage-synology-check", "synology-main"];
            if (!current || known.indexOf(current) >= 0) nameEl.value = defaultName;
          }}
          modeEl.addEventListener("change", autoName);
          autoName();
        }}

      var zoomWraps = document.querySelectorAll(".zoom-wrap");
      zoomWraps.forEach(function (wrap) {{
        var img = wrap.querySelector(".zoom-img");
        if (!img) return;
        wrap.addEventListener("mousemove", function (ev) {{
          var r = wrap.getBoundingClientRect();
          var x = Math.max(0, Math.min(1, (ev.clientX - r.left) / Math.max(1, r.width)));
          var y = Math.max(0, Math.min(1, (ev.clientY - r.top) / Math.max(1, r.height)));
          img.style.setProperty("--ox", (x * 100).toFixed(2) + "%");
          img.style.setProperty("--oy", (y * 100).toFixed(2) + "%");
        }});
        wrap.addEventListener("mouseleave", function () {{
          img.style.setProperty("--ox", "50%");
          img.style.setProperty("--oy", "50%");
        }});
      }});

      var galleryImages = {gallery_urls_json};
      var galleryModal = document.getElementById("gallery-modal");
      var galleryImage = document.getElementById("gallery-image");
      var galleryCaption = document.getElementById("gallery-caption");
      var galleryPrev = document.getElementById("gallery-prev");
      var galleryNext = document.getElementById("gallery-next");
      var galleryClose = document.getElementById("gallery-close");
      var galleryIndex = 0;

      function renderGallery() {{
        if (!galleryImages.length || !galleryImage) return;
        galleryImage.src = galleryImages[galleryIndex];
        galleryCaption.textContent = "Image " + (galleryIndex + 1) + " of " + galleryImages.length;
      }}
      function openGallery(index) {{
        if (!galleryImages.length || !galleryModal) return;
        galleryIndex = Math.max(0, Math.min(galleryImages.length - 1, index));
        renderGallery();
        galleryModal.classList.add("open");
      }}
      function closeGallery() {{
        if (!galleryModal) return;
        galleryModal.classList.remove("open");
      }}
      function stepGallery(delta) {{
        if (!galleryImages.length) return;
        galleryIndex = (galleryIndex + delta + galleryImages.length) % galleryImages.length;
        renderGallery();
      }}

      document.querySelectorAll(".screenshot-link[data-gallery-index]").forEach(function (a) {{
        a.addEventListener("click", function (ev) {{
          ev.preventDefault();
          var idx = parseInt(a.getAttribute("data-gallery-index") || "0", 10);
          openGallery(isNaN(idx) ? 0 : idx);
        }});
      }});
      if (galleryPrev) galleryPrev.addEventListener("click", function () {{ stepGallery(-1); }});
      if (galleryNext) galleryNext.addEventListener("click", function () {{ stepGallery(1); }});
      if (galleryClose) galleryClose.addEventListener("click", closeGallery);
      if (galleryModal) {{
        galleryModal.addEventListener("click", function (ev) {{
          if (ev.target === galleryModal) closeGallery();
        }});
      }}
      document.addEventListener("keydown", function (ev) {{
        if (!galleryModal || !galleryModal.classList.contains("open")) return;
        if (ev.key === "Escape") closeGallery();
        if (ev.key === "ArrowLeft") stepGallery(-1);
        if (ev.key === "ArrowRight") stepGallery(1);
      }});

      function statusClass(status) {{
        if (status === "up") return "st-up";
        if (status === "warning") return "st-warning";
        if (status === "down") return "st-down";
        return "st-unknown";
      }}
      function statusLabel(status) {{
        if (status === "up" || status === "warning" || status === "down") return status.toUpperCase();
        return "UNKNOWN";
      }}
      function tsText(ts) {{
        if (!ts) return "never";
        var d = new Date(ts * 1000);
        return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0")
          + " " + String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0") + ":" + String(d.getSeconds()).padStart(2, "0");
      }}
      function escapeHtml(s) {{
        return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
      }}
      function pulse(el) {{
        if (!el) return;
        el.classList.remove("pulse-hit");
        void el.offsetWidth;
        el.classList.add("pulse-hit");
      }}
      var prevChannelTs = {{}};
      var prevMonitorTs = {{}};
      var selectedHighlight = "{html.escape(highlight_channel)}";

      function applyLiveSnapshot(data) {{
        if (!data || !data.channels || !data.monitors) return;
        ["smart", "storage"].forEach(function (channel) {{
          var card = document.querySelector(".overview-card[data-channel='" + channel + "']");
          var ch = data.channels[channel];
          if (!card || !ch) return;
          var gauge = card.querySelector("[data-role='gauge']");
          var gv = card.querySelector("[data-role='gauge-value']");
          var gs = card.querySelector("[data-role='gauge-sub']");
          var gl = card.querySelector("[data-role='channel-last']");
          var dots = card.querySelector("[data-role='channel-dots']");
          if (gauge) {{
            gauge.style.setProperty("--pct", String(ch.pct || 0));
            gauge.className = "gauge " + statusClass(ch.status);
          }}
          if (gv) gv.textContent = statusLabel(ch.status);
          if (gs) gs.textContent = String(ch.pct || 0) + "%";
          if (gl) gl.textContent = "Last update: " + tsText(ch.ts || 0);
          if (dots) {{
            var hs = Array.isArray(ch.history_statuses) ? ch.history_statuses : [];
            dots.innerHTML = hs.length
              ? hs.map(function (s) {{ return "<span class='dot " + statusClass(s) + "'></span>"; }}).join("")
              : "<span class='muted'>no history</span>";
          }}
          if ((prevChannelTs[channel] || 0) !== (ch.ts || 0) && ch.ts) {{
            pulse(gauge || card);
          }}
          prevChannelTs[channel] = ch.ts || 0;
        }});

        var cards = document.querySelectorAll(".monitor-card[data-monitor]");
        var map = {{}};
        cards.forEach(function (c) {{ map[c.getAttribute("data-monitor")] = c; }});
        cards.forEach(function (c) {{
          var mode = (c.getAttribute("data-mode") || "").toLowerCase();
          var hit = false;
          if (selectedHighlight === "smart") hit = (mode === "smart" || mode === "both");
          if (selectedHighlight === "storage") hit = (mode === "storage" || mode === "both");
          if (selectedHighlight) c.classList.toggle("hl-monitor", hit);
        }});
        data.monitors.forEach(function (m) {{
          var card = map[m.name];
          if (!card) return;
          var badge = card.querySelector(".badge");
          var primary = card.querySelector("[data-role='monitor-primary']");
          var live = card.querySelector("[data-role='monitor-live']");
          if (badge) {{
            badge.className = "badge " + statusClass(m.status);
            badge.textContent = statusLabel(m.status);
          }}
          if (primary) {{
            var ping = m.ping_ms === null || m.ping_ms === undefined ? "n/a" : String(m.ping_ms);
            primary.textContent = "Mode: " + (m.mode || "both") + " | Last ping: " + ping + " ms | Last run: " + tsText(m.ts || 0);
          }}
          if (live) {{
            var htmlParts = [];
            if (m.banner) htmlParts.push("<div class='" + (m.level === "err" ? "err" : "ok") + "'>" + escapeHtml(m.banner) + "</div>");
            if (m.output) htmlParts.push("<pre>" + escapeHtml(m.output) + "</pre>");
            live.innerHTML = htmlParts.join("");
          }}
          if ((prevMonitorTs[m.name] || 0) !== (m.ts || 0) && m.ts) {{
            pulse(card);
          }}
          prevMonitorTs[m.name] = m.ts || 0;
        }});
      }}

      async function refreshLive() {{
        try {{
          var r = await fetch("/status-json", {{ cache: "no-store" }});
          if (!r.ok) return;
          var data = await r.json();
          applyLiveSnapshot(data);
        }} catch (e) {{
          /* ignore transient fetch errors */
        }}
      }}
      refreshLive();
      setInterval(refreshLive, 15000);
      }})();
    </script>
  </div>
</body>
</html>
"""


def _render_auth_shell(title: str, body_html: str, info: str = "", error: str = "", ssl_warning: str = "") -> str:
    info_html = f'<div class="ok">{html.escape(info)}</div>' if info else ""
    err_html = f'<div class="err">{html.escape(error)}</div>' if error else ""
    warn_html = (
        "<details class='warn-wrap'>"
        "<summary class='warn-btn'>Connection security warning (more info)</summary>"
        f"<div class='warn-body'>{html.escape(ssl_warning)}</div>"
        "</details>"
        if ssl_warning
        else ""
    )
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(PRODUCT_NAME)} - Security</title>
  <style>
    body {{ font-family: "Inter","Segoe UI",-apple-system,BlinkMacSystemFont,Arial,sans-serif; margin: 0; background: radial-gradient(circle at 20% 0%, #1f4a80 0%, #0a1220 50%, #070b14 100%); color:#e6eef8; min-height: 100vh; }}
    .wrap {{ max-width: 980px; margin: 28px auto; padding: 0 14px; }}
    .auth-grid {{ display:grid; grid-template-columns: 1fr; gap: 14px; max-width: 560px; margin: 0 auto; }}
    .card {{ background: rgba(17,26,42,0.92); border:1px solid #2e3e56; border-radius:16px; padding:18px; margin-bottom:12px; box-shadow: 0 14px 34px rgba(0,0,0,.36); backdrop-filter: blur(4px); }}
    h2 {{ margin:0 0 6px 0; }}
    h3 {{ margin:0 0 8px 0; }}
    label {{ display:block; margin-top:10px; font-weight:600; }}
    input {{ width:100%; box-sizing:border-box; margin-top:4px; padding:9px; border:1px solid #334861; border-radius:6px; background:#0d1524; color:#e6eef8; }}
    .button-row {{ margin-top:12px; display:flex; gap:8px; flex-wrap:wrap; }}
    button, .btn {{ border:1px solid #3c8ff8; border-radius:8px; padding:9px 14px; background:linear-gradient(180deg,#3d8cf0,#2f80ed); color:#fff; font-weight:600; cursor:pointer; text-decoration:none; }}
    .btn.secondary {{ background:#1a263b; border-color:#3f5678; color:#d7e7ff; }}
    .ok {{ background:rgba(34,197,94,.15); border:1px solid rgba(34,197,94,.35); color:#8ff0b6; padding:8px; border-radius:6px; margin-bottom:8px; }}
    .err {{ background:rgba(239,68,68,.15); border:1px solid rgba(239,68,68,.35); color:#f8b2b2; padding:8px; border-radius:6px; margin-bottom:8px; }}
    .warn-wrap {{ margin-bottom: 10px; border:1px solid rgba(245,158,11,.35); border-radius:8px; background:rgba(245,158,11,.08); }}
    .warn-btn {{ list-style:none; cursor:pointer; padding:8px 10px; color:#ffd896; font-weight:700; }}
    .warn-btn::-webkit-details-marker {{ display:none; }}
    .warn-body {{ border-top:1px solid rgba(245,158,11,.2); padding:8px 10px; color:#ffd896; }}
    code, pre {{ background:#0a1220; border:1px solid #2b3b55; border-radius:6px; }}
    code {{ padding:2px 6px; }}
    pre {{ padding:10px; white-space:pre-wrap; overflow:auto; }}
    .muted {{ color:#9fb2cc; font-size:12px; margin-top:6px; }}
    .qr {{ margin-top:10px; max-width:240px; border-radius:8px; border:1px solid #2f425d; background:#fff; padding:8px; }}
    .hero-logo-wrap {{ text-align:center; margin-top: 10px; }}
    .hero-logo {{ max-height: 78px; width: auto; }}
    .hero-tagline {{ margin: 12px 0 0 0; color:#c6d9f4; font-size: 16px; font-weight: 600; line-height:1.4; text-align:center; }}
    @media (max-width: 860px) {{ .auth-grid {{ max-width: 100%; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="auth-grid">
      <div class="card hero">
        <div class="hero-logo-wrap">
          <a href="{html.escape(BRAND_URL)}" target="_blank" rel="noopener noreferrer">
            <img class="hero-logo" src="{html.escape(BRAND_LOGO_URL)}" alt="{html.escape(BRAND_NAME)} logo">
          </a>
        </div>
        <div class="hero-tagline">Secure Synology monitoring, with clear status and trusted uptime signals.</div>
        <div class="muted" style="text-align:center;margin-top:10px;">Recommendation: publish this UI behind Synology Reverse Proxy with HTTPS.</div>
      </div>
      <div class="card">
        <h3>{html.escape(title)}</h3>
        {warn_html}
        {info_html}
        {err_html}
        {body_html}
      </div>
    </div>
  </div>
</body>
</html>"""


def _render_auth_setup_page(
    info: str = "",
    error: str = "",
    provision: Optional[Dict[str, Any]] = None,
    ssl_warning: str = "",
) -> str:
    provision_html = ""
    if provision:
        qr_html = ""
        recovery_codes_text = "\n".join([str(x) for x in provision.get("recovery_codes", [])])
        if provision.get("qr_data_uri"):
            qr_html = f'<img class="qr" alt="TOTP QR" src="{html.escape(str(provision.get("qr_data_uri", "")))}">'
        provision_html = f"""
        <div class="ok">Account created. Scan the QR code in your authenticator app, then store recovery codes securely.</div>
        {qr_html}
        <div style="margin-top:10px;"><b>TOTP Secret</b><br><code>{html.escape(str(provision.get("totp_secret", "")))}</code></div>
        <div class="muted">If QR is unavailable, add this secret manually in your authenticator app.</div>
        <div style="margin-top:10px;"><b>Recovery Codes (shown once)</b></div>
        <pre>{html.escape(recovery_codes_text)}</pre>
        <div class="button-row">
          <a class="btn" href="/auth/login">Continue to Login</a>
        </div>
        """
    body = (
        provision_html
        if provision
        else """
        <form method="post" action="/auth/setup">
          <label>Create admin password</label>
          <input name="password" type="password" minlength="10" required>
          <label>Confirm password</label>
          <input name="password_confirm" type="password" minlength="10" required>
          <div class="button-row">
            <button type="submit">Initialize Security</button>
          </div>
          <div class="muted">Dependencies required: pyotp, qrcode, Pillow (for QR rendering).</div>
        </form>
        """
    )
    return _render_auth_shell("Initial Security Setup", body, info=info, error=error, ssl_warning=ssl_warning)


def _render_auth_login_page(info: str = "", error: str = "", ssl_warning: str = "") -> str:
    body = """
    <form method="post" action="/auth/login">
      <label>Admin password</label>
      <input name="password" type="password" required>
      <div class="button-row">
        <button type="submit">Continue</button>
      </div>
    </form>
    """
    return _render_auth_shell("Login", body, info=info, error=error, ssl_warning=ssl_warning)


def _render_auth_verify_page(info: str = "", error: str = "", ssl_warning: str = "") -> str:
    body = """
    <form method="post" action="/auth/verify-2fa">
      <label>6-digit authenticator code</label>
      <input name="token" inputmode="numeric" maxlength="6" placeholder="123456" required>
      <div class="button-row">
        <button type="submit">Verify and Sign In</button>
        <a class="btn secondary" href="/auth/recovery">Use recovery code</a>
      </div>
    </form>
    """
    return _render_auth_shell("Two-Factor Verification", body, info=info, error=error, ssl_warning=ssl_warning)


def _render_auth_recovery_page(info: str = "", error: str = "", ssl_warning: str = "") -> str:
    body = """
    <form method="post" action="/auth/recovery">
      <label>One-time recovery code</label>
      <input name="recovery_code" placeholder="ABCD-1234" required>
      <div class="button-row">
        <button type="submit">Sign In with Recovery Code</button>
        <a class="btn secondary" href="/auth/verify-2fa">Back to TOTP</a>
      </div>
    </form>
    """
    return _render_auth_shell("Recovery Access", body, info=info, error=error, ssl_warning=ssl_warning)


def _find_monitor_by_name(monitors: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    for m in monitors:
        if str(m.get("name", "")) == name:
            return m
    return None


def _ui_run_check_now(target_monitor: Optional[str] = None) -> str:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    dbg = bool(cfg.get("debug", False))
    if not monitors:
        append_ui_log("run-check | no monitors configured")
        return "No monitors configured."
    if target_monitor:
        target = _find_monitor_by_name(monitors, target_monitor)
        if not target:
            append_ui_log(f"run-check | monitor not found: {target_monitor}")
            return f"Monitor not found: {target_monitor}"
        monitors = [target]
    lines: List[str] = []
    for m in monitors:
        name = m.get("name", "?")
        mode = str(m.get("check_mode", "both")).lower()
        if mode not in CHECK_MODES:
            mode = "both"
        devices = [str(x) for x in m.get("devices", [])]
        url = m.get("kuma_url", "")
        if not url:
            line = f"x {name}: no Kuma URL"
            lines.append(line)
            _set_monitor_state(str(name), "Monitor check failed", line, level="err")
            append_ui_log(f"run-check | {name} | no Kuma URL")
            continue
        status, msg, lat = check_host(mode, devices, debug=dbg)
        ok = push_to_kuma(url, status, msg, lat, debug=dbg)
        _record_history(str(name), mode, status, lat)
        line = f"{'ok' if ok else 'x'} {name}: {status} (ping={lat:.2f}ms) push {'OK' if ok else 'FAILED'}"
        lines.append(line)
        _set_monitor_state(
            str(name),
            "Monitor check completed" if ok else "Monitor check completed with errors",
            line,
            level="ok" if ok else "err",
        )
        append_ui_log(
            f"run-check | {name} | mode={mode} | status={status} | ping_ms={lat:.2f} | push={'OK' if ok else 'FAILED'}"
        )
        compact_msg = " ".join(msg.replace("\n", " | ").split())
        append_ui_log(f"run-check-detail | {name} | {compact_msg}")
    return "\n".join(lines)


def _ui_test_push(target_monitor: Optional[str] = None) -> str:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    if not monitors:
        append_ui_log("test-push | no monitors configured")
        return "No monitors configured."
    if target_monitor:
        target = _find_monitor_by_name(monitors, target_monitor)
        if not target:
            append_ui_log(f"test-push | monitor not found: {target_monitor}")
            return f"Monitor not found: {target_monitor}"
        monitors = [target]
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    msg = f"Test push @ {now} - {BRAND_NAME} synology-monitor connectivity check"
    lines: List[str] = []
    for m in monitors:
        ok = push_to_kuma(m.get("kuma_url", ""), "up", msg, 0, debug=bool(cfg.get("debug", False)))
        line = f"{'ok' if ok else 'x'} {m.get('name', '?')}: push {'OK' if ok else 'FAILED'}"
        lines.append(line)
        _set_monitor_state(
            str(m.get("name", "?")),
            "Monitor test push completed" if ok else "Monitor test push failed",
            line,
            level="ok" if ok else "err",
        )
        parsed = urlparse(m.get("kuma_url", ""))
        append_ui_log(
            f"test-push | {m.get('name', '?')} | host={parsed.hostname or '?'} | push={'OK' if ok else 'FAILED'}"
        )
    return "\n".join(lines)


def _ui_check_elevated_access() -> str:
    ok, msg = get_smart_helper_status()
    append_ui_log(f"elevated-check | {'active' if ok else 'inactive'} | {msg}")
    return f"{'ACTIVE' if ok else 'INACTIVE'}: {msg}"


def _ui_delete_monitor(name: str) -> str:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    kept = [m for m in monitors if str(m.get("name", "")) != name]
    if len(kept) == len(monitors):
        append_ui_log(f"delete-monitor | not found: {name}")
        return f"Monitor not found: {name}"
    cfg["monitors"] = kept
    save_config(cfg)
    _delete_monitor_runtime_data(name)
    append_ui_log(f"delete-monitor | removed: {name}")
    return f"Removed monitor: {name}"


def _ui_run_scheduled_now() -> str:
    cfg = load_config()
    if not cfg.get("cron_enabled", False):
        append_ui_log("automation | run-scheduled-now | skipped | automatic checks disabled")
        return "Automatic checks are disabled in monitor settings."
    output = _ui_run_check_now()
    _touch_scheduled_run()
    append_ui_log("automation | run-scheduled-now | completed")
    return output


def _ui_repair_automation() -> str:
    details: List[str] = []
    service_script = _scheduler_service_path()
    if service_script.exists():
        rc, out = _run_cmd([str(service_script), "start"], timeout_sec=12)
        details.append(f"service start rc={rc}")
        if out.strip():
            details.append(out.strip().replace("\n", " ")[:240])
    else:
        details.append(f"service script missing: {service_script}")

    # Best-effort user-level crontab fallback.
    helper = str(get_smart_helper_script_path())
    sched = "/var/packages/synology-monitor/target/monitor-scheduler.sh"
    for line in (
        f"*/5 * * * * {helper} # synology-monitor smart helper auto",
        f"* * * * * {sched} # synology-monitor scheduled checks auto",
    ):
        rc, out = _run_cmd(["crontab", "-l"], timeout_sec=8)
        current = out if rc == 0 else ""
        if line not in current:
            new_cron = (current.rstrip() + "\n" + line + "\n").lstrip("\n")
            try:
                p = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
                p.communicate(new_cron)
                details.append(f"crontab install {'ok' if p.returncode == 0 else 'failed'} for: {line}")
            except OSError as e:
                details.append(f"crontab error for {line}: {type(e).__name__}: {e}")
        else:
            details.append(f"crontab already has: {line}")

    append_ui_log("automation | repair | " + " | ".join(details))
    return "\n".join(details)


def run_setup_ui(host: str = "0.0.0.0", port: int = 8787) -> int:
    class Handler(BaseHTTPRequestHandler):
        def _reply_png(self, data: bytes, code: int = 200) -> None:
            self.send_response(code)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _reply_html(self, content: str, code: int = 200, extra_headers: Optional[List[Tuple[str, str]]] = None) -> None:
            payload = content.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            if extra_headers:
                for k, v in extra_headers:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _reply_json(self, data: Dict[str, Any], code: int = 200, extra_headers: Optional[List[Tuple[str, str]]] = None) -> None:
            payload = json.dumps(data).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            if extra_headers:
                for k, v in extra_headers:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _redirect(self, location: str, extra_headers: Optional[List[Tuple[str, str]]] = None) -> None:
            self.send_response(302)
            if extra_headers:
                for k, v in extra_headers:
                    self.send_header(k, v)
            self.send_header("Location", location)
            self.end_headers()

        def _cookie_header(self, name: str, value: str, max_age: int) -> str:
            morsel = cookies.SimpleCookie()
            morsel[name] = value
            morsel[name]["path"] = "/"
            morsel[name]["httponly"] = True
            morsel[name]["samesite"] = "Lax"
            morsel[name]["max-age"] = str(max_age)
            return morsel.output(header="").strip()

        def _clear_cookie_header(self, name: str) -> str:
            return self._cookie_header(name, "", 0)

        def _parse_cookies(self) -> Dict[str, str]:
            raw = self.headers.get("Cookie", "")
            if not raw:
                return {}
            parsed = cookies.SimpleCookie()
            try:
                parsed.load(raw)
            except Exception:
                return {}
            out: Dict[str, str] = {}
            for k, m in parsed.items():
                out[k] = m.value
            return out

        def _ssl_warning_text(self) -> str:
            forwarded = (self.headers.get("X-Forwarded-Proto", "") or self.headers.get("X-Forwarded-Protocol", "")).lower()
            if "https" in forwarded:
                return ""
            host = self.headers.get("Host", "")
            return (
                f"Connection appears to be plain HTTP ({host or 'direct access'}). "
                "Use Synology Reverse Proxy with HTTPS to protect login credentials and 2FA codes."
            )

        def _view_from_referer(self) -> str:
            ref = self.headers.get("Referer", "")
            if not ref:
                return "overview"
            try:
                q = parse_qs(urlparse(ref).query)
                v = (q.get("view", ["overview"])[0] or "overview").strip().lower()
            except Exception:
                return "overview"
            return v if v in ("overview", "setup", "settings") else "overview"

        def _is_authenticated(self) -> bool:
            auth = _load_auth_state()
            token = self._parse_cookies().get(AUTH_COOKIE_NAME, "")
            if not token:
                return False
            payload = _verify_signed_payload(token, str(auth.get("session_secret", "")))
            if not payload:
                return False
            return bool(payload.get("auth") is True)

        def _has_valid_challenge(self) -> bool:
            auth = _load_auth_state()
            token = self._parse_cookies().get(AUTH_CHALLENGE_COOKIE_NAME, "")
            if not token:
                return False
            payload = _verify_signed_payload(token, str(auth.get("session_secret", "")))
            if not payload:
                return False
            return payload.get("step") == "2fa"

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            auth = _load_auth_state()
            ssl_warning = self._ssl_warning_text()
            if parsed.path == "/auth/logout":
                self._redirect(
                    "/auth/login",
                    extra_headers=[
                        ("Set-Cookie", self._clear_cookie_header(AUTH_COOKIE_NAME)),
                        ("Set-Cookie", self._clear_cookie_header(AUTH_CHALLENGE_COOKIE_NAME)),
                    ],
                )
                return
            if parsed.path == "/auth/setup":
                if _auth_initialized(auth):
                    self._redirect("/auth/login")
                    return
                self._reply_html(_render_auth_setup_page(ssl_warning=ssl_warning))
                return
            if parsed.path == "/auth/login":
                if not _auth_initialized(auth):
                    self._redirect("/auth/setup")
                    return
                if self._is_authenticated():
                    self._redirect("/")
                    return
                locked, wait_sec = _is_locked(auth)
                msg = f"Login temporarily locked. Try again in {wait_sec}s." if locked else ""
                self._reply_html(_render_auth_login_page(info=msg, ssl_warning=ssl_warning))
                return
            if parsed.path == "/auth/verify-2fa":
                if not _auth_initialized(auth):
                    self._redirect("/auth/setup")
                    return
                if self._is_authenticated():
                    self._redirect("/")
                    return
                if not self._has_valid_challenge():
                    self._redirect("/auth/login")
                    return
                self._reply_html(_render_auth_verify_page(ssl_warning=ssl_warning))
                return
            if parsed.path == "/auth/recovery":
                if not _auth_initialized(auth):
                    self._redirect("/auth/setup")
                    return
                if self._is_authenticated():
                    self._redirect("/")
                    return
                if not self._has_valid_challenge():
                    self._redirect("/auth/login")
                    return
                self._reply_html(_render_auth_recovery_page(ssl_warning=ssl_warning))
                return
            if parsed.path == "/auth/export":
                if not _auth_initialized(auth):
                    self._redirect("/auth/setup")
                    return
                if not self._is_authenticated():
                    self._redirect("/auth/login")
                    return
                cfg = load_config()
                monitors = cfg.get("monitors", []) if isinstance(cfg.get("monitors", []), list) else []
                public_monitors = []
                for m in monitors:
                    if not isinstance(m, dict):
                        continue
                    public_monitors.append(
                        {
                            "name": str(m.get("name", "")),
                            "check_mode": str(m.get("check_mode", "both")),
                            "device_count": len([x for x in m.get("devices", []) if str(x).strip()]),
                            "kuma_token_hint": kuma_token_label(str(m.get("kuma_url", ""))),
                        }
                    )
                payload = {
                    "export_type": "safe-public",
                    "exported_at": int(time.time()),
                    "config_public": {
                        "cron_enabled": bool(cfg.get("cron_enabled", False)),
                        "cron_interval_minutes": int(cfg.get("cron_interval_minutes", 60) or 60),
                        "debug": bool(cfg.get("debug", False)),
                        "monitor_count": len(public_monitors),
                        "monitors": public_monitors,
                    },
                    "auth_public": {
                        "auth_initialized": bool(auth.get("auth_initialized", False)),
                        "recovery_codes_remaining": _count_unused_recovery(auth),
                    },
                    "notes": [
                        "Sensitive secrets are intentionally excluded.",
                        "No password hash, TOTP secret, session secret, recovery hashes, or full Kuma URLs are exported.",
                    ],
                }
                self._reply_json(
                    payload,
                    200,
                    extra_headers=[("Content-Disposition", 'attachment; filename="synology-monitor-settings-export.json"')],
                )
                return
            if not _auth_initialized(auth):
                self._redirect("/auth/setup")
                return
            if not self._is_authenticated():
                self._redirect("/auth/login")
                return
            if parsed.path == "/status-json":
                self._reply_json(_build_live_snapshot(), 200)
                return
            if parsed.path == "/guide-image":
                name = (parse_qs(parsed.query).get("name", [""])[0] or "").strip()
                p = get_task_guide_images().get(name)
                if p is None:
                    self._reply_html(_render_setup_html(error=f"Unknown guide image: {name}"), 404)
                    return
                try:
                    self._reply_png(p.read_bytes(), 200)
                except OSError:
                    self._reply_html(_render_setup_html(error=f"Guide image missing in package: {name}"), 500)
                return
            qs = parse_qs(parsed.query)
            log_filter = (qs.get("log_filter", ["all"])[0] or "all").strip().lower()
            diag_view = (qs.get("diag_view", ["logs"])[0] or "logs").strip().lower()
            ui_view = (qs.get("view", ["overview"])[0] or "overview").strip().lower()
            highlight = (qs.get("highlight", [""])[0] or "").strip().lower()
            if highlight not in ("smart", "storage"):
                highlight = ""
            self._reply_html(
                _render_setup_html(
                    log_filter=log_filter,
                    diag_view=diag_view,
                    ui_view=ui_view,
                    highlight_channel=highlight,
                    ssl_warning=ssl_warning,
                )
            )

        def do_POST(self) -> None:  # noqa: N802
            auth_routes = (
                "/auth/setup",
                "/auth/login",
                "/auth/verify-2fa",
                "/auth/recovery",
                "/auth/logout",
                "/auth/regenerate-recovery",
                "/auth/rotate-totp",
                "/auth/change-password",
                "/auth/import",
            )
            auth = _load_auth_state()
            ssl_warning = self._ssl_warning_text()
            ui_view = self._view_from_referer()
            if self.path in auth_routes:
                content_type = (self.headers.get("Content-Type", "") or "").lower()
                import_file_json = ""
                if self.path == "/auth/import" and "multipart/form-data" in content_type:
                    fs = cgi.FieldStorage(
                        fp=self.rfile,
                        headers=self.headers,
                        environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": self.headers.get("Content-Type", "")},
                        keep_blank_values=True,
                    )
                    raw_payload = fs.getvalue("import_payload")
                    if isinstance(raw_payload, bytes):
                        raw_payload = raw_payload.decode("utf-8", errors="ignore")
                    form = {"import_payload": [str(raw_payload or "")]}
                    if "import_file" in fs:
                        up = fs["import_file"]
                        if getattr(up, "file", None):
                            try:
                                data = up.file.read(2 * 1024 * 1024)  # 2MB safety limit
                            except Exception:
                                data = b""
                            if isinstance(data, bytes):
                                import_file_json = data.decode("utf-8", errors="ignore").strip()
                else:
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                if self.path == "/auth/logout":
                    self._redirect(
                        "/auth/login",
                        extra_headers=[
                            ("Set-Cookie", self._clear_cookie_header(AUTH_COOKIE_NAME)),
                            ("Set-Cookie", self._clear_cookie_header(AUTH_CHALLENGE_COOKIE_NAME)),
                        ],
                    )
                    return
                if self.path == "/auth/setup":
                    if _auth_initialized(auth):
                        self._redirect("/auth/login")
                        return
                    ok, dep_msg = _totp_available()
                    if not ok:
                        self._reply_html(_render_auth_setup_page(error=dep_msg, ssl_warning=ssl_warning))
                        return
                    pwd = (form.get("password", [""])[0] or "").strip()
                    pwd2 = (form.get("password_confirm", [""])[0] or "").strip()
                    if len(pwd) < 10:
                        self._reply_html(_render_auth_setup_page(error="Password must be at least 10 characters.", ssl_warning=ssl_warning))
                        return
                    if pwd != pwd2:
                        self._reply_html(_render_auth_setup_page(error="Password confirmation does not match.", ssl_warning=ssl_warning))
                        return
                    totp_secret = _generate_totp_secret()
                    recovery_codes = _generate_recovery_codes()
                    auth["auth_initialized"] = True
                    auth["password_hash"] = generate_password_hash(pwd)
                    auth["totp_secret"] = totp_secret
                    auth["recovery_hashes"] = _issue_recovery_hashes(recovery_codes)
                    auth["failed_attempts"] = 0
                    auth["lockout_until"] = 0
                    _save_auth_state(auth)
                    uri = _build_totp_uri(totp_secret)
                    qr_data_uri = _build_qr_data_uri(uri)
                    self._reply_html(
                        _render_auth_setup_page(
                            provision={
                                "totp_secret": totp_secret,
                                "recovery_codes": recovery_codes,
                                "qr_data_uri": qr_data_uri,
                            },
                            ssl_warning=ssl_warning,
                        )
                    )
                    append_ui_log("auth-setup | initialized admin auth + 2fa")
                    return
                if self.path == "/auth/login":
                    if not _auth_initialized(auth):
                        self._redirect("/auth/setup")
                        return
                    locked, wait_sec = _is_locked(auth)
                    if locked:
                        self._reply_html(_render_auth_login_page(error=f"Locked. Try again in {wait_sec}s.", ssl_warning=ssl_warning))
                        return
                    pwd = (form.get("password", [""])[0] or "").strip()
                    if not check_password_hash(str(auth.get("password_hash", "")), pwd):
                        _register_auth_failure(auth)
                        self._reply_html(_render_auth_login_page(error="Invalid password.", ssl_warning=ssl_warning))
                        return
                    _register_auth_success(auth)
                    challenge = _sign_payload(
                        {"step": "2fa", "exp": int(time.time()) + AUTH_CHALLENGE_TTL_SEC},
                        str(auth.get("session_secret", "")),
                    )
                    self._redirect(
                        "/auth/verify-2fa",
                        extra_headers=[("Set-Cookie", self._cookie_header(AUTH_CHALLENGE_COOKIE_NAME, challenge, AUTH_CHALLENGE_TTL_SEC))],
                    )
                    return
                if self.path == "/auth/verify-2fa":
                    if not self._has_valid_challenge():
                        self._redirect("/auth/login")
                        return
                    token = (form.get("token", [""])[0] or "").strip()
                    if not _verify_totp_token(str(auth.get("totp_secret", "")), token):
                        _register_auth_failure(auth)
                        self._reply_html(_render_auth_verify_page(error="Invalid authenticator code.", ssl_warning=ssl_warning))
                        return
                    _register_auth_success(auth)
                    sess = _sign_payload(
                        {"auth": True, "exp": int(time.time()) + AUTH_SESSION_TTL_SEC},
                        str(auth.get("session_secret", "")),
                    )
                    self._redirect(
                        "/",
                        extra_headers=[
                            ("Set-Cookie", self._cookie_header(AUTH_COOKIE_NAME, sess, AUTH_SESSION_TTL_SEC)),
                            ("Set-Cookie", self._clear_cookie_header(AUTH_CHALLENGE_COOKIE_NAME)),
                        ],
                    )
                    return
                if self.path == "/auth/recovery":
                    if not self._has_valid_challenge():
                        self._redirect("/auth/login")
                        return
                    code = (form.get("recovery_code", [""])[0] or "").strip()
                    if not _consume_recovery_code(auth, code):
                        _register_auth_failure(auth)
                        self._reply_html(_render_auth_recovery_page(error="Invalid or already used recovery code.", ssl_warning=ssl_warning))
                        return
                    _register_auth_success(auth)
                    sess = _sign_payload(
                        {"auth": True, "exp": int(time.time()) + AUTH_SESSION_TTL_SEC},
                        str(auth.get("session_secret", "")),
                    )
                    self._redirect(
                        "/",
                        extra_headers=[
                            ("Set-Cookie", self._cookie_header(AUTH_COOKIE_NAME, sess, AUTH_SESSION_TTL_SEC)),
                            ("Set-Cookie", self._clear_cookie_header(AUTH_CHALLENGE_COOKIE_NAME)),
                        ],
                    )
                    append_ui_log("auth-login | recovery code consumed")
                    return
                if self.path == "/auth/regenerate-recovery":
                    if not self._is_authenticated():
                        self._redirect("/auth/login")
                        return
                    new_codes = _generate_recovery_codes()
                    auth["recovery_hashes"] = _issue_recovery_hashes(new_codes)
                    _save_auth_state(auth)
                    output = "New one-time recovery codes (shown once):\n" + "\n".join(new_codes)
                    self._reply_html(
                        _render_setup_html(
                            security_message="Recovery codes regenerated",
                            security_output=output,
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        )
                    )
                    append_ui_log("auth-security | recovery codes regenerated")
                    return
                if self.path == "/auth/rotate-totp":
                    if not self._is_authenticated():
                        self._redirect("/auth/login")
                        return
                    token = (form.get("token", [""])[0] or "").strip()
                    if not _verify_totp_token(str(auth.get("totp_secret", "")), token):
                        self._reply_html(_render_setup_html(error="Invalid current TOTP code for rotation.", ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    ok, dep_msg = _totp_available()
                    if not ok:
                        self._reply_html(_render_setup_html(error=dep_msg, ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    totp_secret = _generate_totp_secret()
                    new_codes = _generate_recovery_codes()
                    auth["totp_secret"] = totp_secret
                    auth["recovery_hashes"] = _issue_recovery_hashes(new_codes)
                    _save_auth_state(auth)
                    uri = _build_totp_uri(totp_secret)
                    qr = _build_qr_data_uri(uri)
                    out = "TOTP secret rotated.\nNew recovery codes (shown once):\n" + "\n".join(new_codes)
                    if qr:
                        out += "\n\nQR data URI generated (displayed on auth setup pages)."
                    self._reply_html(
                        _render_setup_html(
                            security_message="Security credentials rotated",
                            security_output=out,
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        )
                    )
                    append_ui_log("auth-security | totp secret rotated")
                    return
                if self.path == "/auth/change-password":
                    if not self._is_authenticated():
                        self._redirect("/auth/login")
                        return
                    cur = (form.get("current_password", [""])[0] or "").strip()
                    newp = (form.get("new_password", [""])[0] or "").strip()
                    conf = (form.get("new_password_confirm", [""])[0] or "").strip()
                    if not check_password_hash(str(auth.get("password_hash", "")), cur):
                        self._reply_html(_render_setup_html(error="Current password is incorrect.", ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    if len(newp) < 10:
                        self._reply_html(_render_setup_html(error="New password must be at least 10 characters.", ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    if newp != conf:
                        self._reply_html(_render_setup_html(error="New password confirmation does not match.", ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    auth["password_hash"] = generate_password_hash(newp)
                    _save_auth_state(auth)
                    append_ui_log("auth-security | password updated")
                    self._reply_html(_render_setup_html(security_message="Password updated successfully.", ui_view=ui_view, ssl_warning=ssl_warning))
                    return
                if self.path == "/auth/import":
                    if not self._is_authenticated():
                        self._redirect("/auth/login")
                        return
                    raw = (form.get("import_payload", [""])[0] or "").strip()
                    if not raw and import_file_json:
                        raw = import_file_json
                    if not raw:
                        self._reply_html(_render_setup_html(error="Import payload is empty. Paste JSON or choose a JSON file.", ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    try:
                        payload = json.loads(raw)
                    except json.JSONDecodeError:
                        self._reply_html(_render_setup_html(error="Import payload is not valid JSON.", ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    if not isinstance(payload, dict):
                        self._reply_html(_render_setup_html(error="Import payload must be a JSON object.", ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    cfg_in = payload.get("config")
                    auth_in = payload.get("auth")
                    if isinstance(cfg_in, dict):
                        save_config(cfg_in, reapply_cron=False)
                    if isinstance(auth_in, dict):
                        if not str(auth_in.get("session_secret", "")).strip():
                            auth_in["session_secret"] = secrets.token_hex(32)
                        _save_auth_state(auth_in)
                    append_ui_log("auth-security | settings import applied")
                    self._redirect(
                        "/auth/login",
                        extra_headers=[
                            ("Set-Cookie", self._clear_cookie_header(AUTH_COOKIE_NAME)),
                            ("Set-Cookie", self._clear_cookie_header(AUTH_CHALLENGE_COOKIE_NAME)),
                        ],
                    )
                    return

            if not _auth_initialized(auth):
                self._redirect("/auth/setup")
                return
            if not self._is_authenticated():
                self._redirect("/auth/login")
                return
            if self.path not in (
                "/save",
                "/run-check",
                "/run-check-monitor",
                "/test-push",
                "/test-push-monitor",
                "/run-scheduled-now",
                "/repair-automation",
                "/automation-status",
                "/open-create",
                "/open-setup-popup",
                "/edit-monitor",
                "/delete-monitor",
                "/clear-logs",
                "/check-elevated",
                "/auto-create-task",
                "/danger-restart",
            ):
                self._reply_html(_render_setup_html(error="Unsupported endpoint"), 404)
                return
            try:
                if self.path == "/danger-restart":
                    service_script = "/var/packages/synology-monitor/scripts/start-stop-status"
                    cmd = f'(sleep 1; "{service_script}" stop; sleep 1; "{service_script}" start) >/dev/null 2>&1'
                    try:
                        subprocess.Popen(["sh", "-c", cmd])
                        append_ui_log("danger-zone | package restart requested from UI")
                        self._reply_html(
                            _render_setup_html(
                                security_message="Restart requested. UI may disconnect briefly (~10s).",
                                ui_view=ui_view,
                                ssl_warning=ssl_warning,
                            )
                        )
                    except OSError as e:
                        self._reply_html(_render_setup_html(error=f"Restart failed: {type(e).__name__}: {e}", ui_view=ui_view, ssl_warning=ssl_warning))
                    return
                if self.path == "/run-check":
                    output = _ui_run_check_now()
                    self._reply_html(_render_setup_html(message="Run check completed", action_output=output, ui_view=ui_view, ssl_warning=ssl_warning))
                    return
                if self.path == "/run-check-monitor":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    monitor_name = (form.get("monitor_name", [""])[0] or "").strip()
                    output = _ui_run_check_now(target_monitor=monitor_name)
                    self._reply_html(
                        _render_setup_html(
                            monitor_action_name=monitor_name,
                            monitor_action_message="Monitor check completed",
                            monitor_action_output=output,
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/test-push":
                    output = _ui_test_push()
                    self._reply_html(_render_setup_html(message="Connection test completed", action_output=output, ui_view=ui_view, ssl_warning=ssl_warning))
                    return
                if self.path == "/test-push-monitor":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    monitor_name = (form.get("monitor_name", [""])[0] or "").strip()
                    output = _ui_test_push(target_monitor=monitor_name)
                    self._reply_html(
                        _render_setup_html(
                            monitor_action_name=monitor_name,
                            monitor_action_message="Monitor test push completed",
                            monitor_action_output=output,
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/run-scheduled-now":
                    output = _ui_run_scheduled_now()
                    self._reply_html(
                        _render_setup_html(
                            automation_message="Scheduled run executed",
                            automation_output=output,
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/repair-automation":
                    output = _ui_repair_automation()
                    self._reply_html(
                        _render_setup_html(
                            automation_message="Automation repair attempted",
                            automation_output=output,
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/automation-status":
                    self._reply_html(_render_setup_html(automation_message="Automation status refreshed", ui_view=ui_view, ssl_warning=ssl_warning))
                    return
                if self.path == "/open-create":
                    append_ui_log("open-create | requested")
                    self._reply_html(_render_setup_html(message="Create monitor", create_mode=True, ui_view="setup", ssl_warning=ssl_warning))
                    return
                if self.path == "/open-setup-popup":
                    append_ui_log("open-setup-popup | requested")
                    self._reply_html(_render_setup_html(message="Elevation setup guide", show_setup_popup=True, ui_view="setup", ssl_warning=ssl_warning))
                    return
                if self.path == "/edit-monitor":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    monitor_name = (form.get("monitor_name", [""])[0] or "").strip()
                    append_ui_log(f"edit-monitor | target={monitor_name}")
                    self._reply_html(_render_setup_html(message=f"Editing monitor: {monitor_name}", edit_target=monitor_name, ui_view="setup", ssl_warning=ssl_warning))
                    return
                if self.path == "/delete-monitor":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    monitor_name = (form.get("monitor_name", [""])[0] or "").strip()
                    output = _ui_delete_monitor(monitor_name)
                    self._reply_html(_render_setup_html(message=output, ui_view=ui_view, ssl_warning=ssl_warning))
                    return
                if self.path == "/clear-logs":
                    clear_ui_log()
                    append_ui_log("logs cleared")
                    self._reply_html(_render_setup_html(message="Logs cleared", ui_view=ui_view, ssl_warning=ssl_warning))
                    return
                if self.path == "/check-elevated":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    stay_popup = "stay_popup" in form
                    output = _ui_check_elevated_access()
                    self._reply_html(
                        _render_setup_html(
                            message="Elevated access check completed",
                            action_output=output,
                            show_setup_popup=stay_popup,
                            ui_view="setup",
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/auto-create-task":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    stay_popup = "stay_popup" in form
                    output = _ui_auto_create_task_beta()
                    self._reply_html(
                        _render_setup_html(
                            message="Auto-create task attempt finished",
                            action_output=output,
                            show_setup_popup=stay_popup,
                            ui_view="setup",
                            ssl_warning=ssl_warning,
                        )
                    )
                    return

                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)

                name = (form.get("name", [""])[0] or "").strip()
                mode = (form.get("check_mode", ["both"])[0] or "both").strip().lower()
                kuma_url = (form.get("kuma_url", [""])[0] or "").strip()
                interval_raw = (form.get("interval", ["60"])[0] or "60").strip()
                cron_enabled = "cron_enabled" in form
                replace_all = "replace_all" in form
                edit_original_name = (form.get("edit_original_name", [""])[0] or "").strip()

                if mode not in CHECK_MODES:
                    append_ui_log(f"save-config | invalid mode: {mode}")
                    self._reply_html(_render_setup_html(error="Invalid check mode", ui_view=ui_view, ssl_warning=ssl_warning))
                    return
                if not name:
                    name = f"{mode}-synology-check"
                if not kuma_url.startswith(("http://", "https://")):
                    kuma_url = "https://" + kuma_url
                kuma_url = normalize_kuma_url(kuma_url)
                err = validate_kuma_url(kuma_url)
                if err:
                    append_ui_log(f"save-config | invalid Kuma URL: {err}")
                    self._reply_html(_render_setup_html(error=f"Invalid Kuma URL: {err}", ui_view=ui_view, ssl_warning=ssl_warning))
                    return
                try:
                    interval = max(INTERVAL_MIN, min(INTERVAL_MAX, int(interval_raw)))
                except ValueError:
                    interval = 60

                cfg = load_config()
                new_monitor = {"name": name, "check_mode": mode, "devices": [], "kuma_url": kuma_url}
                if edit_original_name:
                    updated = False
                    for i, m in enumerate(cfg.get("monitors", [])):
                        if str(m.get("name", "")) == edit_original_name:
                            keep_devices = [str(x) for x in m.get("devices", [])]
                            new_monitor["devices"] = keep_devices
                            cfg["monitors"][i] = new_monitor
                            updated = True
                            break
                    if not updated:
                        cfg.setdefault("monitors", []).append(new_monitor)
                elif replace_all:
                    cfg["monitors"] = [new_monitor]
                else:
                    existing = _find_monitor_by_name(cfg.get("monitors", []), name)
                    if existing is not None:
                        existing["check_mode"] = mode
                        existing["kuma_url"] = kuma_url
                    else:
                        cfg.setdefault("monitors", []).append(new_monitor)
                cfg["cron_enabled"] = cron_enabled
                cfg["cron_interval_minutes"] = interval
                # Package runtime uses headless scheduler helper; avoid per-user crontab dependencies.
                save_config(cfg, reapply_cron=False)
                append_ui_log(
                    f"save-config | name={name} | mode={mode} | cron={'on' if cron_enabled else 'off'} | interval={interval} | edit_target={edit_original_name or '-'}"
                )
                self._reply_html(_render_setup_html(message="Saved successfully", ui_view="setup", ssl_warning=ssl_warning))
            except Exception as e:
                append_ui_log(f"ui-error | {type(e).__name__}: {e}")
                self._reply_html(_render_setup_html(error=f"Failed to save: {type(e).__name__}: {e}", ui_view=ui_view, ssl_warning=ssl_warning), code=500)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Setup UI running on http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping setup UI.")
    finally:
        server.server_close()
    return 0


def run_scheduled() -> int:
    cfg = load_config()
    if not bool(cfg.get("cron_enabled", False)):
        return 0
    interval = int(cfg.get("cron_interval_minutes", 60) or 60)
    if not _is_scheduled_due(interval):
        return 0
    append_ui_log(f"scheduled-run | starting | interval_min={interval}")
    run_check(debug=bool(cfg.get("debug", False)), interactive=False)
    _touch_scheduled_run()
    append_ui_log("scheduled-run | completed")
    return 0


def run_scheduled_loop() -> int:
    append_ui_log("scheduled-loop | started")
    try:
        while True:
            try:
                run_scheduled()
            except Exception as e:
                append_ui_log(f"scheduled-loop | error | {type(e).__name__}: {e}")
            time.sleep(60)
    except KeyboardInterrupt:
        pass
    append_ui_log("scheduled-loop | stopped")
    return 0


def main_menu() -> str:
    cfg = load_config()
    print("\n" + "=" * 50)
    print(f"  {PRODUCT_NAME}")
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
    if "--run-smart-helper" in sys.argv:
        sys.exit(run_smart_helper())
    if "--run-system-log-helper" in sys.argv:
        sys.exit(run_system_log_helper())
    if "--run-scheduled" in sys.argv:
        sys.exit(run_scheduled())
    if "--run-scheduled-loop" in sys.argv:
        sys.exit(run_scheduled_loop())
    if "--ui" in sys.argv:
        ui_host = "0.0.0.0"
        ui_port = 8787
        if "--host" in sys.argv:
            try:
                ui_host = sys.argv[sys.argv.index("--host") + 1]
            except (ValueError, IndexError):
                print("Invalid --host usage. Example: --host 0.0.0.0")
                sys.exit(1)
        if "--port" in sys.argv:
            try:
                ui_port = int(sys.argv[sys.argv.index("--port") + 1])
            except (ValueError, IndexError):
                print("Invalid --port usage. Example: --port 8787")
                sys.exit(1)
        sys.exit(run_setup_ui(host=ui_host, port=ui_port))
    if len(sys.argv) > 1 and sys.argv[1] in ("--run", "-r"):
        dbg = "--debug" in sys.argv or "-d" in sys.argv
        run_check(debug=dbg, interactive=False)
        sys.exit(0)
    sys.exit(main())
