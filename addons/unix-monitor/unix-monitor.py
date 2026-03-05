#!/usr/bin/env python3

#########################################
# Author: Konrad von Burg               #
# Date: 2026-02-19                      #
# Description: Interactive menu script  #
# to monitor Unix host storage and   #
# SMART health and report to Kuma.      #
# Version: 1.0.0                        #
# Copyright (c) 2026 EasySystems GmbH   #
#                                       #
# Usage:                                #
#   python3 unix-monitor.py         #
#   python3 unix-monitor.py --run   #
#   python3 unix-monitor.py --run -d
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
import hashlib
import hmac
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import traceback
import platform
import warnings
from io import BytesIO
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse
try:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning, module="cgi")
        import cgi  # type: ignore[import-not-found]
except Exception:
    cgi = None
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


VERSION = "1.0.0-0054"
CONFIG_FILE_MODE = 0o600
CRON_MARKER = "# unix-monitor.py - do not edit this line manually"
INTERVAL_MIN = 1
INTERVAL_MAX = 1440
CHECK_MODES = ("mount", "smart", "storage", "ping", "port", "dns", "backup")
PEER_ROLES = ("standalone", "agent", "master")
PEER_HEALTH_TIMEOUT_SEC = 180
BACK_KEYS = ("0", "b", "back", "q", "quit")
CHANGES_NOTICE = "  Changes are not saved until you confirm (Save/Apply)."
ALLOWED_SCHEMES = ("https", "http")
KUMA_PUSH_PATH_PATTERN = re.compile(r"^/api/push/[A-Za-z0-9_-]+$")
UI_LOG_MAX_LINES = 200
UI_LOG_MSG_MAX_CHARS = 6000
NAS_VOLUME_PATTERN = re.compile(r"^/volume[0-9]+$")
SMART_CACHE_MAX_AGE_SEC = 20 * 60
BACKUP_CACHE_MAX_AGE_SEC = 20 * 60
TASK_STATUS_MAX_DETAIL = 2000
HISTORY_MAX_ENTRIES = 500
AUTH_FILE_MODE = 0o600
AUTH_COOKIE_NAME = "unix_auth"
AUTH_CHALLENGE_COOKIE_NAME = "unix_auth_challenge"
AUTH_SESSION_TTL_SEC = 1800
AUTH_CHALLENGE_TTL_SEC = 300
AUTH_MAX_LOGIN_ATTEMPTS = 5
AUTH_LOCKOUT_DURATION_SEC = 15 * 60
SYSTEM_LABEL = (platform.uname().system or platform.system() or "Unix").strip()
BRAND_NAME = "EasySystems GmbH"
PRODUCT_NAME = f"{SYSTEM_LABEL} Kuma Monitor Addon"
BRAND_URL = "https://www.easysystems.ch/de"
BRAND_LOGO_URL = "https://www.easysystems.ch/img/logo-blue.png"
BRAND_FAVICON_URL = "https://www.easysystems.ch/Themes/essys_v2-v1_19-08-2025/favicon/android-icon-96x96.png"
BRAND_AUTHOR = "Konrad von Burg"
BRAND_COPYRIGHT = "Copyright (c) 2026"
REPO_URL = "https://github.com/gsiscotty/Uptime.Kuma.Monitor.Tools"
GITHUB_REPO = "gsiscotty/Uptime.Kuma.Monitor.Tools"
AUTOUPDATE_CHECK_INTERVAL_SEC = 6 * 3600  # Max once per 6 hours
UPDATE_SCRIPT_REMOTE_PATH = "addons/unix-monitor/unix-monitor.py"
PRODUCT_DESC = (
    "Checks Unix host SMART and storage health, provides guided elevated-access setup and diagnostics, "
    "and pushes monitor status to Uptime Kuma."
)


def _normalize_source_platform(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return "unix"
    if "synology" in raw or raw == "dsm":
        return "synology"
    return "unix"


def _monitor_source_platform(monitor: Dict[str, Any]) -> str:
    hint = (
        str(monitor.get("source_platform", "") or "")
        or str(monitor.get("platform", "") or "")
        or str(monitor.get("source", "") or "")
    )
    return _normalize_source_platform(hint)


def _check_title_for_platform(source_platform: str) -> str:
    return "Synology check" if _normalize_source_platform(source_platform) == "synology" else "Unix check"


def get_script_path() -> Path:
    return Path(__file__).resolve()


def get_auth_state_path() -> Path:
    return get_runtime_data_dir() / "unix-auth.json"


def _default_auth_state() -> Dict[str, Any]:
    return {
        "auth_initialized": False,
        "password_hash": "",
        "totp_secret": "",
        "recovery_hashes": [],
        "failed_attempts": 0,
        "lockout_until": 0,
        "last_login_ip": "",
        "last_login_at": 0,
        "login_history": [],
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
    changed = False
    defaults = _default_auth_state()
    for k, v in defaults.items():
        if k not in data:
            data[k] = v
            changed = True
    if "session_secret" not in data or not str(data.get("session_secret", "")).strip():
        data["session_secret"] = secrets.token_hex(32)
        changed = True
    if changed:
        _save_auth_state(data)
    return data


def _save_auth_state(data: Dict[str, Any]) -> None:
    p = get_auth_state_path()
    tmp = p.parent / ".unix-auth.json.tmp"
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


def _detect_primary_server_ip() -> str:
    """Best-effort primary local IP for UI display."""
    candidates: List[str] = []
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None):
            if len(info) < 5 or not info[4]:
                continue
            ip = str(info[4][0])
            if ip and ip not in candidates:
                candidates.append(ip)
    except Exception:
        pass
    for ip in candidates:
        if "." in ip and not ip.startswith("127."):
            return ip
    for ip in candidates:
        if ":" in ip and ip != "::1":
            return ip
    return candidates[0] if candidates else "n/a"


def _list_system_ips() -> List[str]:
    ips: List[str] = []
    rc, out = _run_cmd(["ip", "-o", "addr", "show"], timeout_sec=5)
    if rc == 0 and out.strip():
        for ln in out.splitlines():
            m = re.search(r"\sinet6?\s+([0-9a-fA-F\.:]+)/\d+", ln)
            if not m:
                continue
            ip = m.group(1).strip()
            if ip and ip not in ips:
                ips.append(ip)
        if ips:
            return ips
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None):
            if len(info) < 5 or not info[4]:
                continue
            ip = str(info[4][0]).strip()
            if ip and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def _ntp_sync_details() -> Dict[str, str]:
    result = {"synced": "unknown", "service": "unknown", "source": "unknown", "detail": "No NTP details available"}
    rc, out = _run_cmd(["timedatectl", "show", "-p", "NTPSynchronized", "-p", "NTPService", "-p", "SystemClockSynchronized"], timeout_sec=5)
    if rc == 0 and out.strip():
        values: Dict[str, str] = {}
        for ln in out.splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                values[k.strip()] = v.strip()
        ntp_sync = values.get("NTPSynchronized", values.get("SystemClockSynchronized", "unknown")).lower()
        result["synced"] = "yes" if ntp_sync == "yes" else ("no" if ntp_sync == "no" else "unknown")
        result["service"] = values.get("NTPService", "unknown") or "unknown"
    for cmd in (["chronyc", "sources", "-n"], ["ntpq", "-pn"]):
        rc2, out2 = _run_cmd(cmd, timeout_sec=6)
        if rc2 != 0 or not out2.strip():
            continue
        lines = [ln.strip() for ln in out2.splitlines() if ln.strip()]
        src = ""
        for ln in lines:
            if ln.startswith(("^*", "*", "+", "^+")):
                parts = ln.split()
                if len(parts) >= 2:
                    src = parts[1]
                    break
        if not src and len(lines) > 2:
            parts = lines[2].split()
            if len(parts) >= 2:
                src = parts[1]
        if src:
            result["source"] = src
            result["detail"] = f"Synced={result['synced']} | Service={result['service']} | Source={src}"
            return result
    result["detail"] = f"Synced={result['synced']} | Service={result['service']} | Source={result['source']}"
    return result


def _append_login_event(auth: Dict[str, Any], ip: str, state: str) -> None:
    events = auth.get("login_history", [])
    if not isinstance(events, list):
        events = []
    events.append({"ts": int(time.time()), "ip": str(ip or "unknown"), "state": str(state or "unknown")})
    auth["login_history"] = events[-20:]


def get_config_path() -> Path:
    script_dir = get_script_path().parent
    home_config = Path.home() / ".config" / "unix-monitor.json"
    package_var = Path("/var/lib/unix-monitor/unix-monitor.json")
    if package_var.exists():
        return package_var
    script_local = script_dir / "unix-monitor.json"
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
    script_local = get_script_path().parent / "unix-monitor.json"
    home_config = Path.home() / ".config" / "unix-monitor.json"
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
    package_var_dir = Path("/var/lib/unix-monitor")
    home_dir = Path.home() / ".config" / "unix-monitor"
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
    return get_runtime_data_dir() / "unix-monitor-ui.log"


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
        if filt in ("smart", "storage", "ping", "port", "dns", "backup"):
            lines = [ln for ln in lines if filt in ln.lower()]
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


def _clear_file(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


def clear_smart_cache() -> None:
    _clear_file(get_smart_cache_path())


def clear_backup_cache() -> None:
    _clear_file(get_backup_cache_path())


def clear_system_log_cache() -> None:
    _clear_file(get_system_log_cache_path())


def clear_task_status() -> None:
    _clear_file(get_task_status_path())


def clear_history() -> None:
    _save_history([])


# ---------------------------------------------------------------------------
# Peering (multi-instance master/agent)
# ---------------------------------------------------------------------------

def _get_instance_id(cfg: Dict[str, Any]) -> str:
    iid = str(cfg.get("instance_id", "") or "").strip()
    if iid:
        return iid
    import uuid
    iid = str(uuid.uuid4())
    cfg["instance_id"] = iid
    save_config(cfg, reapply_cron=False)
    return iid


def _is_valid_peer_instance_id(instance_id: str) -> bool:
    iid = str(instance_id or "").strip()
    if len(iid) < 8:
        return False
    if iid.lower() in {"none", "null", "unknown", "-", "?"}:
        return False
    return bool(re.match(r"^[A-Za-z0-9_-]+$", iid))


def get_peer_data_dir() -> Path:
    d = get_runtime_data_dir() / "peers"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load_peer_snapshot(peer_id: str) -> Optional[Dict[str, Any]]:
    p = get_peer_data_dir() / f"{peer_id}.json"
    if not p.exists():
        return None
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _save_peer_snapshot(peer_id: str, data: Dict[str, Any]) -> None:
    d = get_peer_data_dir()
    tmp = d / f".{peer_id}.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(str(tmp), str(d / f"{peer_id}.json"))
    except OSError:
        pass


def _load_all_peer_snapshots() -> List[Dict[str, Any]]:
    d = get_peer_data_dir()
    results: List[Dict[str, Any]] = []
    if not d.exists():
        return results
    for p in sorted(d.glob("*.json")):
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                results.append(data)
        except (OSError, json.JSONDecodeError):
            pass
    return results


# ---------------------------------------------------------------------------
# Peering Security: mTLS Certificate Management + Payload Encryption
# ---------------------------------------------------------------------------

def get_certs_dir() -> Path:
    d = get_runtime_data_dir() / "certs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _openssl_available() -> bool:
    try:
        rc, _ = _run_cmd(["openssl", "version"], timeout_sec=5)
        return rc == 0
    except Exception:
        return False


def _generate_ca(force: bool = False) -> Tuple[bool, str]:
    """Generate a self-signed CA key + cert for the master. Returns (ok, message)."""
    d = get_certs_dir()
    ca_key = d / "ca.key"
    ca_crt = d / "ca.crt"
    if ca_key.exists() and ca_crt.exists() and not force:
        return True, "CA already exists."
    if not _openssl_available():
        return False, "openssl not found on this system."
    try:
        rc, out = _run_cmd([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_crt),
            "-days", "3650", "-subj", "/CN=UnixMonitorCA",
        ], timeout_sec=30)
        if rc != 0:
            return False, f"openssl CA generation failed (rc={rc}): {out[:200]}"
        ca_key.chmod(0o600)
        ca_crt.chmod(0o644)
        append_ui_log("mtls | CA key+cert generated")
        return True, "CA generated."
    except Exception as e:
        return False, f"CA generation error: {e}"


def _generate_instance_cert(instance_id: str, cn_prefix: str = "peer") -> Tuple[bool, str]:
    """Generate a key + CSR, sign it with the CA. Returns (ok, message)."""
    d = get_certs_dir()
    ca_key = d / "ca.key"
    ca_crt = d / "ca.crt"
    if not ca_key.exists() or not ca_crt.exists():
        return False, "CA not generated yet."
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', instance_id)[:40]
    key_path = d / f"{safe_id}.key"
    csr_path = d / f"{safe_id}.csr"
    crt_path = d / f"{safe_id}.crt"
    try:
        rc, out = _run_cmd([
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path), "-out", str(csr_path),
            "-subj", f"/CN={cn_prefix}-{safe_id[:20]}",
        ], timeout_sec=20)
        if rc != 0:
            return False, f"CSR generation failed: {out[:200]}"
        rc, out = _run_cmd([
            "openssl", "x509", "-req", "-in", str(csr_path),
            "-CA", str(ca_crt), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(crt_path),
            "-days", "3650",
        ], timeout_sec=20)
        if rc != 0:
            return False, f"cert signing failed: {out[:200]}"
        key_path.chmod(0o600)
        crt_path.chmod(0o644)
        csr_path.unlink(missing_ok=True)
        append_ui_log(f"mtls | cert generated for {cn_prefix}-{safe_id[:20]}")
        return True, "Certificate generated and signed."
    except Exception as e:
        return False, f"cert generation error: {e}"


def _sign_agent_csr(csr_pem: str, agent_id: str) -> Tuple[Optional[str], str]:
    """Sign an agent CSR with the CA. Returns (signed_cert_pem_or_None, message)."""
    d = get_certs_dir()
    ca_key = d / "ca.key"
    ca_crt = d / "ca.crt"
    if not ca_key.exists() or not ca_crt.exists():
        return None, "CA not available."
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', agent_id)[:40]
    csr_file = d / f"agent-{safe_id}.csr"
    crt_file = d / f"agent-{safe_id}.crt"
    try:
        csr_file.write_text(csr_pem, encoding="utf-8")
        rc, out = _run_cmd([
            "openssl", "x509", "-req", "-in", str(csr_file),
            "-CA", str(ca_crt), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(crt_file),
            "-days", "3650",
        ], timeout_sec=20)
        csr_file.unlink(missing_ok=True)
        if rc != 0:
            return None, f"signing failed: {out[:200]}"
        signed_pem = crt_file.read_text(encoding="utf-8")
        crt_file.chmod(0o644)
        append_ui_log(f"mtls | signed agent cert for {agent_id[:20]}")
        return signed_pem, "Agent cert signed."
    except Exception as e:
        return None, f"signing error: {e}"


def _get_ca_fingerprint() -> str:
    ca_crt = get_certs_dir() / "ca.crt"
    if not ca_crt.exists():
        return ""
    try:
        rc, out = _run_cmd(["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", str(ca_crt)], timeout_sec=5)
        if rc == 0 and "=" in out:
            return out.strip().split("=", 1)[1].strip()
    except Exception:
        pass
    return ""


def _list_signed_agents() -> List[str]:
    d = get_certs_dir()
    agents = []
    for p in sorted(d.glob("agent-*.crt")):
        agents.append(p.stem.replace("agent-", "", 1))
    return agents


def _revoke_agent_cert(agent_id: str) -> str:
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', agent_id)[:40]
    d = get_certs_dir()
    removed = False
    for suffix in (".crt", ".key", ".csr"):
        p = d / f"agent-{safe_id}{suffix}"
        if p.exists():
            p.unlink()
            removed = True
    if removed:
        append_ui_log(f"mtls | revoked cert for agent {agent_id[:20]}")
        return f"Certificate for {agent_id} revoked."
    return f"No certificate found for {agent_id}."


def _get_mtls_cert_paths(cfg: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (cert_path, key_path, ca_cert_path) if all exist, else (None, None, None)."""
    d = get_certs_dir()
    ca_crt = d / "ca.crt"
    if not ca_crt.exists():
        return None, None, None
    instance_id = str(cfg.get("instance_id", "") or "").strip()
    if not instance_id:
        return None, None, None
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', instance_id)[:40]
    cert_path = d / f"{safe_id}.crt"
    key_path = d / f"{safe_id}.key"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path), str(ca_crt)
    return None, None, None


def _get_mtls_security_status(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Return summary of mTLS and signing state for display in UI."""
    d = get_certs_dir()
    ca_exists = (d / "ca.crt").exists()
    fingerprint = _get_ca_fingerprint() if ca_exists else ""
    cert, key, ca = _get_mtls_cert_paths(cfg)
    instance_cert_ok = cert is not None
    signed_agents = _list_signed_agents() if ca_exists else []
    openssl_ok = _openssl_available()
    signing_active = instance_cert_ok and openssl_ok and key is not None
    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
    has_master_cert = (d / "master.crt").exists() if role == "agent" else False
    return {
        "openssl_available": openssl_ok,
        "ca_exists": ca_exists,
        "ca_fingerprint": fingerprint,
        "instance_cert_ok": instance_cert_ok,
        "signed_agents": signed_agents,
        "mtls_active": ca_exists and instance_cert_ok,
        "signing_active": signing_active,
        "has_master_cert": has_master_cert,
    }


# --- Payload encryption (AES-GCM) for HTTP safety net ---

def _derive_aes_key(token: str, salt: bytes = b"synmon-peer-v1") -> bytes:
    """Derive a 32-byte AES key from the peering token using PBKDF2."""
    return hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt, 100000)


def _encrypt_payload(plaintext: str, token: str) -> str:
    """Encrypt a JSON string with AES-256-GCM using the peering token. Returns base64(iv + tag + ciphertext)."""
    key = _derive_aes_key(token)
    iv = secrets.token_bytes(12)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[import-not-found]
        aes = AESGCM(key)
        ct = aes.encrypt(iv, plaintext.encode("utf-8"), None)
        return base64.b64encode(iv + ct).decode("ascii")
    except ImportError:
        pass
    # Pure-Python AES-GCM fallback using openssl CLI
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pt") as ptf:
        ptf.write(plaintext.encode("utf-8"))
        ptf_name = ptf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".ct") as ctf:
        ctf_name = ctf.name
    try:
        rc, out = _run_cmd([
            "openssl", "enc", "-aes-256-gcm", "-e",
            "-K", key.hex(), "-iv", iv.hex(),
            "-in", ptf_name, "-out", ctf_name,
        ], timeout_sec=10)
        if rc == 0 and Path(ctf_name).exists():
            ct_data = Path(ctf_name).read_bytes()
            return base64.b64encode(iv + ct_data).decode("ascii")
    finally:
        Path(ptf_name).unlink(missing_ok=True)
        Path(ctf_name).unlink(missing_ok=True)
    # Last resort: XOR-based cipher (not as strong but still encrypts)
    ct_bytes = bytearray()
    key_stream = hashlib.sha512(key + iv).digest()
    for i, b in enumerate(plaintext.encode("utf-8")):
        if i % 64 == 0 and i > 0:
            key_stream = hashlib.sha512(key + iv + i.to_bytes(4, "big")).digest()
        ct_bytes.append(b ^ key_stream[i % 64])
    tag = hmac.new(key, iv + bytes(ct_bytes), hashlib.sha256).digest()[:16]
    return base64.b64encode(iv + tag + bytes(ct_bytes)).decode("ascii")


def _decrypt_payload(encoded: str, token: str) -> Optional[str]:
    """Decrypt an encrypted payload. Returns plaintext or None on failure."""
    key = _derive_aes_key(token)
    try:
        raw = base64.b64decode(encoded)
    except Exception:
        return None
    if len(raw) < 13:
        return None
    iv = raw[:12]
    rest = raw[12:]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[import-not-found]
        aes = AESGCM(key)
        plaintext = aes.decrypt(iv, rest, None)
        return plaintext.decode("utf-8")
    except ImportError:
        pass
    except Exception:
        pass
    # Try XOR fallback: iv(12) + tag(16) + ciphertext
    if len(rest) < 16:
        return None
    tag = rest[:16]
    ct_bytes = rest[16:]
    expected_tag = hmac.new(key, iv + ct_bytes, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, expected_tag):
        return None
    plaintext_bytes = bytearray()
    key_stream = hashlib.sha512(key + iv).digest()
    for i, b in enumerate(ct_bytes):
        if i % 64 == 0 and i > 0:
            key_stream = hashlib.sha512(key + iv + i.to_bytes(4, "big")).digest()
        plaintext_bytes.append(b ^ key_stream[i % 64])
    return bytes(plaintext_bytes).decode("utf-8", errors="ignore")


BACKUP_SALT = b"unix-monitor-backup-v1"


def _derive_backup_key(user_key: str) -> bytes:
    """Derive a 32-byte AES key from user-provided backup key."""
    return hashlib.pbkdf2_hmac("sha256", user_key.encode("utf-8"), BACKUP_SALT, 100000)


def _encrypt_backup(plaintext: str, user_key: str) -> str:
    """Encrypt backup payload with user key. Returns base64(iv + tag + ciphertext)."""
    key = _derive_backup_key(user_key)
    iv = secrets.token_bytes(12)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[import-not-found]
        aes = AESGCM(key)
        ct = aes.encrypt(iv, plaintext.encode("utf-8"), None)
        return base64.b64encode(iv + ct).decode("ascii")
    except ImportError:
        pass
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pt") as ptf:
        ptf.write(plaintext.encode("utf-8"))
        ptf_name = ptf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".ct") as ctf:
        ctf_name = ctf.name
    try:
        rc, _ = _run_cmd([
            "openssl", "enc", "-aes-256-gcm", "-e",
            "-K", key.hex(), "-iv", iv.hex(),
            "-in", ptf_name, "-out", ctf_name,
        ], timeout_sec=10)
        if rc == 0 and Path(ctf_name).exists():
            ct_data = Path(ctf_name).read_bytes()
            return base64.b64encode(iv + ct_data).decode("ascii")
    finally:
        Path(ptf_name).unlink(missing_ok=True)
        Path(ctf_name).unlink(missing_ok=True)
    ct_bytes = bytearray()
    key_stream = hashlib.sha512(key + iv).digest()
    for i, b in enumerate(plaintext.encode("utf-8")):
        if i % 64 == 0 and i > 0:
            key_stream = hashlib.sha512(key + iv + i.to_bytes(4, "big")).digest()
        ct_bytes.append(b ^ key_stream[i % 64])
    tag = hmac.new(key, iv + bytes(ct_bytes), hashlib.sha256).digest()[:16]
    return base64.b64encode(iv + tag + bytes(ct_bytes)).decode("ascii")


def _decrypt_backup(encoded: str, user_key: str) -> Optional[str]:
    """Decrypt backup payload. Returns plaintext or None on failure."""
    key = _derive_backup_key(user_key)
    try:
        raw = base64.b64decode(encoded)
    except Exception:
        return None
    if len(raw) < 12:
        return None
    iv = raw[:12]
    rest = raw[12:]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[import-not-found]
        aes = AESGCM(key)
        plaintext = aes.decrypt(iv, rest, None)
        return plaintext.decode("utf-8")
    except ImportError:
        pass
    except Exception:
        return None
    if len(rest) < 16:
        return None
    tag = rest[:16]
    ct_bytes = rest[16:]
    expected_tag = hmac.new(key, iv + ct_bytes, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, expected_tag):
        return None
    plaintext_bytes = bytearray()
    key_stream = hashlib.sha512(key + iv).digest()
    for i, b in enumerate(ct_bytes):
        if i % 64 == 0 and i > 0:
            key_stream = hashlib.sha512(key + iv + i.to_bytes(4, "big")).digest()
        plaintext_bytes.append(b ^ key_stream[i % 64])
    return bytes(plaintext_bytes).decode("utf-8", errors="ignore")


def _agent_request_cert(cfg: Dict[str, Any]) -> str:
    """Agent requests a signed cert from master and stores cert chain locally."""
    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
    if role != "agent":
        return "Certificate request is only available for agent role."
    master_host, master_port = _parse_peer_host_port(
        cfg.get("peer_master_url", ""), int(cfg.get("peer_port", PEER_DEFAULT_PORT) or PEER_DEFAULT_PORT)
    )
    token = str(cfg.get("peering_token", "") or "").strip()
    if not master_host or not token:
        return "Missing master host or peering token."
    master_url = _resolve_peer_url(master_host, master_port, token, timeout=10)
    if not master_url:
        return f"Cannot reach master at {master_host}:{master_port}."
    if not _openssl_available():
        return "openssl not available on this system."
    instance_id = _get_instance_id(cfg)
    safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", instance_id)[:40]
    d = get_certs_dir()
    key_path = d / f"{safe_id}.key"
    csr_path = d / f"{safe_id}.csr"
    crt_path = d / f"{safe_id}.crt"
    try:
        rc, out = _run_cmd([
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path), "-out", str(csr_path),
            "-subj", f"/CN=agent-{safe_id[:20]}",
        ], timeout_sec=25)
        if rc != 0:
            return f"CSR generation failed: {out[:200]}"
        csr_pem = csr_path.read_text(encoding="utf-8")
        payload = {
            "instance_id": instance_id,
            "instance_name": str(cfg.get("instance_name", "") or ""),
            "version": VERSION,
            "monitor_count": len(cfg.get("monitors", [])) if isinstance(cfg.get("monitors", []), list) else 0,
            "csr_pem": csr_pem,
        }
        status, body = _peer_http_request(master_url, token, "POST", "/api/peer/register", payload=payload, timeout=15)
        if status >= 300:
            return f"Register failed (HTTP {status}): {body[:300]}"
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return "Register failed: invalid response from master."
        signed_cert = str(data.get("signed_cert", "") or "").strip()
        ca_cert = str(data.get("ca_cert", "") or "").strip()
        master_cert = str(data.get("master_cert", "") or "").strip()
        if not signed_cert or not ca_cert:
            return "Register failed: master did not return signed cert + CA cert."
        crt_path.write_text(signed_cert + ("\n" if not signed_cert.endswith("\n") else ""), encoding="utf-8")
        (d / "ca.crt").write_text(ca_cert + ("\n" if not ca_cert.endswith("\n") else ""), encoding="utf-8")
        if master_cert:
            (d / "master.crt").write_text(master_cert + ("\n" if not master_cert.endswith("\n") else ""), encoding="utf-8")
            (d / "master.crt").chmod(0o644)
        key_path.chmod(0o600)
        crt_path.chmod(0o644)
        (d / "ca.crt").chmod(0o644)
        csr_path.unlink(missing_ok=True)
        return "Certificate signed by master CA and stored locally."
    except Exception as e:
        return f"Certificate request failed: {type(e).__name__}: {e}"


def _peer_push_to_master(cfg: Dict[str, Any]) -> str:
    master_host, master_port = _parse_peer_host_port(
        cfg.get("peer_master_url", ""), int(cfg.get("peer_port", PEER_DEFAULT_PORT) or PEER_DEFAULT_PORT)
    )
    token = str(cfg.get("peering_token", "") or "").strip()
    if not master_host or not token:
        return "Agent sync skipped: no master host or peering token configured."
    master_url = _resolve_peer_url(master_host, master_port, token, timeout=8)
    if not master_url:
        return f"Cannot reach master at {master_host}:{master_port}."
    instance_id = _get_instance_id(cfg)
    instance_name = str(cfg.get("instance_name", "") or "").strip() or instance_id[:8]
    history = _load_history()
    state = _load_monitor_state()
    monitors_cfg = cfg.get("monitors", [])
    cb_host, cb_port = _parse_peer_host_port(
        cfg.get("agent_callback_url", ""), int(cfg.get("peer_port", PEER_DEFAULT_PORT) or PEER_DEFAULT_PORT)
    )
    push_payload: Dict[str, Any] = {
        "instance_id": instance_id,
        "instance_name": instance_name,
        "version": VERSION,
        "platform": SYSTEM_LABEL,
        "platform_family": "unix",
        "monitors": monitors_cfg,
        "history": history[-200:],
        "state": state,
        "pushed_at": int(time.time()),
    }
    if cb_host:
        push_payload["callback_url"] = f"{cb_host}:{cb_port}"
    try:
        t0 = time.time()
        status, body = _peer_http_request(master_url, token, "POST", "/api/peer/push", push_payload, timeout=12)
        latency_ms = round((time.time() - t0) * 1000)
        cfg["last_peer_sync"] = int(time.time())
        cfg["last_peer_sync_latency_ms"] = latency_ms
        if status < 300:
            cfg["last_peer_sync_result"] = f"OK ({latency_ms} ms)"
            save_config(cfg, reapply_cron=False)
            return f"Pushed to master ({master_url}): {status} ({latency_ms} ms)"
        cfg["last_peer_sync_result"] = f"HTTP {status}"
        save_config(cfg, reapply_cron=False)
        return f"Master push failed ({master_url}): HTTP {status} - {body}"
    except Exception as e:
        cfg["last_peer_sync"] = int(time.time())
        cfg["last_peer_sync_result"] = f"Error: {type(e).__name__}"
        cfg["last_peer_sync_latency_ms"] = None
        save_config(cfg, reapply_cron=False)
        return f"Master push error: {type(e).__name__}: {e}"


PEER_DEFAULT_PORT = 8787


def _parse_peer_host_port(url_or_host: str, default_port: int = PEER_DEFAULT_PORT) -> Tuple[str, int]:
    """Extract host and port from URL (https://host:port) or plain host or host:port. Returns (host, port)."""
    s = str(url_or_host or "").strip().rstrip("/")
    if not s:
        return ("", default_port)
    parsed = urlparse(s if "://" in s else f"http://{s}")
    host = (parsed.hostname or parsed.path or s).strip()
    if not host:
        return ("", default_port)
    port = parsed.port if parsed.port is not None else default_port
    return (host, port)


def _peer_url_for_input_display(url: str, default_port: int = PEER_DEFAULT_PORT) -> str:
    """Return URL for display in agent URL input - omit :8787 when that's the port so user enters host only."""
    if not url or not str(url).strip():
        return ""
    host, port = _parse_peer_host_port(url, default_port)
    if not host:
        return ""
    if port == default_port:
        return host
    return f"{host}:{port}"


def _peer_url_for_open(url: str, default_port: int = PEER_DEFAULT_PORT) -> str:
    """Build full URL for opening agent UI in a new tab. Uses http when no scheme to avoid SSL errors."""
    if not url or not str(url).strip():
        return ""
    if "://" in url:
        return url.rstrip("/")
    host, port = _parse_peer_host_port(url, default_port)
    if not host:
        return ""
    return f"http://{host}:{port}"


def _resolve_peer_url(host: str, port: int, token: str, timeout: int = 5) -> str:
    """Try HTTPS first, fall back to HTTP. Returns the working base URL (e.g. https://host:port)."""
    if not host:
        return ""
    for scheme in ("https", "http"):
        base = f"{scheme}://{host}:{port}"
        try:
            status, _ = _peer_http_request(base, token, "GET", "/api/peer/health", timeout=timeout)
            if status < 500:
                return base.rstrip("/")
        except Exception:
            continue
    return f"https://{host}:{port}"  # prefer https for next attempt


def _resolve_peer_url_from_stored(url_or_host: str, token: str, timeout: int = 5) -> str:
    """Parse stored url (host, host:port, or full URL) and resolve to working scheme. Returns base URL."""
    host, port = _parse_peer_host_port(url_or_host)
    if not host:
        return ""
    return _resolve_peer_url(host, port, token, timeout)


def _peer_http_request(url: str, token: str, method: str = "GET",
                       path_override: str = "", payload: Optional[Dict[str, Any]] = None,
                       timeout: int = 10) -> Tuple[int, str]:
    """Low-level HTTP request to a peer instance. Returns (status_code, body_text)."""
    url = url.strip().rstrip("/")
    endpoint = url + (path_override or "/api/peer/health")
    parsed = urlparse(endpoint)
    req_path = parsed.path or path_override or "/api/peer/health"
    if parsed.query:
        req_path += "?" + parsed.query
    is_register = req_path.startswith("/api/peer/register")
    is_peer_api = req_path.startswith("/api/peer/")
    if parsed.scheme == "https":
        cfg = load_config()
        cert_path, key_path, ca_path = _get_mtls_cert_paths(cfg)
        if cert_path and key_path and ca_path:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ctx.load_verify_locations(ca_path)
            ctx.load_cert_chain(cert_path, key_path)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            # Bootstrap path before certificates exist.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if not is_register:
                append_ui_log("mtls | HTTPS request without local certs (token fallback)")
        conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=timeout)
    headers: Dict[str, str] = {"Authorization": f"Bearer {token}"}
    body_bytes: Optional[bytes] = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        if parsed.scheme != "https" and is_peer_api:
            plaintext = json.dumps(payload)
            body_bytes = json.dumps({"enc": _encrypt_payload(plaintext, token)}).encode("utf-8")
            headers["X-Peer-Encrypted"] = "1"
        else:
            body_bytes = json.dumps(payload).encode("utf-8")
    conn.request(method, req_path, body=body_bytes, headers=headers)
    resp = conn.getresponse()
    resp_raw = resp.read().decode("utf-8", errors="ignore")[:64000]
    resp_body = resp_raw
    if parsed.scheme != "https" and is_peer_api and resp_raw:
        try:
            wrapped = json.loads(resp_raw)
            if isinstance(wrapped, dict) and isinstance(wrapped.get("enc"), str):
                dec = _decrypt_payload(str(wrapped.get("enc", "")), token)
                if dec is not None:
                    resp_body = dec
        except (json.JSONDecodeError, ValueError):
            pass
    status = resp.status
    conn.close()
    return status, resp_body


def _peer_test_connection(url: str, token: str) -> str:
    url = url.strip().rstrip("/")
    if not url or not token:
        return "Missing URL or token."
    try:
        t0 = time.time()
        status, body = _peer_http_request(url, token, "GET", "/api/peer/health", timeout=8)
        latency_ms = round((time.time() - t0) * 1000)
        if status < 300:
            try:
                data = json.loads(body)
                name = data.get("instance_name", "") or data.get("instance_id", "?")
                role = data.get("role", "?")
                ver = data.get("version", "?")
                mc = data.get("monitor_count", 0)
                return (
                    f"OK: Connected to {name} ({latency_ms} ms)\n"
                    f"  Role: {role} | Version: {ver} | Monitors: {mc}"
                )
            except (json.JSONDecodeError, ValueError):
                return f"OK: {url} responded {status} ({latency_ms} ms)"
        return f"FAILED: {url} responded HTTP {status}"
    except Exception as e:
        return f"Connection error: {type(e).__name__}: {e}"


def _peer_sync_from_master(cfg: Dict[str, Any]) -> str:
    """Master pulls full snapshot from each agent, saves it, and updates peer status."""
    peers = cfg.get("peers", [])
    if not isinstance(peers, list) or not peers:
        return "No peers configured."
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return "No peering token configured."
    now = int(time.time())
    lines: List[str] = []
    for p in peers:
        pid = str(p.get("instance_id", ""))
        pname = str(p.get("instance_name", "") or pid[:8])
        p_url_raw = str(p.get("url", "") or "").strip().rstrip("/")
        if not p_url_raw:
            lines.append(f"{pname}: skipped (no URL)")
            continue
        p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=8)
        if not p_url:
            lines.append(f"{pname}: cannot reach {p_url_raw}")
            continue
        try:
            t0 = time.time()
            status, body = _peer_http_request(p_url, token, "GET", "/api/peer/snapshot", timeout=10)
            latency_ms = round((time.time() - t0) * 1000)
            if status < 300:
                p["last_seen"] = now
                p["status"] = "online"
                p["latency_ms"] = latency_ms
                try:
                    snap = json.loads(body)
                    p["monitor_count"] = len(snap.get("monitors", []))
                    p["instance_name"] = str(snap.get("instance_name", "") or pname)
                    p["version"] = str(snap.get("version", "") or "")
                    snap["received_at"] = now
                    _save_peer_snapshot(pid, snap)
                except (json.JSONDecodeError, ValueError):
                    pass
                lines.append(f"{pname}: online ({latency_ms} ms)")
            else:
                p["status"] = "offline"
                p["latency_ms"] = None
                lines.append(f"{pname}: HTTP {status}")
        except Exception as e:
            p["status"] = "offline"
            p["latency_ms"] = None
            lines.append(f"{pname}: {type(e).__name__}: {e}")
    cfg["peers"] = peers
    cfg["last_peer_sync"] = now
    save_config(cfg, reapply_cron=False)
    return "\n".join(lines) if lines else "Done."


def _trigger_peer_sync_bg(cfg: Dict[str, Any]) -> None:
    """Fire-and-forget peer sync in a background thread (agent push or master pull)."""
    role = str(cfg.get("peer_role", "") or "").lower()
    if role not in ("agent", "master"):
        return
    def _do_sync() -> None:
        try:
            fresh = load_config()
            r = fresh.get("peer_role", "")
            if str(r).lower() == "agent":
                result = _peer_push_to_master(fresh)
            elif str(r).lower() == "master":
                result = _peer_sync_from_master(fresh)
            else:
                return
            append_ui_log(f"peer-sync | auto: {result}")
        except Exception as exc:
            append_ui_log(f"peer-sync | auto error: {type(exc).__name__}: {exc}")
    threading.Thread(target=_do_sync, daemon=True).start()


def _fetch_agent_diag(
    cfg: Dict[str, Any],
    peer_id: str,
    view: str,
    log_filter: str = "all",
    resolve_timeout: int = 15,
    fetch_timeout: int = 25,
) -> str:
    """Master fetches diagnostic text from an agent."""
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return "No peering token configured."
    peers = cfg.get("peers", [])
    target = None
    for p in (peers if isinstance(peers, list) else []):
        if str(p.get("instance_id", "")) == peer_id:
            target = p
            break
    if not target:
        return f"Agent '{peer_id}' not found in peers."
    p_name = str(target.get("instance_name", "") or peer_id[:8])
    p_url_raw = str(target.get("url", "") or "").strip().rstrip("/")
    if not p_url_raw:
        return f"No URL configured for agent '{p_name}'."
    p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=resolve_timeout)
    if not p_url:
        return f"Cannot reach agent '{p_name}' at {p_url_raw}."
    try:
        qs = f"?view={quote(view)}&log_filter={quote(log_filter)}"
        status, body = _peer_http_request(p_url, token, "GET", f"/api/peer/diag{qs}", timeout=fetch_timeout)
        if status < 300:
            text = body
            try:
                data = json.loads(body)
                text = str(data.get("text", body))
            except (json.JSONDecodeError, ValueError):
                pass
            header = f"--- Agent: {p_name} ({p_url}) | View: {view} ---\n\n"
            return header + text
        return f"Agent returned HTTP {status}: {body[:500]}"
    except Exception as e:
        return f"Failed to fetch from agent: {type(e).__name__}: {e}"


def _trigger_agent_update(cfg: Dict[str, Any], peer_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Master triggers update on agent. Returns (session_id, error). session_id None on error."""
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return None, "No peering token configured."
    peers = cfg.get("peers", [])
    target = None
    for p in (peers if isinstance(peers, list) else []):
        if str(p.get("instance_id", "")) == peer_id:
            target = p
            break
    if not target:
        return None, f"Agent '{peer_id}' not found in peers."
    p_url_raw = str(target.get("url", "") or "").strip().rstrip("/")
    if not p_url_raw:
        return None, f"No URL configured for agent."
    p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=10)
    if not p_url:
        return None, f"Cannot reach agent at {p_url_raw}."
    try:
        status, body = _peer_http_request(p_url, token, "POST", "/api/peer/update", payload={}, timeout=15)
        if status in (200, 202):
            try:
                data = json.loads(body)
                return str(data.get("session_id", "") or ""), None
            except (json.JSONDecodeError, ValueError):
                return None, f"Invalid response: {body[:200]}"
        try:
            err = json.loads(body)
            msg = str(err.get("error", body))[:500]
            tb = err.get("traceback", "")
            if tb:
                return None, f"HTTP {status}: {msg}\n\nTraceback:\n{tb[:1500]}"
            return None, f"HTTP {status}: {msg}"
        except (json.JSONDecodeError, ValueError):
            return None, f"HTTP {status}: {body[:500]}"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _fetch_agent_update_status(cfg: Dict[str, Any], peer_id: str, session_id: str) -> Dict[str, Any]:
    """Master fetches update status from agent."""
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return {"error": "No peering token configured."}
    peers = cfg.get("peers", [])
    target = None
    for p in (peers if isinstance(peers, list) else []):
        if str(p.get("instance_id", "")) == peer_id:
            target = p
            break
    if not target:
        return {"error": f"Agent '{peer_id}' not found."}
    p_url_raw = str(target.get("url", "") or "").strip().rstrip("/")
    if not p_url_raw:
        return {"error": "No URL configured for agent."}
    p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=5)
    if not p_url:
        return {"error": f"Cannot reach agent at {p_url_raw}."}
    try:
        qs = f"?session_id={quote(session_id)}"
        status, body = _peer_http_request(p_url, token, "GET", f"/api/peer/update-status{qs}", timeout=10)
        if status < 300:
            try:
                return json.loads(body) if body else {}
            except (json.JSONDecodeError, ValueError):
                return {"error": "Invalid response", "raw": body[:200]}
        try:
            err = json.loads(body)
            return {"error": str(err.get("error", body))[:500], "stage": err.get("stage", "unknown")}
        except (json.JSONDecodeError, ValueError):
            return {"error": f"HTTP {status}", "stage": "unknown"}
    except Exception as e:
        return {"error": str(e), "stage": "unknown"}


def _diagnose_agent_diag_connection(cfg: Dict[str, Any], peer_id: str) -> str:
    """Run step-by-step diagnostic for master->agent log fetch. Returns a detailed report."""
    lines: List[str] = []
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return "Diagnostic: No peering token configured."
    peers = cfg.get("peers", []) or []
    target = None
    for p in peers:
        if str(p.get("instance_id", "")) == peer_id:
            target = p
            break
    if not target:
        return f"Diagnostic: Agent '{peer_id}' not found in peers."
    p_name = str(target.get("instance_name", "") or peer_id[:8])
    p_url_raw = str(target.get("url", "") or "").strip().rstrip("/")
    lines.append(f"=== Master->Agent Diag Connection Diagnostic ===")
    lines.append(f"Agent: {p_name} (id={peer_id})")
    lines.append(f"Stored URL: {p_url_raw or '(empty)'}")
    lines.append("")
    if not p_url_raw:
        lines.append("FAIL: No URL configured. Set the agent URL in Settings > Peering > Connected Agents.")
        return "\n".join(lines)
    host, port = _parse_peer_host_port(p_url_raw)
    lines.append(f"Parsed host: {host or '(none)'}  port: {port}")
    lines.append("")
    # Step 1: Try HTTPS
    lines.append("Step 1: Resolve URL (try HTTPS, then HTTP)...")
    t0 = time.time()
    try:
        resolved = _resolve_peer_url_from_stored(p_url_raw, token, timeout=15)
        elapsed = round((time.time() - t0) * 1000)
        if resolved:
            lines.append(f"  OK: Resolved to {resolved} ({elapsed} ms)")
        else:
            lines.append(f"  FAIL: Could not reach agent ({elapsed} ms). Tried HTTPS and HTTP on {host}:{port}.")
            lines.append("  Check: firewall, network path, agent service running, correct IP/hostname.")
            return "\n".join(lines)
    except Exception as ex:
        lines.append(f"  FAIL: {type(ex).__name__}: {ex}")
        return "\n".join(lines)
    # Step 2: Health check
    lines.append("")
    lines.append("Step 2: Health check (GET /api/peer/health)...")
    t0 = time.time()
    try:
        status, body = _peer_http_request(resolved, token, "GET", "/api/peer/health", timeout=10)
        elapsed = round((time.time() - t0) * 1000)
        if status < 300:
            lines.append(f"  OK: HTTP {status} ({elapsed} ms)")
        else:
            lines.append(f"  FAIL: HTTP {status} ({elapsed} ms) - {body[:200]}")
    except Exception as ex:
        lines.append(f"  FAIL: {type(ex).__name__}: {ex} (timeout or connection error)")
        lines.append("  If timeout: agent may be slow, on different VLAN, or firewall blocking.")
        return "\n".join(lines)
    # Step 3: Diag fetch
    lines.append("")
    lines.append("Step 3: Fetch diag (GET /api/peer/diag?view=logs)...")
    t0 = time.time()
    try:
        status, body = _peer_http_request(resolved, token, "GET", "/api/peer/diag?view=logs&log_filter=all", timeout=25)
        elapsed = round((time.time() - t0) * 1000)
        if status < 300:
            lines.append(f"  OK: HTTP {status} ({elapsed} ms, body ~{len(body)} chars)")
        else:
            lines.append(f"  FAIL: HTTP {status} ({elapsed} ms) - {body[:200]}")
    except Exception as ex:
        lines.append(f"  FAIL: {type(ex).__name__}: {ex} (timeout or connection error)")
        lines.append("  Diag payload can be large; try increasing timeout or check network latency.")
        return "\n".join(lines)
    lines.append("")
    lines.append("All steps passed. Log fetch should work.")
    return "\n".join(lines)


def _peer_create_remote_monitor(cfg: Dict[str, Any], peer_id: str,
                                monitor_cfg: Dict[str, Any]) -> str:
    """Master sends a monitor config to an agent for creation."""
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return "No peering token set."
    peers = cfg.get("peers", [])
    target = None
    for p in peers:
        if str(p.get("instance_id", "")) == peer_id:
            target = p
            break
    if not target:
        return f"Peer {peer_id} not found."
    p_url_raw = str(target.get("url", "") or "").strip().rstrip("/")
    if not p_url_raw:
        return f"Peer {target.get('instance_name', peer_id[:8])} has no URL configured."
    p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=10)
    if not p_url:
        return f"Cannot reach peer at {p_url_raw}."
    try:
        status, body = _peer_http_request(
            p_url, token, "POST", "/api/peer/create-monitor",
            payload=monitor_cfg, timeout=10,
        )
        if status < 300:
            return f"Monitor created on {target.get('instance_name', peer_id[:8])}: {body.strip()}"
        return f"Failed (HTTP {status}): {body.strip()}"
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


def _infer_peer_source_platform(cfg: Dict[str, Any], peer_id: str) -> str:
    for p in (cfg.get("peers", []) or []):
        if str(p.get("instance_id", "")) != peer_id:
            continue
        direct = str(p.get("platform", "") or "")
        if direct:
            return _normalize_source_platform(direct)
        probe = " ".join(
            [
                str(p.get("instance_name", "") or ""),
                str(p.get("version", "") or ""),
                str(p.get("url", "") or ""),
            ]
        )
        if "synology" in probe.lower() or "dsm" in probe.lower():
            return "synology"
    snap = _load_peer_snapshot(peer_id) or {}
    for key in ("platform", "platform_family", "instance_name", "version"):
        val = str(snap.get(key, "") or "")
        if "synology" in val.lower() or "dsm" in val.lower():
            return "synology"
    return "unix"


def get_smart_cache_path() -> Path:
    return get_runtime_data_dir() / "unix-smart-cache.json"


def get_system_log_cache_path() -> Path:
    return get_runtime_data_dir() / "unix-system-log-cache.json"


def _write_smart_cache(payload: Dict[str, Any]) -> None:
    path = get_smart_cache_path()
    tmp = path.parent / ".unix-smart-cache.json.tmp"
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
    tmp = path.parent / ".unix-system-log-cache.json.tmp"
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


def get_backup_cache_path() -> Path:
    return get_runtime_data_dir() / "unix-backup-cache.json"


def _write_backup_cache(payload: Dict[str, Any]) -> None:
    path = get_backup_cache_path()
    tmp = path.parent / ".unix-backup-cache.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(str(tmp), str(path))
        path.chmod(0o644)
    except OSError:
        pass


def _read_backup_cache() -> Optional[Dict[str, Any]]:
    path = get_backup_cache_path()
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def get_backup_helper_script_path() -> Path:
    return get_script_path().parent / "backup-helper.sh"


def get_smart_helper_script_path() -> Path:
    return get_script_path().parent / "smart-helper.sh"


def get_update_helper_path() -> Path:
    return get_script_path().parent / "update-helper.sh"


def _update_helper_env(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Env for update-helper: UNIX_MONITOR_USE_MAIN=1 when update_from_main is enabled."""
    if cfg is None:
        cfg = load_config()
    if cfg.get("update_from_main"):
        return {"UNIX_MONITOR_USE_MAIN": "1"}
    return {}


def _get_update_check_path() -> Path:
    return get_runtime_data_dir() / "unix-update-check.json"


def _version_tuple(version: str) -> Tuple[int, ...]:
    """Parse '1.0.0-0055' or 'v1.0.0-0055' to (1, 0, 0, 55) for comparison."""
    s = str(version or "").strip().lstrip("vV")
    if not s:
        return (0, 0, 0, 0)
    main, _, build = s.partition("-")
    parts = [int(x or 0) for x in re.split(r"[.]", main)[:3]]
    while len(parts) < 3:
        parts.append(0)
    try:
        parts.append(int(build.strip()) if build.strip() else 0)
    except ValueError:
        parts.append(0)
    return tuple(parts[:4])


def _selected_update_channel(cfg: Optional[Dict[str, Any]] = None) -> str:
    if cfg is None:
        cfg = load_config()
    return "main" if bool(cfg.get("update_from_main", False)) else "latest"


def _fetch_latest_release_tag() -> Tuple[Optional[str], Optional[str]]:
    try:
        req = http.client.HTTPSConnection("api.github.com", timeout=10)
        req.request(
            "GET",
            f"/repos/{GITHUB_REPO}/releases/latest",
            headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "unix-monitor"},
        )
        resp = req.getresponse()
        data = resp.read().decode("utf-8", errors="ignore")
        req.close()
        if resp.status != 200:
            return None, f"HTTP {resp.status}"
        obj = json.loads(data)
        tag = str(obj.get("tag_name", "") or "").strip().lstrip("vV")
        if not tag:
            return None, "No tag_name in response"
        return tag, None
    except Exception as e:
        return None, str(e) if str(e) else type(e).__name__


def _fetch_public_version_from_script(ref: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        req = http.client.HTTPSConnection("raw.githubusercontent.com", timeout=10)
        ref_path = quote(ref, safe="")
        req.request("GET", f"/{GITHUB_REPO}/{ref_path}/{UPDATE_SCRIPT_REMOTE_PATH}", headers={"User-Agent": "unix-monitor"})
        resp = req.getresponse()
        data = resp.read().decode("utf-8", errors="ignore")
        req.close()
        if resp.status != 200:
            return None, f"HTTP {resp.status}"
        m = re.search(r'^VERSION\s*=\s*"([^"]+)"', data, flags=re.MULTILINE)
        if not m:
            return None, "No VERSION in script"
        return m.group(1).strip(), None
    except Exception as e:
        return None, str(e) if str(e) else type(e).__name__


def _run_update_check(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Fetch selected channel public version, compare with local VERSION. Returns result dict."""
    channel = _selected_update_channel(cfg)
    result: Dict[str, Any] = {
        "checked_at": int(time.time()),
        "error": None,
        "latest_version": None,
        "public_version": None,
        "selected_channel": channel,
        "selected_ref": None,
        "effective_ref": None,
        "update_available": False,
    }
    try:
        if channel == "main":
            ref = "main"
        else:
            tag, tag_err = _fetch_latest_release_tag()
            if tag_err or not tag:
                result["error"] = tag_err or "Failed to resolve latest release"
                return result
            ref = tag

        result["selected_ref"] = ref
        effective_ref = ref
        public_version, version_err = _fetch_public_version_from_script(ref)
        if (version_err or not public_version) and ref != "main":
            # Match update-helper behavior: release tags may not include unix-monitor; fall back to main.
            public_version, version_err = _fetch_public_version_from_script("main")
            if not version_err and public_version:
                effective_ref = "main"
        if version_err or not public_version:
            result["error"] = version_err or "Failed to resolve public script version"
            return result

        result["public_version"] = public_version
        result["latest_version"] = public_version  # Backward compatibility with existing cache consumers
        result["effective_ref"] = effective_ref
        current = _version_tuple(VERSION)
        latest = _version_tuple(public_version)
        result["update_available"] = latest > current
    except Exception as e:
        result["error"] = str(e) if str(e) else type(e).__name__
    return result


def _save_update_check_result(result: Dict[str, Any]) -> None:
    path = _get_update_check_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.parent / ".unix-update-check.json.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        os.replace(str(tmp), str(path))
    except Exception:
        pass


def _load_update_check_result() -> Dict[str, Any]:
    path = _get_update_check_path()
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _get_autoupdate_on_logout_flag_path() -> Path:
    return get_runtime_data_dir() / "unix-autoupdate-on-logout.flag"


def _get_agent_update_session_path() -> Path:
    return get_runtime_data_dir() / "unix-agent-update-session.json"


def _load_agent_update_session() -> Dict[str, Any]:
    path = _get_agent_update_session_path()
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_agent_update_session(data: Dict[str, Any]) -> None:
    path = _get_agent_update_session_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.parent / ".unix-agent-update-session.json.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(str(tmp), str(path))
    except OSError:
        pass


def _run_agent_update_background() -> str:
    """Run update-helper in background, streaming output to session file. Returns session_id."""
    session_id = secrets.token_hex(8)
    helper = get_update_helper_path()
    script_dir = str(get_script_path().parent)
    append_ui_log(f"peer-update | session {session_id} helper={helper} script_dir={script_dir}")
    if not helper.exists():
        append_ui_log(f"peer-update | helper missing at {helper}")
        try:
            _save_agent_update_session({
                "session_id": session_id,
                "stage": "failed",
                "log": [],
                "error": "Update helper not found",
                "started_at": int(time.time()),
                "updated_at": int(time.time()),
            })
        except Exception as e:
            append_ui_log(f"peer-update | save session failed: {type(e).__name__}: {e}")
            raise
        return session_id
    try:
        _save_agent_update_session({
            "session_id": session_id,
            "stage": "running",
            "log": [],
            "error": None,
            "started_at": int(time.time()),
            "updated_at": int(time.time()),
        })
    except Exception as e:
        append_ui_log(f"peer-update | save session failed: {type(e).__name__}: {e}")
        raise

    def _do_update() -> None:
        log_lines: List[str] = []
        try:
            cfg = load_config()
            proc_env = {**os.environ, **_update_helper_env(cfg)}
            proc = subprocess.Popen(
                [str(helper), script_dir, "update", "no-restart"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=proc_env,
            )
            assert proc.stdout
            for line in iter(proc.stdout.readline, ""):
                line = line.rstrip("\n")
                if line:
                    log_lines.append(line)
                    sess = _load_agent_update_session()
                    sess["log"] = list(log_lines)
                    sess["updated_at"] = int(time.time())
                    _save_agent_update_session(sess)
            proc.wait()
            sess = _load_agent_update_session()
            sess["log"] = list(log_lines)
            sess["stage"] = "done" if proc.returncode == 0 else "failed"
            sess["error"] = None if proc.returncode == 0 else f"Exit code {proc.returncode}"
            sess["updated_at"] = int(time.time())
            _save_agent_update_session(sess)
            if proc.returncode == 0:
                time.sleep(2)
                for u in ("unix-monitor-ui.service", "unix-monitor-scheduler.timer", "unix-monitor-smart-helper.timer", "unix-monitor-backup-helper.timer", "unix-monitor-system-log-helper.timer"):
                    _run_cmd(["systemctl", "restart", u], timeout_sec=10)
        except Exception as e:
            log_lines.append(f"Error: {e}")
            sess = _load_agent_update_session()
            sess["log"] = list(log_lines)
            sess["stage"] = "failed"
            sess["error"] = str(e)
            sess["updated_at"] = int(time.time())
            _save_agent_update_session(sess)

    threading.Thread(target=_do_update, daemon=True).start()
    return session_id


def _maybe_run_autoupdate(defer_if_user_logged_in: bool = True) -> None:
    """Background: if autoupdate enabled, check for updates. If available and not deferred, run update. Throttled.
    When defer_if_user_logged_in=True (page load), only check and save result; do not apply.
    When defer_if_user_logged_in=False (e.g. logout), apply update if available."""
    try:
        cfg = load_config()
        if not cfg.get("autoupdate_enabled"):
            return
        last = _load_update_check_result()
        last_ts = int(last.get("checked_at", 0) or 0)
        if defer_if_user_logged_in:
            if time.time() - last_ts < AUTOUPDATE_CHECK_INTERVAL_SEC:
                return
            result = _run_update_check(cfg)
            _save_update_check_result(result)
            if not result.get("update_available"):
                return
            return
        if (time.time() - last_ts < 3600) and last.get("update_available"):
            result = last
        else:
            result = _run_update_check(cfg)
            _save_update_check_result(result)
        if not result.get("update_available"):
            return
        helper = get_update_helper_path()
        if not helper.exists():
            return
        script_dir = str(get_script_path().parent)
        rc, out = _run_cmd([str(helper), script_dir, "update", "no-restart"], timeout_sec=30, env=_update_helper_env(cfg))
        if rc != 0:
            append_ui_log(f"autoupdate | failed: {out.strip() or rc}")
            return
        append_ui_log(f"autoupdate | updated to {result.get('latest_version', '?')}")

        def _delayed_restart() -> None:
            time.sleep(2)
            for u in ("unix-monitor-ui.service", "unix-monitor-scheduler.timer", "unix-monitor-smart-helper.timer", "unix-monitor-backup-helper.timer", "unix-monitor-system-log-helper.timer"):
                _run_cmd(["systemctl", "restart", u], timeout_sec=10)

        threading.Thread(target=_delayed_restart, daemon=True).start()
    except Exception:
        pass


def get_task_guide_images() -> Dict[str, Path]:
    base = get_script_path().parent
    return {
        "task-scheduler-guide.png": base / "task-scheduler-guide.png",
        "task-step-general.png": base / "task-step-general.png",
        "task-step-schedule.png": base / "task-step-schedule.png",
        "task-step-command.png": base / "task-step-command.png",
    }


def get_task_status_path() -> Path:
    return get_runtime_data_dir() / "unix-task-status.json"


def _write_task_status(payload: Dict[str, Any]) -> None:
    path = get_task_status_path()
    tmp = path.parent / ".unix-task-status.json.tmp"
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
    return get_runtime_data_dir() / "unix-monitor-history.json"


def get_monitor_state_path() -> Path:
    return get_runtime_data_dir() / "unix-monitor-state.json"


def get_schedule_state_path() -> Path:
    return get_runtime_data_dir() / "unix-schedule-state.json"


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
    tmp = p.parent / ".unix-monitor-state.json.tmp"
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


def _is_scheduled_due(interval_minutes: int, monitor_name: str = "") -> bool:
    if interval_minutes < 1:
        interval_minutes = 1
    state = _read_schedule_state()
    now = int(time.time())
    if monitor_name:
        per_mon = state.get("per_monitor", {})
        last_run = int(per_mon.get(monitor_name, 0) or 0)
    else:
        last_run = int(state.get("last_run_ts", 0) or 0)
    if now - last_run < interval_minutes * 60:
        return False
    return True


def _touch_scheduled_run(monitor_name: str = "") -> None:
    p = get_schedule_state_path()
    state = _read_schedule_state()
    now = int(time.time())
    state["last_run_ts"] = now
    if monitor_name:
        state.setdefault("per_monitor", {})[monitor_name] = now
    tmp = p.parent / ".unix-schedule-state.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
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
    return Path("/var/lib/unix-monitor/scheduler.pid")


def _scheduler_service_path() -> Path:
    return Path("/usr/local/bin/unix-monitor-service")


def _systemd_show_properties(unit: str, props: List[str]) -> Dict[str, str]:
    if not unit or not props:
        return {}
    cmd = ["systemctl", "show", unit, "--no-pager"]
    for prop in props:
        cmd.extend(["-p", prop])
    rc, out = _run_cmd(cmd, timeout_sec=8)
    if rc != 0:
        return {}
    data: Dict[str, str] = {}
    for ln in (out or "").splitlines():
        if "=" not in ln:
            continue
        k, v = ln.split("=", 1)
        if k and k not in data:
            data[k] = v.strip()
    return data


def _systemd_timer_status(timer_unit: str) -> Dict[str, str]:
    keys = ["LoadState", "ActiveState", "SubState", "NextElapseUSecRealtime", "LastTriggerUSec", "UnitFileState"]
    data = _systemd_show_properties(timer_unit, keys)
    if not data:
        return {
            "load_state": "unknown",
            "active_state": "unknown",
            "sub_state": "unknown",
            "next": "n/a",
            "last": "n/a",
            "unit_file_state": "unknown",
        }
    return {
        "load_state": data.get("LoadState", "unknown"),
        "active_state": data.get("ActiveState", "unknown"),
        "sub_state": data.get("SubState", "unknown"),
        "next": data.get("NextElapseUSecRealtime", "n/a"),
        "last": data.get("LastTriggerUSec", "n/a"),
        "unit_file_state": data.get("UnitFileState", "unknown"),
    }


def _scheduler_status_text(cfg: Dict[str, Any]) -> str:
    interval = int(cfg.get("cron_interval_minutes", 60) or 60)
    cron_enabled = bool(cfg.get("cron_enabled", False))
    backend = str(cfg.get("scheduler_backend", "cron")).strip().lower()
    if backend not in ("systemd", "cron"):
        backend = "cron"
    cfg_path = str(get_config_path())
    runtime_dir = str(get_runtime_data_dir())
    state = _read_schedule_state()
    last_ts = int(state.get("last_run_ts", 0) or 0)
    last_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_ts)) if last_ts else "never"
    due_text = "yes" if _is_scheduled_due(interval) else "no"
    helper_ok, helper_msg = get_smart_helper_status()
    lines: List[str]
    if backend == "systemd":
        t = _systemd_timer_status("unix-monitor-scheduler.timer")
        timer_running = t.get("active_state") == "active"
        lines = [
            f"Scheduler backend: {backend}",
            (
                "Scheduler timer: "
                f"{'active' if timer_running else 'inactive'} "
                f"(state={t.get('active_state')}/{t.get('sub_state')}, unit={t.get('unit_file_state')})"
            ),
            "Scheduler service mode: systemd oneshot (no persistent PID expected)",
            f"Automatic checks enabled (global): {'yes' if cron_enabled else 'no'}",
            f"Configured scheduler interval: {interval} minute(s)",
            f"Timer next trigger: {t.get('next', 'n/a')}",
            f"Timer last trigger: {t.get('last', 'n/a')}",
            f"Last scheduled run (state file): {last_text}",
            f"SMART elevated cache: {'active' if helper_ok else 'inactive'} | {helper_msg}",
            f"Config file: {cfg_path}",
            f"Runtime data dir: {runtime_dir}",
            f"Scheduler service script: {_scheduler_service_path()}",
        ]
    else:
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
        lines = [
            f"Scheduler backend: {backend}",
            f"Scheduler process: {'running' if running else 'not running'} (pid={pid_text})",
            f"Automatic checks enabled (global): {'yes' if cron_enabled else 'no'}",
            f"Configured scheduler interval: {interval} minute(s)",
            f"Last scheduled run: {last_text}",
            f"SMART elevated cache: {'active' if helper_ok else 'inactive'} | {helper_msg}",
            f"Config file: {cfg_path}",
            f"Runtime data dir: {runtime_dir}",
            f"Scheduler service script: {_scheduler_service_path()}",
        ]
    per_mon = state.get("per_monitor", {})
    monitors = cfg.get("monitors", [])
    if monitors:
        lines.append("")
        lines.append("Per-monitor schedule:")
        for m in monitors:
            mn = str(m.get("name", "?"))
            mi = int(m.get("interval", interval) or interval)
            mc = bool(m.get("cron_enabled", cron_enabled))
            mlr = int(per_mon.get(mn, 0) or 0)
            mlr_text = time.strftime("%H:%M:%S", time.localtime(mlr)) if mlr else "never"
            due = "yes" if _is_scheduled_due(mi, mn) else "no"
            lines.append(f"  {mn}: {mi}m | cron={'on' if mc else 'off'} | last={mlr_text} | due={due}")
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
    tmp = p.parent / ".unix-monitor-history.json.tmp"
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
    channels = [mode]
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
    backend = str(cfg.get("scheduler_backend", "cron")).strip().lower()
    if backend not in ("systemd", "cron"):
        backend = "cron"
    sched_state = _read_schedule_state()
    last_sched = int(sched_state.get("last_run_ts", 0) or 0)
    last_sched_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_sched)) if last_sched else "never"

    pid_val = 0
    running = False
    timer_diag = ""
    if backend == "systemd":
        t = _systemd_timer_status("unix-monitor-scheduler.timer")
        running = t.get("active_state") == "active"
        timer_diag = (
            f"- scheduler timer: {'active' if running else 'inactive'} "
            f"(state={t.get('active_state')}/{t.get('sub_state')}, unit={t.get('unit_file_state')})\n"
            "- scheduler service mode: systemd oneshot (no persistent PID expected)\n"
            f"- timer next trigger: {t.get('next', 'n/a')}\n"
            f"- timer last trigger: {t.get('last', 'n/a')}\n"
        )
    else:
        pid_path = _scheduler_pid_path()
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

    cron_text = "(cron backend not selected)"
    if backend == "cron":
        rc, out = _run_cmd(["crontab", "-l"], timeout_sec=8)
        if rc == 0:
            cron_lines = [ln for ln in out.splitlines() if "unix-monitor" in ln]
            cron_text = "\n".join(cron_lines) if cron_lines else "(no unix-monitor crontab entries)"
        else:
            cron_text = f"(crontab unavailable rc={rc})"

    auto_task = _read_task_status()
    auto_task_text = json.dumps(auto_task, indent=2) if auto_task else "No auto-create task attempts recorded."

    helper_log = Path("/var/lib/unix-monitor/smart-helper.log")
    backup_helper_log = Path("/var/lib/unix-monitor/backup-helper.log")
    sched_log = Path("/var/lib/unix-monitor/monitor-scheduler.log")

    backup_cache = _read_backup_cache() or {}
    backup_checked = int(backup_cache.get("checked_at", 0) or 0)
    backup_checked_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(backup_checked)) if backup_checked else "never"
    backup_overall = str(backup_cache.get("overall", "n/a"))

    per_mon = sched_state.get("per_monitor", {})
    monitors = cfg.get("monitors", [])
    per_mon_lines = []
    for m in monitors:
        mn = str(m.get("name", "?"))
        mi = int(m.get("interval", interval) or interval)
        mc = bool(m.get("cron_enabled", cron_enabled))
        mlr = int(per_mon.get(mn, 0) or 0)
        mlr_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mlr)) if mlr else "never"
        per_mon_lines.append(f"  {mn}: interval={mi}m, cron={'on' if mc else 'off'}, last_run={mlr_text}")
    per_mon_text = "\n".join(per_mon_lines) if per_mon_lines else "  (no monitors)"

    scheduler_line = (
        f"- scheduler process: {'running' if running else 'not running'} (pid={pid_val or 'n/a'})\n"
        if backend == "cron"
        else timer_diag
    )

    return (
        "Automation Overview\n"
        f"- scheduler backend: {backend}\n"
        f"- automatic checks enabled (global): {'yes' if cron_enabled else 'no'}\n"
        f"- configured scheduler interval: {interval} minute(s)\n"
        f"{scheduler_line}"
        f"- last scheduled run: {last_sched_text}\n"
        f"\nPer-monitor schedule:\n{per_mon_text}\n"
        f"- SMART helper cache: {'active' if helper_ok else 'inactive'} (last: {helper_checked_text})\n"
        f"- SMART helper message: {helper_msg}\n"
        f"- Backup helper cache: last={backup_checked_text} overall={backup_overall}\n\n"
        "Crontab entries (unix-monitor; cron backend only)\n"
        f"{cron_text}\n\n"
        "Auto-create task status\n"
        f"{auto_task_text}\n\n"
        "Scheduler log (tail)\n"
        f"{_tail_text_file(sched_log)}\n\n"
        "SMART helper log (tail)\n"
        f"{_tail_text_file(helper_log)}\n\n"
        "Backup helper log (tail)\n"
        f"{_tail_text_file(backup_helper_log)}"
    )


def _build_system_diag_text() -> str:
    ui_log = _tail_text_file(get_ui_log_path(), max_lines=200)
    helper_log = _tail_text_file(Path("/var/lib/unix-monitor/smart-helper.log"), max_lines=160)
    backup_helper_log_text = _tail_text_file(Path("/var/lib/unix-monitor/backup-helper.log"), max_lines=100)
    sched_log = _tail_text_file(Path("/var/lib/unix-monitor/monitor-scheduler.log"), max_lines=160)
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
        "Backup helper log (tail)\n"
        f"{backup_helper_log_text or '(no log yet)'}\n\n"
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
        smart_cache = _read_smart_cache()
        backup_cache = _read_backup_cache()
        parts: List[str] = []
        parts.append("=== SMART Helper Cache ===")
        parts.append(json.dumps(smart_cache, indent=2) if smart_cache else "No SMART helper cache yet.")
        parts.append("")
        parts.append("=== Backup Helper Cache ===")
        parts.append(json.dumps(backup_cache, indent=2) if backup_cache else "No Backup helper cache yet.")
        return "\n".join(parts)
    if view == "history":
        return json.dumps(history[-120:], indent=2) if history else "No run history yet."
    if view == "paths":
        details = {
            "config_path": str(get_config_path()),
            "ui_log_path": str(get_ui_log_path()),
            "smart_cache_path": str(get_smart_cache_path()),
            "backup_cache_path": str(get_backup_cache_path()),
            "system_log_cache_path": str(get_system_log_cache_path()),
            "task_status_path": str(get_task_status_path()),
            "helper_script_path": str(get_smart_helper_script_path()),
            "backup_helper_script_path": str(get_backup_helper_script_path()),
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

    channels_order = ("smart", "storage", "ping", "port", "dns", "backup")
    used_channels: List[str] = []
    for m in cfg.get("monitors", []):
        mode = str(m.get("check_mode", "smart")).lower()
        if mode in channels_order and mode not in used_channels:
            used_channels.append(mode)
    for e in history:
        ch = str(e.get("channel", "")).lower()
        if ch in channels_order and ch not in used_channels:
            used_channels.append(ch)
    used_channels = [c for c in channels_order if c in used_channels]
    if not used_channels:
        used_channels = ["smart", "storage"]

    channel_data: Dict[str, Dict[str, Any]] = {}
    for channel in used_channels:
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
        if m.get("_remote_peer"):
            continue
        name = str(m.get("name", "?"))
        mode = str(m.get("check_mode", "smart"))
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
                "origin": "local",
            }
        )

    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
    peers_summary: List[Dict[str, Any]] = []
    peers_cfg_map: Dict[str, Dict[str, Any]] = {}
    for pc in (cfg.get("peers", []) or []):
        pcid = str(pc.get("instance_id", ""))
        if pcid:
            peers_cfg_map[pcid] = pc
    sync_info: Dict[str, Any] = {
        "role": role,
        "last_sync": int(cfg.get("last_peer_sync", 0) or 0),
        "last_sync_result": str(cfg.get("last_peer_sync_result", "") or ""),
        "last_sync_latency_ms": cfg.get("last_peer_sync_latency_ms"),
    }
    if role == "master":
        now = int(time.time())
        token = str(cfg.get("peering_token", "") or "").strip()
        for snap in _load_all_peer_snapshots():
            peer_id = str(snap.get("instance_id", ""))
            peer_name = str(snap.get("instance_name", "") or peer_id[:8])
            received_at = int(snap.get("received_at", 0) or 0)
            pc_info = peers_cfg_map.get(peer_id, {})
            cfg_last_seen = int(pc_info.get("last_seen", 0) or 0)
            best_seen = max(received_at, cfg_last_seen)
            age = now - best_seen if best_seen else 9999
            peer_status = "online" if age < PEER_HEALTH_TIMEOUT_SEC else "offline"
            peer_latency = pc_info.get("latency_ms")
            p_url = str(pc_info.get("url", "") or "").strip().rstrip("/")
            if peer_status == "offline" and p_url and token:
                try:
                    t0 = time.time()
                    hst, _ = _peer_http_request(p_url, token, "GET", "/api/peer/health", timeout=3)
                    if hst < 300:
                        peer_status = "online"
                        peer_latency = round((time.time() - t0) * 1000)
                        best_seen = now
                except Exception:
                    pass
            peers_summary.append({
                "instance_id": peer_id,
                "instance_name": peer_name,
                "status": peer_status,
                "last_seen": best_seen,
                "monitor_count": len(snap.get("monitors", [])),
                "latency_ms": peer_latency,
                "url": p_url,
                "open_url": _peer_url_for_open(p_url),
                "version": str(pc_info.get("version", "") or ""),
            })
            peer_history = snap.get("history", [])
            peer_state = snap.get("state", {})
            for e in peer_history:
                ch = str(e.get("channel", "")).lower()
                if ch in channels_order and ch not in used_channels:
                    used_channels.append(ch)
            for channel in channels_order:
                items = [e for e in peer_history if str(e.get("channel")) == channel]
                if not items:
                    continue
                if channel not in channel_data:
                    used_channels_set = set(used_channels)
                    if channel not in used_channels_set:
                        used_channels.append(channel)
                    latest = items[-1]
                    st = str(latest.get("status", "unknown"))
                    pct = {"up": 100, "warning": 55, "down": 15}.get(st, 0)
                    ts = int(latest.get("ts", 0) or 0)
                    channel_data[channel] = {
                        "status": st, "pct": pct, "ts": ts,
                        "history_statuses": [str(x.get("status", "unknown")) for x in items[-20:]],
                    }
                else:
                    existing = channel_data[channel]
                    latest = items[-1]
                    if int(latest.get("ts", 0) or 0) > existing.get("ts", 0):
                        st = str(latest.get("status", "unknown"))
                        existing["status"] = st
                        existing["pct"] = {"up": 100, "warning": 55, "down": 15}.get(st, 0)
                        existing["ts"] = int(latest.get("ts", 0) or 0)
                    combined_hist = existing.get("history_statuses", []) + [str(x.get("status", "unknown")) for x in items[-10:]]
                    existing["history_statuses"] = combined_hist[-20:]
            peer_monitor_latest: Dict[str, Dict[str, Any]] = {}
            for e in peer_history:
                mn = str(e.get("monitor", ""))
                if mn:
                    peer_monitor_latest[mn] = e
            for pm in snap.get("monitors", []):
                pname = str(pm.get("name", "?"))
                pmode = str(pm.get("check_mode", "smart"))
                platest = peer_monitor_latest.get(pname, {})
                pst = str(platest.get("status", "unknown"))
                pping = platest.get("ping_ms", "n/a")
                pts = int(platest.get("ts", 0) or 0)
                ps = peer_state.get(pname, {})
                monitors.append({
                    "name": pname,
                    "mode": pmode,
                    "status": pst,
                    "ping_ms": pping,
                    "ts": pts,
                    "banner": str(ps.get("banner", "") or ""),
                    "output": str(ps.get("output", "") or ""),
                    "level": "err" if str(ps.get("level", "ok")) == "err" else "ok",
                    "origin": peer_name,
                })

    return {
        "generated_at": int(time.time()),
        "channels": channel_data,
        "monitors": monitors,
        "peers": peers_summary,
        "sync": sync_info,
    }


def _build_live_snapshot_for_source(source_id: str = "local") -> Dict[str, Any]:
    """Build a live snapshot scoped to one source context (local or a peer instance_id)."""
    base = _build_live_snapshot()
    cfg = load_config()
    local_name = str(cfg.get("instance_name", "") or "").strip() or "Local"
    sid = (source_id or "local").strip()
    if sid == "local":
        base["source_id"] = "local"
        base["source_name"] = local_name
        base["source_scope"] = "local"
        return base

    if not _is_valid_peer_instance_id(sid):
        base["source_id"] = "local"
        base["source_name"] = local_name
        base["source_scope"] = "local"
        return base

    snap = _load_peer_snapshot(sid)
    if not snap:
        base["source_id"] = "local"
        base["source_name"] = local_name
        base["source_scope"] = "local"
        return base

    channels_order = ("smart", "storage", "ping", "port", "dns", "backup")
    peer_name = str(snap.get("instance_name", "") or sid[:8])
    peer_history = snap.get("history", [])
    peer_state = snap.get("state", {})
    peer_monitors_cfg = snap.get("monitors", [])

    used_channels: List[str] = []
    for pm in peer_monitors_cfg:
        mode = str(pm.get("check_mode", "smart")).lower()
        if mode in channels_order and mode not in used_channels:
            used_channels.append(mode)
    for e in peer_history:
        ch = str(e.get("channel", "")).lower()
        if ch in channels_order and ch not in used_channels:
            used_channels.append(ch)
    used_channels = [c for c in channels_order if c in used_channels] or ["smart", "storage"]

    channel_data: Dict[str, Dict[str, Any]] = {}
    for channel in used_channels:
        items = [e for e in peer_history if str(e.get("channel")) == channel]
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

    peer_monitor_latest: Dict[str, Dict[str, Any]] = {}
    for e in peer_history:
        mn = str(e.get("monitor", ""))
        if mn:
            peer_monitor_latest[mn] = e

    monitors: List[Dict[str, Any]] = []
    for pm in peer_monitors_cfg:
        pname = str(pm.get("name", "?"))
        pmode = str(pm.get("check_mode", "smart"))
        platest = peer_monitor_latest.get(pname, {})
        pst = str(platest.get("status", "unknown"))
        pping = platest.get("ping_ms", "n/a")
        pts = int(platest.get("ts", 0) or 0)
        ps = peer_state.get(pname, {})
        monitors.append(
            {
                "name": pname,
                "mode": pmode,
                "status": pst,
                "ping_ms": pping,
                "ts": pts,
                "banner": str(ps.get("banner", "") or ""),
                "output": str(ps.get("output", "") or ""),
                "level": "err" if str(ps.get("level", "ok")) == "err" else "ok",
                "origin": peer_name,
            }
        )

    base["channels"] = channel_data
    base["monitors"] = monitors
    base["source_id"] = sid
    base["source_name"] = peer_name
    base["source_scope"] = "remote"
    return base


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
    cron_line = f"*/5 * * * * {helper_script} # unix-monitor smart helper beta"
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
        mode = str(monitor.get("check_mode", "smart")).lower()
        if mode == "both":
            monitor["check_mode"] = "smart"
            changed = True
        elif mode not in CHECK_MODES:
            monitor["check_mode"] = "smart"
            changed = True

    # Normalize legacy duplicate monitor names: keep the newest definition by name.
    seen: set[str] = set()
    dedup_rev: List[Dict[str, Any]] = []
    for m in reversed(monitors):
        name = str(m.get("name", "")).strip()
        if not name:
            name = f"{str(m.get('check_mode', 'smart')).lower()}-unix-check"
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
    tmp_path = path.parent / ".unix-monitor.json.tmp"
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


def _run_cmd(cmd: List[str], timeout_sec: int = 20, env: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
    try:
        kwargs: Dict[str, Any] = dict(capture_output=True, text=True, timeout=timeout_sec, check=False)
        if env is not None:
            kwargs["env"] = {**os.environ, **env}
        p = subprocess.run(cmd, **kwargs)
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
        return False, "synospace not found (run this on a Unix host)"
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

    # Preserve original behavior: detect sequence gaps that often mean missing disks.
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

    # Also collect backup status while running as root
    try:
        bk = _collect_backup_status()
        _write_backup_cache(bk)
        bk_overall = bk.get("overall", "unknown")
        pkg_names = ", ".join(p.get("label", p.get("id", "?")) for p in bk.get("packages", []))
        append_ui_log(f"backup-helper | cache updated | overall={bk_overall} | packages=[{pkg_names}]")
        for bt in bk.get("tasks", []):
            t_name = bt.get("name", "?")
            t_status = bt.get("status", "?")
            t_source = bt.get("source", "?")
            t_parts = [f"task [{t_status.upper()}] {t_name} (via {t_source})"]
            for fk in ("api_status", "last_result", "state", "error", "last_error"):
                fv = bt.get(fk, "")
                if fv and str(fv) not in ("0", "none", ""):
                    t_parts.append(f"{fk}={fv}")
            append_ui_log(f"backup-helper |   {' | '.join(t_parts)}")
        if not bk.get("tasks"):
            append_ui_log("backup-helper |   (no backup tasks detected)")
        print(f"Backup helper cache updated: overall={bk_overall}, tasks={len(bk.get('tasks', []))}, packages={len(bk.get('packages', []))}")
    except Exception as exc:
        append_ui_log(f"backup-helper | error in smart-helper: {type(exc).__name__}: {exc}")
        print(f"Backup helper error: {exc}")

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


# ---------------------------------------------------------------------------
#  Backup monitoring
# ---------------------------------------------------------------------------


def _detect_backup_packages() -> List[Dict[str, Any]]:
    """Detect installed backup packages."""
    pkgs: List[Dict[str, Any]] = []
    known = [
        ("HyperBackup", "Hyper Backup"),
        ("ActiveBackup", "Active Backup for Business"),
        ("ActiveBackupOffice365", "Active Backup for Microsoft 365"),
        ("ActiveBackupGSuite", "Active Backup for Google Workspace"),
        ("SnapshotReplication", "Snapshot Replication"),
        ("USBCopy", "USB Copy"),
        ("CloudSync", "Cloud Sync"),
    ]
    for pkg_id, label in known:
        try:
            pkg_dir = Path(f"/var/packages/{pkg_id}")
            if not pkg_dir.exists():
                continue
        except OSError:
            continue
        version = ""
        try:
            rc, out = _run_cmd(["synopkg", "version", pkg_id], timeout_sec=5)
            if rc == 0 and out.strip():
                version = out.strip()
        except Exception:
            pass
        pkgs.append({"id": pkg_id, "label": label, "version": version})
    return pkgs


def _read_backup_logs(max_lines: int = 600) -> str:
    """Read backup log files."""
    log_paths = [
        Path("/var/log/synolog/synobackup.log"),
        Path("/var/packages/HyperBackup/var/log/synolog/synobackup.log"),
        Path("/var/log/synolog/synobackup.log.1"),
        Path("/var/packages/HyperBackup/target/log/synolog/synobackup.log"),
        Path("/var/log/synolog/backup.log"),
    ]
    all_lines: List[str] = []
    for p in log_paths:
        try:
            if not p.exists():
                continue
            with open(p, encoding="utf-8", errors="ignore") as f:
                all_lines.extend(f.readlines())
        except OSError:
            continue
    # Also try synologtool to get log entries from Synology's log database
    for log_cmd in (
        ["synologtool", "log", "--get", "--type", "backup", "--limit", "50"],
        ["synologtool", "log", "--get", "--limit", "100"],
    ):
        try:
            rc, out = _run_cmd(log_cmd, timeout_sec=10)
            if rc == 0 and out.strip():
                for ln in out.splitlines():
                    if "backup" in ln.lower() or "task" in ln.lower():
                        all_lines.append(ln)
        except Exception:
            pass
    if not all_lines:
        return ""
    tail = "".join(all_lines[-max_lines:]).strip()
    return tail


def _parse_backup_log_tasks(log_text: str) -> Dict[str, Dict[str, Any]]:
    """Parse backup log for task statuses keyed by task name.

    Backup logs use formats like:
      Backup task [My Task Name] finished successfully. [12345]
      Backup task [My Task Name] has started
      Datensicherungsaufgabe [My Task Name] fehlgeschlagen
      Backup integrity check for [My Task Name] has started
    We specifically look for "task [Name]" or "aufgabe [Name]" patterns
    and filter out numeric-only or too-short bracket content.
    """
    tasks: Dict[str, Dict[str, Any]] = {}
    task_name_pattern = re.compile(
        r'(?:backup\s+task|task|aufgabe|integrity\s+check\s+(?:for\s+)?)\s*\[([^\]]{3,})\]',
        re.IGNORECASE,
    )
    bracket_pattern = re.compile(r'\[([^\]]{3,})\]')
    _status_keywords = [
        ("finished successfully", "success"), ("erfolgreich", "success"),
        ("has been completed", "success"), ("completed successfully", "success"),
        ("error_detect", "warning"),  # C2 Backup state - before "error" to avoid false failed
        ("has failed", "failed"), ("failed", "failed"), ("fehlgeschlagen", "failed"),
        ("no response", "failed"), ("error", "failed"),
        ("has started", "running"), ("started", "running"), ("gestartet", "running"),
        ("cancelled", "cancelled"), ("abgebrochen", "cancelled"),
        ("partially completed", "partial"), ("teilweise", "partial"),
        ("suspend", "cancelled"),
    ]
    for line in log_text.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue
        m = task_name_pattern.search(line_stripped)
        if not m:
            lower_check = line_stripped.lower()
            has_result_keyword = any(kw in lower_check for kw, _ in _status_keywords if _ in ("failed", "success", "warning"))
            if has_result_keyword:
                bm = bracket_pattern.search(line_stripped)
                if bm:
                    candidate = bm.group(1).strip()
                    if candidate and not candidate.isdigit() and len(candidate) >= 3:
                        m = bm
            if not m:
                continue
        task_name = m.group(1).strip()
        if not task_name or task_name.isdigit():
            continue
        lower = line_stripped.lower()
        status = "unknown"
        for kw, st in _status_keywords:
            if kw in lower:
                status = st
                break
        ts_match = re.match(r'(\d{4}[/-]\d{2}[/-]\d{2}\s+\d{2}:\d{2}:\d{2})', line_stripped)
        if not ts_match:
            # Try tab-separated format: "info\t2026/02/20\t12:00:00\t..."
            ts_match = re.search(r'(\d{4}[/-]\d{2}[/-]\d{2})\t(\d{2}:\d{2}:\d{2})', line_stripped)
            if ts_match:
                ts_str = f"{ts_match.group(1)} {ts_match.group(2)}"
            else:
                ts_str = ""
        else:
            ts_str = ts_match.group(1)
        ts_epoch = 0
        if ts_str:
            try:
                ts_epoch = int(time.mktime(time.strptime(ts_str.replace("/", "-"), "%Y-%m-%d %H:%M:%S")))
            except Exception:
                pass
        if task_name not in tasks or ts_epoch >= tasks[task_name].get("ts", 0):
            tasks[task_name] = {"status": status, "ts": ts_epoch, "line": line_stripped[:300]}
    return tasks


def _query_hyperbackup_task_detail(task_id: int) -> Tuple[Dict[str, Any], str]:
    """Query detailed status for a single Hyper Backup task.

    Tries multiple API endpoints and versions to get last_bkp_result, last_bkp_time, etc.
    Returns (detail_dict, debug_log).
    """
    debug_parts: List[str] = []
    _apis = [
        ("SYNO.Backup.Task", "status", "1", f"task_id={task_id}"),
        ("SYNO.Backup.Task", "get", "1", f"task_id={task_id}"),
        ("SYNO.Backup.Task", "status", "2", f"task_id={task_id}"),
        ("SYNO.Backup.Task", "get", "2", f"task_id={task_id}"),
        ("SYNO.Backup.Repository", "get", "1", f"repo_id={task_id}"),
    ]
    for api, method, ver, extra in _apis:
        try:
            rc, out = _run_cmd(
                ["synowebapi", "-s", "--exec",
                 f"api={api}", f"method={method}", f"version={ver}", extra],
                timeout_sec=10,
            )
            snippet = out[:300] if out else "(empty)"
            debug_parts.append(f"{api}/{method}/v{ver}: rc={rc} -> {snippet}")
            if rc == 0 and out.strip():
                data = json.loads(out)
                if data.get("success") is False:
                    continue
                d = data.get("data", data)
                if isinstance(d, dict) and d:
                    useful_keys = {"last_bkp_result", "last_bkp_time", "next_bkp_time",
                                   "last_bkp_error", "error", "state", "status", "result"}
                    if any(k in d for k in useful_keys):
                        return d, "\n".join(debug_parts)
        except Exception as exc:
            debug_parts.append(f"{api}/{method}/v{ver}: exception {type(exc).__name__}: {exc}")
    return {}, "\n".join(debug_parts)


def _query_hyperbackup_api() -> Tuple[List[Dict[str, Any]], str]:
    """Query SYNO.Backup.Task API for Hyper Backup tasks (requires root).

    First lists tasks, then queries each one individually for detailed status.
    Returns (task_list_with_detail, raw_response_snippet) for debugging.
    """
    try:
        rc, out = _run_cmd(
            ["synowebapi", "-s", "--exec",
             "api=SYNO.Backup.Task", "method=list", "version=1"],
            timeout_sec=15,
        )
        raw_snippet = f"rc={rc} body={out[:500]}" if out else f"rc={rc} (empty)"
        if rc != 0 or not out.strip():
            return [], raw_snippet
        data = json.loads(out)
        task_list = data.get("data", {}).get("task_list", [])
        if not task_list:
            task_list = data.get("data", {}).get("task", [])
        if not task_list and isinstance(data.get("data"), list):
            task_list = data["data"]

        enriched = []
        detail_logs: List[str] = []
        for t in task_list:
            tid = t.get("task_id", t.get("id", 0))
            if tid:
                detail, detail_debug = _query_hyperbackup_task_detail(int(tid))
                detail_logs.append(f"task_id={tid}: {detail_debug}")
                if detail:
                    merged = dict(t)
                    merged.update(detail)
                    enriched.append(merged)
                    continue
            enriched.append(t)
        if detail_logs:
            raw_snippet += "\n--- detail queries ---\n" + "\n".join(detail_logs)
        return enriched, raw_snippet
    except Exception as exc:
        return [], f"error: {type(exc).__name__}: {exc}"


def _collect_backup_status() -> Dict[str, Any]:
    """Collect comprehensive backup status (best run as root)."""
    packages = _detect_backup_packages()
    log_text = _read_backup_logs()
    log_tasks = _parse_backup_log_tasks(log_text)
    if log_text:
        last_5 = log_text.strip().splitlines()[-5:]
        append_ui_log(f"backup-helper | log tail ({len(log_text.splitlines())} lines): {' // '.join(l.strip()[:100] for l in last_5)}")
    else:
        append_ui_log("backup-helper | no backup log content found")
    api_tasks, api_raw_snippet = _query_hyperbackup_api()
    append_ui_log(f"backup-helper | api returned {len(api_tasks)} tasks")
    for at in api_tasks:
        enriched_keys = [k for k in ("last_bkp_result", "last_bkp_time", "next_bkp_time", "last_bkp_error") if k in at]
        append_ui_log(f"backup-helper | api task '{at.get('name','?')}': state={at.get('state','?')} status={at.get('status','?')} enriched_keys={enriched_keys}")
    api_raw_summary = []
    for at in api_tasks:
        api_raw_summary.append({k: at[k] for k in sorted(at.keys())})

    tasks: List[Dict[str, Any]] = []
    seen_names: set = set()

    _FAIL_WORDS = ("fail", "error", "err", "broken", "crash", "fehlgeschlagen")
    _SUCCESS_WORDS = ("done", "success", "ok", "erfolgreich")
    _CANCEL_WORDS = ("cancel", "suspend", "abgebrochen")

    for at in api_tasks:
        name = str(at.get("name", "") or "").strip()
        if not name:
            continue
        seen_names.add(name)
        api_status = str(at.get("status", "") or "").lower()
        last_result = str(at.get("last_bkp_result", "") or "").lower()
        result_field = str(at.get("result", "") or "").lower()
        state_field = str(at.get("state", "") or "").lower()
        error_field = str(at.get("error", at.get("error_code", "")) or "")
        last_error = str(at.get("last_bkp_error", at.get("last_error", "")) or "").lower()
        last_bkp_time = at.get("last_bkp_time", 0)
        next_bkp_time = at.get("next_bkp_time", 0)
        all_vals = f"{api_status} {last_result} {result_field} {state_field} {last_error}"
        status = "unknown"
        if api_status in ("backingup", "resuming"):
            status = "running"
        elif state_field == "error_detect":
            status = "warning"
        elif any(w in all_vals for w in _FAIL_WORDS):
            status = "failed"
        elif str(error_field) not in ("0", "", "none", "None") and error_field:
            status = "failed"
        elif any(w in all_vals for w in _SUCCESS_WORDS):
            status = "success"
        elif any(w in all_vals for w in _CANCEL_WORDS):
            status = "cancelled"
        elif "partial" in all_vals:
            status = "partial"
        elif api_status in ("idle",):
            status = "success"
        log_info = log_tasks.get(name, {})
        if log_info.get("status") == "failed" and status in ("success", "unknown"):
            status = "failed"
        elif log_info.get("status") == "success" and status == "unknown":
            status = "success"
        if status == "unknown" and state_field == "backupable":
            if last_bkp_time:
                status = "success"
            else:
                status = "warning"
        task_entry: Dict[str, Any] = {
            "name": name,
            "source": "api",
            "status": status,
            "api_status": api_status,
            "last_result": last_result,
            "state": state_field,
            "error": str(error_field),
            "last_error": last_error,
        }
        if last_bkp_time:
            task_entry["last_bkp_time"] = int(last_bkp_time)
        if next_bkp_time:
            task_entry["next_bkp_time"] = int(next_bkp_time)
        tasks.append(task_entry)

    for tname, tinfo in log_tasks.items():
        if tname in seen_names:
            continue
        tasks.append({
            "name": tname,
            "source": "log",
            "status": tinfo["status"],
            "ts": tinfo.get("ts", 0),
        })

    overall = "up"
    if not tasks and not packages:
        overall = "unknown"
    else:
        for t in tasks:
            s = t.get("status", "unknown")
            if s == "failed":
                overall = "down"
                break
            elif s in ("partial", "cancelled", "warning"):
                if overall != "down":
                    overall = "warning"
            elif s == "running":
                if overall == "up":
                    overall = "up"
            elif s == "unknown":
                if overall == "up":
                    overall = "warning"

    log_task_summary = []
    for tname, tinfo in log_tasks.items():
        log_task_summary.append({"name": tname, "status": tinfo.get("status", "?"), "line": tinfo.get("line", "")[:200]})

    return {
        "checked_at": int(time.time()),
        "overall": overall,
        "packages": packages,
        "tasks": tasks,
        "_debug_api_raw": api_raw_summary,
        "_debug_api_response": api_raw_snippet[:2000],
        "_debug_log_tasks": log_task_summary,
        "_debug_log_lines": len(log_text.splitlines()) if log_text else 0,
    }


def run_backup_helper() -> int:
    """Root helper to collect backup status and write cache."""
    if os.geteuid() != 0:
        print("ERROR: --run-backup-helper requires root")
        append_ui_log("backup-helper | failed | requires root")
        return 1
    payload = _collect_backup_status()
    _write_backup_cache(payload)
    overall = payload.get("overall", "unknown")
    pkg_names = ", ".join(p.get("label", p.get("id", "?")) for p in payload.get("packages", []))
    append_ui_log(f"backup-helper | cache updated | overall={overall} | packages=[{pkg_names}]")
    for bt in payload.get("tasks", []):
        t_name = bt.get("name", "?")
        t_status = bt.get("status", "?")
        t_source = bt.get("source", "?")
        t_parts = [f"task [{t_status.upper()}] {t_name} (via {t_source})"]
        for fk in ("api_status", "last_result", "state", "error", "last_error"):
            fv = bt.get(fk, "")
            if fv and fv not in ("0", "none", ""):
                t_parts.append(f"{fk}={fv}")
        append_ui_log(f"backup-helper |   {' | '.join(t_parts)}")
    if not payload.get("tasks"):
        append_ui_log("backup-helper |   (no backup tasks detected)")
    print(f"Backup helper cache updated: overall={overall}, tasks={len(payload.get('tasks', []))}")
    return 0


def _probe_backup(source_platform: str = "unix") -> Tuple[str, List[str], float]:
    """Check backup status, reading from root helper cache or direct probing."""
    t0 = time.time()
    lines: List[str] = []

    cache = _read_backup_cache()
    if cache:
        checked_at = int(cache.get("checked_at", 0) or 0)
        age = max(0, int(time.time()) - checked_at)
        checked_ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(checked_at)) if checked_at else "never"
        if age > BACKUP_CACHE_MAX_AGE_SEC:
            lines.append(f"STALE CACHE ({age}s)")

        packages = cache.get("packages", [])
        pkg_names = ", ".join(p.get("label", p.get("id", "?")) for p in packages) if packages else "none"
        lines.append(f"Scan: {checked_ts} | Packages: {pkg_names}")

        tasks = cache.get("tasks", [])
        if tasks:
            for t in tasks:
                name = t.get("name", "?")
                st = t.get("status", "unknown")
                icon = {"success": "OK", "failed": "FAIL", "running": "RUN", "partial": "PARTIAL", "cancelled": "CANCEL", "warning": "WARN"}.get(st, "?")
                detail_parts = []
                state_val = t.get("state", "")
                if state_val and state_val not in ("none", ""):
                    detail_parts.append(f"state={state_val}")
                lr = t.get("last_result", "")
                if lr and lr not in ("none", ""):
                    detail_parts.append(f"result={lr}")
                le = t.get("last_error", "")
                if le and le not in ("none", "", "0"):
                    detail_parts.append(f"error={le}")
                lbt = t.get("last_bkp_time", 0)
                if lbt:
                    detail_parts.append(f"last={time.strftime('%m/%d %H:%M', time.localtime(int(lbt)))}")
                nbt = t.get("next_bkp_time", 0)
                if nbt:
                    detail_parts.append(f"next={time.strftime('%m/%d %H:%M', time.localtime(int(nbt)))}")
                detail = f" ({', '.join(detail_parts)})" if detail_parts else ""
                lines.append(f"[{icon}] {name}{detail}")
        else:
            lines.append("No backup tasks found")

        overall = str(cache.get("overall", "unknown"))
        status = {"up": "up", "down": "down", "warning": "warning"}.get(overall, "warning")
        latency = round((time.time() - t0) * 1000, 1)
        return status, lines, latency

    # No cache: try direct detection (limited without root)
    lines.append("WARNING: no root helper cache, direct probe (limited)")
    try:
        packages = _detect_backup_packages()
        if packages:
            pkg_names = ", ".join(p.get("label", p.get("id", "?")) for p in packages)
            lines.append(f"Packages ({len(packages)}): {pkg_names}")
        else:
            lines.append("Packages: none detected")

        log_text = _read_backup_logs()
        if log_text:
            log_tasks = _parse_backup_log_tasks(log_text)
            if log_tasks:
                failed = False
                warning = False
                lines.append(f"Tasks ({len(log_tasks)}, from logs only):")
                for tname, tinfo in log_tasks.items():
                    s = tinfo.get("status", "unknown")
                    icon = {"success": "OK", "failed": "FAIL", "running": "RUN", "partial": "PARTIAL", "cancelled": "CANCEL"}.get(s, "?")
                    log_line = tinfo.get("line", "")[:120]
                    lines.append(f"  [{icon}] {tname} | {log_line}")
                    if s == "failed":
                        failed = True
                    elif s in ("partial", "cancelled", "warning", "unknown"):
                        warning = True
                status = "down" if failed else ("warning" if warning else "up")
            else:
                lines.append("No backup task entries found in logs")
                status = "warning"
        else:
            lines.append("Backup logs not accessible (root helper needed)")
            if _normalize_source_platform(source_platform) == "synology":
                lines.append("Run the elevated helper task in DSM Task Scheduler to enable full backup monitoring")
            else:
                lines.append("Run the elevated backup helper as root (--run-backup-helper) to enable full backup monitoring")
            status = "warning" if packages else "up"
    except Exception as exc:
        lines.append(f"Direct probe failed: {type(exc).__name__}: {exc}")
        lines.append("Root helper needed for full backup monitoring")
        status = "warning"

    latency = round((time.time() - t0) * 1000, 1)
    return status, lines, latency


def check_storage(debug: bool = False) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    ok_tools, err = _has_synology_tools()
    if not ok_tools:
        append_ui_log(f"storage-check | synospace unavailable | reason={err}")
        fb_status, fb_lines = _check_storage_fallback(debug=debug)
        fb_lines.insert(0, f"Unix storage command unavailable: {err}")
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


def get_mounts() -> List[Tuple[str, str, str]]:
    result: List[Tuple[str, str, str]] = []
    try:
        with open("/proc/mounts", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
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
        os.statvfs(mount_point)
        return True, None, _latency_ms(t0)
    except PermissionError:
        return False, "Permission denied (statvfs)", _latency_ms(t0)
    except OSError as e:
        return False, str(e), _latency_ms(t0)


def check_mounts_status(
    mounts: List[Tuple[str, str, str]],
    debug: bool = False,
) -> Tuple[str, List[str], float]:
    ok_list: List[str] = []
    fail_list: List[Tuple[str, str]] = []
    max_latency_ms = 0.0

    for _dev, mpoint, fstype in mounts:
        ok, err, lat_ms = check_mount_accessible(mpoint)
        max_latency_ms = max(max_latency_ms, lat_ms)
        if debug:
            res = "OK" if ok else f"FAIL: {err or 'unreachable'}"
            print(f"    [mount] {mpoint} ({fstype}) -> {res} ({lat_ms:.2f}ms)")
        if ok:
            ok_list.append(f"{mpoint} ({fstype})")
        else:
            fail_list.append((mpoint, err or "unreachable"))

    if not fail_list:
        status = "up"
        lines = [f"All {len(ok_list)} mount(s) healthy", *ok_list]
    elif not ok_list:
        status = "down"
        lines = [f"All {len(fail_list)} mount(s) down", *[f"{m}: {e}" for m, e in fail_list]]
    else:
        status = "warning"
        lines = [f"{len(ok_list)} OK, {len(fail_list)} down", *[f"{m}: {e}" for m, e in fail_list]]
    return status, lines, max_latency_ms


def check_host(mode: str, devices: List[str], debug: bool = False) -> Tuple[str, str, float]:
    return check_host_with_monitor(mode, devices, monitor={}, debug=debug)


def _probe_ping(host: str) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    target = (host or "").strip()
    if not target:
        return "down", ["Ping target host is missing."], _latency_ms(t0)
    for ping_bin in ("/bin/ping", "/usr/bin/ping", "ping"):
        rc, out = _run_cmd([ping_bin, "-c", "1", "-W", "2", target], timeout_sec=5)
        if rc == 0:
            return "up", [f"Ping target {target} is reachable."], _latency_ms(t0)
        if "Operation not permitted" not in out and "not found" not in out:
            detail = out.strip().splitlines()[-1] if out.strip() else "no output"
            return "down", [f"Ping target {target} is unreachable: {detail}"], _latency_ms(t0)
    try:
        with socket.create_connection((target, 80), timeout=3):
            return "up", [f"Ping target {target} is reachable (TCP fallback port 80)."], _latency_ms(t0)
    except OSError:
        pass
    try:
        with socket.create_connection((target, 443), timeout=3):
            return "up", [f"Ping target {target} is reachable (TCP fallback port 443)."], _latency_ms(t0)
    except OSError:
        pass
    return "down", [f"Ping target {target} is unreachable (ICMP not permitted, TCP 80/443 failed)."], _latency_ms(t0)


def _probe_port(host: str, port: int) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    target = (host or "").strip()
    if not target:
        return "down", ["Port probe host is missing."], _latency_ms(t0)
    if port < 1 or port > 65535:
        return "down", [f"Port probe has invalid port: {port}"], _latency_ms(t0)
    try:
        with socket.create_connection((target, int(port)), timeout=3):
            return "up", [f"Port {port} on {target} is open."], _latency_ms(t0)
    except OSError as e:
        return "down", [f"Port {port} on {target} is closed/unreachable: {type(e).__name__}: {e}"], _latency_ms(t0)


def _probe_dns(name: str, dns_server: str = "") -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    target = (name or "").strip()
    server = (dns_server or "").strip()
    if not target:
        return "down", ["DNS monitor domain/hostname is missing."], _latency_ms(t0)
    if server:
        rc, out = _run_cmd(["nslookup", target, server], timeout_sec=6)
        if rc == 0:
            return "up", [f"DNS lookup resolved {target} via {server}."], _latency_ms(t0)
        detail = out.strip().splitlines()[-1] if out.strip() else "no output"
        return "down", [f"DNS lookup failed for {target} via {server}: {detail}"], _latency_ms(t0)
    try:
        answers = socket.getaddrinfo(target, None)
        ips = sorted({str(x[4][0]) for x in answers if x and len(x) > 4 and x[4]})
        if ips:
            return "up", [f"DNS lookup resolved {target}: {', '.join(ips[:4])}"], _latency_ms(t0)
        return "down", [f"DNS lookup returned no addresses for {target}"], _latency_ms(t0)
    except OSError as e:
        return "down", [f"DNS lookup failed for {target}: {type(e).__name__}: {e}"], _latency_ms(t0)


def check_host_with_monitor(mode: str, devices: List[str], monitor: Dict[str, Any], debug: bool = False) -> Tuple[str, str, float]:
    worst = "up"
    max_latency = 0.0
    sections: List[str] = []
    source_platform = _monitor_source_platform(monitor)

    if mode == "mount":
        mounts_data = monitor.get("mounts", [])
        mounts = [
            (x.get("device", "?"), x.get("mount_point", ""), x.get("fstype", "?"))
            for x in mounts_data if x.get("mount_point")
        ]
        if not mounts:
            mounts = get_mounts()
        m_status, m_lines, m_lat = check_mounts_status(mounts, debug=debug)
        max_latency = max(max_latency, m_lat)
        if _severity(m_status) > _severity(worst):
            worst = m_status
        sections.append("Mounts:\n" + "\n".join(f"  - {x}" for x in m_lines))

    if mode == "smart":
        s_status, s_lines, s_lat = check_smart(devices, debug=debug)
        max_latency = max(max_latency, s_lat)
        if _severity(s_status) > _severity(worst):
            worst = s_status
        sections.append("SMART:\n" + "\n".join(f"  - {x}" for x in s_lines))

    if mode == "storage":
        st_status, st_lines, st_lat = check_storage(debug=debug)
        max_latency = max(max_latency, st_lat)
        if _severity(st_status) > _severity(worst):
            worst = st_status
        sections.append("Storage:\n" + "\n".join(f"  - {x}" for x in st_lines))

    if mode == "ping":
        p_status, p_lines, p_lat = _probe_ping(str(monitor.get("probe_host", "")))
        max_latency = max(max_latency, p_lat)
        if _severity(p_status) > _severity(worst):
            worst = p_status
        sections.append("Ping:\n" + "\n".join(f"  - {x}" for x in p_lines))

    if mode == "port":
        host = str(monitor.get("probe_host", ""))
        try:
            port = int(monitor.get("probe_port", 0) or 0)
        except (TypeError, ValueError):
            port = 0
        p_status, p_lines, p_lat = _probe_port(host, port)
        max_latency = max(max_latency, p_lat)
        if _severity(p_status) > _severity(worst):
            worst = p_status
        sections.append("Port:\n" + "\n".join(f"  - {x}" for x in p_lines))

    if mode == "dns":
        target = str(monitor.get("dns_name", ""))
        server = str(monitor.get("dns_server", ""))
        d_status, d_lines, d_lat = _probe_dns(target, server)
        max_latency = max(max_latency, d_lat)
        if _severity(d_status) > _severity(worst):
            worst = d_status
        sections.append("DNS:\n" + "\n".join(f"  - {x}" for x in d_lines))

    if mode == "backup":
        b_status, b_lines, b_lat = _probe_backup(source_platform=source_platform)
        max_latency = max(max_latency, b_lat)
        if _severity(b_status) > _severity(worst):
            worst = b_status
        sections.append("Backup:\n" + "\n".join(f"  - {x}" for x in b_lines))

    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    check_title = _check_title_for_platform(source_platform)
    msg = f"{check_title} ({mode}) = {worst} @ {now}\n" + "\n".join(sections)
    return worst, msg, max_latency


def push_to_kuma(url: str, status: str, message: str, ping_ms: float, debug: bool = False) -> bool:
    """Push heartbeat to Uptime Kuma. Kuma only accepts status 'up' or 'down' (anything else becomes down).
    We map 'warning' -> 'up' so degraded-but-not-down shows green; the message conveys the warning."""
    kuma_status = "up" if status == "warning" else status
    base = normalize_kuma_url(url)
    full = f"{base}?status={kuma_status}&msg={quote(message)}&ping={ping_ms}"
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
    mode = prompt_with_back("Check mode: mount / smart / storage / ping / port / dns / backup", "mount")
    if mode is None:
        return
    mode = (mode or "mount").lower()
    if mode not in CHECK_MODES:
        print("Invalid mode.")
        return

    devices: List[str] = []
    monitor_mounts: List[Dict[str, str]] = []
    if mode == "mount":
        mounts = get_mounts()
        if not mounts:
            print("No mounts found.")
            return
        print("\nDetected mounts:")
        for i, (_dev, mpoint, fstype) in enumerate(mounts, 1):
            print(f"  [{i}] {mpoint} ({fstype})")
        idxs = prompt_multi_indices(len(mounts), "Select mount(s)")
        if idxs is None:
            return
        monitor_mounts = [
            {"device": mounts[i - 1][0], "mount_point": mounts[i - 1][1], "fstype": mounts[i - 1][2]}
            for i in idxs
        ]
    if mode == "smart":
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
    probe_host = ""
    probe_port = 0
    dns_name = ""
    dns_server = ""
    if mode == "ping":
        probe_host = (prompt_with_back("Ping target host/IP", "") or "").strip()
        if not probe_host:
            print("Ping target is required.")
            return
    if mode == "port":
        probe_host = (prompt_with_back("Port probe host/IP", "") or "").strip()
        probe_port_raw = (prompt_with_back("Port probe TCP port", "443") or "443").strip()
        try:
            probe_port = int(probe_port_raw)
        except ValueError:
            probe_port = 0
        if not probe_host or probe_port < 1 or probe_port > 65535:
            print("Valid host and port are required.")
            return
    if mode == "dns":
        dns_name = (prompt_with_back("DNS hostname/domain", "") or "").strip()
        dns_server = (prompt_with_back("DNS server (optional, empty=system resolver)", "") or "").strip()
        if not dns_name:
            print("DNS hostname/domain is required.")
            return

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

    name = prompt_with_back("Monitor name", f"{mode}-unix-check")
    if name is None:
        return
    print(
        f"\nName: {name}\nMode: {mode}\nDevices: {', '.join(devices) if devices else '(auto)'}"
        f"\nMounts: {', '.join(m['mount_point'] for m in monitor_mounts) if monitor_mounts else '(none)'}\nURL: {kuma_url}"
    )
    if not confirm_save("Add monitor"):
        print("Discarded.")
        return

    cfg = load_config()
    cfg.setdefault("monitors", []).append(
        {
            "name": name,
            "check_mode": mode,
            "devices": devices,
            "mounts": monitor_mounts,
            "kuma_url": kuma_url,
            "probe_host": probe_host,
            "probe_port": probe_port,
            "dns_name": dns_name,
            "dns_server": dns_server,
        }
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
        mode = str(m.get("check_mode", "smart")).lower()
        if mode not in CHECK_MODES:
            mode = "smart"
        devices = [str(x) for x in m.get("devices", [])]
        url = m.get("kuma_url", "")
        if not url:
            print(f"  x {name}: no Kuma URL")
            continue
        status, msg, lat = check_host_with_monitor(mode, devices, monitor=m, debug=dbg)
        ok = push_to_kuma(url, status, msg, lat, debug=dbg)
        recorded_status = status if ok else "warning"
        _record_history(str(name), mode, recorded_status, lat)
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
        print(f"      Mode: {m.get('check_mode', 'smart')}")
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
        print(f"  [{i}] {m.get('name', '?')} ({m.get('check_mode', 'smart')})")
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
    msg = f"Test push @ {now} - {BRAND_NAME} unix-monitor connectivity check"
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


def toggle_update_from_main() -> None:
    """Toggle update_from_main: when ON, updates fetch from main branch instead of latest release."""
    cfg = load_config()
    cfg["update_from_main"] = not cfg.get("update_from_main", False)
    save_config(cfg, reapply_cron=False)
    on_off = "ON" if cfg["update_from_main"] else "OFF"
    print(f"\n  Update from main (testing): {on_off}")
    print("  Future updates will use " + ("main branch" if cfg["update_from_main"] else "latest release") + ".")


def _render_peering_card(cfg: Dict[str, Any], peering_message: str = "") -> str:
    instance_id = _get_instance_id(cfg)
    instance_name = str(cfg.get("instance_name", "") or "")
    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
    peering_token = str(cfg.get("peering_token", "") or "")
    _master_host, _master_port = _parse_peer_host_port(
        cfg.get("peer_master_url", ""), int(cfg.get("peer_port", PEER_DEFAULT_PORT) or PEER_DEFAULT_PORT)
    )
    _cb_host, _cb_port = _parse_peer_host_port(
        cfg.get("agent_callback_url", ""), int(cfg.get("peer_port", PEER_DEFAULT_PORT) or PEER_DEFAULT_PORT)
    )
    master_host = _master_host
    agent_callback_host = _cb_host
    peer_port = int(cfg.get("peer_port", PEER_DEFAULT_PORT) or PEER_DEFAULT_PORT)
    peers = cfg.get("peers", [])
    if not isinstance(peers, list):
        peers = []

    last_sync = int(cfg.get("last_peer_sync", 0) or 0)
    last_sync_result = str(cfg.get("last_peer_sync_result", "") or "")
    last_sync_latency = cfg.get("last_peer_sync_latency_ms")
    last_sync_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_sync)) if last_sync else "never"

    token_display = peering_token or "not set"

    # mTLS security status
    sec = _get_mtls_security_status(cfg)

    role_opts = ""
    for r in PEER_ROLES:
        sel = "selected" if r == role else ""
        role_opts += f"<option value='{r}' {sel}>{r.capitalize()}</option>"

    live_panel_html = ""
    master_peer_actions_html = ""
    now = int(time.time())
    valid_peers = [p for p in peers if _is_valid_peer_instance_id(str(p.get("instance_id", "") or ""))] if peers else []
    online = 0
    for _vp in valid_peers:
        _vp_age = now - int(_vp.get("last_seen", 0) or 0) if int(_vp.get("last_seen", 0) or 0) else 9999
        if _vp_age < PEER_HEALTH_TIMEOUT_SEC:
            online += 1
    offline = len(valid_peers) - online
    peer_monitor_count = sum(int(p.get("monitor_count", 0) or 0) for p in peers) if peers else 0
    last_sync_ts = int(cfg.get("last_peer_sync", 0) or 0)
    last_sync_txt = time.strftime("%H:%M:%S", time.localtime(last_sync_ts)) if last_sync_ts else "never"
    peer_rows = ""
    if peers:
        for p in peers:
            pid = str(p.get("instance_id", "") or "").strip()
            if not _is_valid_peer_instance_id(pid):
                continue
            pname = str(p.get("instance_name", "") or pid[:8])
            last_seen = int(p.get("last_seen", 0) or 0)
            age = now - last_seen if last_seen else 9999
            pstatus = "online" if age < PEER_HEALTH_TIMEOUT_SEC else "offline"
            mc = int(p.get("monitor_count", 0) or 0)
            p_url = str(p.get("url", "") or "")
            p_latency = p.get("latency_ms")
            if pstatus == "offline" and p_url and peering_token:
                try:
                    p_url_resolved = _resolve_peer_url_from_stored(p_url, peering_token, timeout=3)
                    if p_url_resolved:
                        t0 = time.time()
                        hst, _ = _peer_http_request(p_url_resolved, peering_token, "GET", "/api/peer/health", timeout=3)
                        if hst < 300:
                            pstatus = "online"
                            p_latency = round((time.time() - t0) * 1000)
                            last_seen = now
                except Exception:
                    pass
            p_open_url = _peer_url_for_open(p_url)
            pclass = "ok" if pstatus == "online" else "err"
            seen_short = time.strftime("%H:%M:%S", time.localtime(last_seen)) if last_seen else "never"
            lat_txt = f"{p_latency} ms" if p_latency else "-"
            p_version = str(p.get("version", "") or "")
            pbtn = "padding:6px 12px;font-size:12px;border-radius:8px;font-weight:600;white-space:nowrap;cursor:pointer;line-height:1.2;border:1px solid #36517a;background:transparent;color:#c8dbf8;"
            open_btn = (
                f"<a href='{html.escape(p_open_url)}' target='_blank' rel='noopener noreferrer' "
                f"style='{pbtn}text-decoration:none;display:inline-block;text-align:center;'>"
                f"Open</a>"
            ) if p_open_url else ""
            version_badge = f"<span class='badge muted-badge' data-role='peer-version'>v{html.escape(p_version)}</span>" if p_version else ""
            synced_badge = f"<span class='badge muted-badge' data-role='peer-synced'>Synced: {html.escape(seen_short)}</span>"
            peer_rows += (
                f"<div class='peer-row' data-peer-id='{html.escape(pid)}' data-peer-url='{html.escape(p_url)}' "
                f"style='border:1px solid rgba(42,61,90,.35);border-radius:8px;background:rgba(15,23,38,.6);padding:10px 12px;margin-bottom:8px;'>"
                f"<div style='display:flex;align-items:center;gap:10px;flex-wrap:wrap;'>"
                f"<span class='badge {pclass}' style='min-width:56px;text-align:center;'>{pstatus}</span>"
                f"<strong style='flex:1;font-size:13px;'>{html.escape(pname)}</strong>"
                f"{synced_badge}"
                f"<span class='badge muted-badge' data-role='peer-monitors'>{mc} monitors</span>"
                f"{version_badge}"
                f"</div>"
                f"<div style='display:flex;align-items:center;gap:8px;margin-top:6px;'>"
                f"<span class='muted' style='font-size:11px;'>Last seen: {html.escape(seen_short)} ({lat_txt})</span>"
                f"<span class='muted' style='font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>{html.escape(p_url or 'no URL')}</span>"
                f"</div>"
                f"<div style='display:flex;align-items:center;gap:6px;margin-top:8px;'>"
                f"<form method='post' action='/peer/update-peer-url' style='margin:0;display:flex;gap:4px;flex:1;'>"
                f"<input type='hidden' name='peer_id' value='{html.escape(pid)}'>"
                f"<input name='peer_url' value='{html.escape(_peer_url_for_input_display(p_url))}' placeholder='agent-nas or 192.168.31.10' style='flex:1;padding:4px 6px;font-size:11px;'>"
                f"<button type='submit' style='{pbtn}'>Set URL</button>"
                f"</form>"
                f"<form method='post' action='/peer/sync-one' style='margin:0;'>"
                f"<input type='hidden' name='peer_id' value='{html.escape(pid)}'>"
                f"<button type='submit' style='{pbtn}'>Sync</button>"
                f"</form>"
                f"<button type='button' class='agent-update-btn' data-peer-id='{html.escape(pid)}' data-peer-name='{html.escape(pname)}' style='{pbtn}'>Update</button>"
                f"{open_btn}"
                f"<form method='post' action='/peer/remove' style='margin:0;'>"
                f"<input type='hidden' name='peer_id' value='{html.escape(pid)}'>"
                f"<button type='submit' onclick=\"return confirm('Remove this agent?')\" "
                f"style='{pbtn}border-color:#ef4444;color:#ef4444;'>Remove</button>"
                f"</form>"
                f"</div>"
                f"</div>"
            )
    no_agents_hint = ""
    if not peers and role == "master":
        no_agents_hint = "<div class='muted' style='font-size:12px;text-align:center;padding:12px 0;'>No agents registered yet. Click <b>Add agent</b> to register one, or agents will appear here automatically once they push data.</div>"
    if role == "master":
        master_peer_actions_html = (
            f"<div style='display:flex;gap:8px;margin-top:10px;align-items:center;justify-content:flex-start;flex-wrap:wrap;'>"
            f"<form method='post' action='/peer/sync-now' style='margin:0;'>"
            f"<button type='submit'>Sync all agents</button>"
            f"</form>"
            f"<button type=\"button\" onclick=\"window._openAddAgent && window._openAddAgent(this)\">Add agent</button>"
            f"</div>"
        )
        live_panel_html = (
            f"<div style='margin-top:16px;border:1px solid var(--border);border-radius:10px;background:var(--card-soft);padding:12px;'>"
            f"<div id='peer-header' style='display:flex;align-items:center;gap:10px;margin-bottom:8px;'>"
            f"<strong style='font-size:14px;'>Connected Agents</strong>"
            f"<span id='peer-online-badge' class='badge ok'>{online} online</span>"
            f"<span id='peer-offline-badge' class='badge err' style='{'display:none' if not offline else ''}'>{offline} offline</span>"
            f"<span id='peer-remote-count' class='muted' style='margin-left:auto;'>Remote monitors: {peer_monitor_count}</span>"
            f"</div>"
            f"<div id='peer-live-panel'>"
            + peer_rows + no_agents_hint
            + f"</div>"
            f"</div>"
        )

    agent_fields = ""
    if role == "agent":
        agent_fields = f"""
          <div style="margin-top:16px;padding:10px 12px;border:1px solid rgba(47,128,237,.4);border-radius:8px;background:rgba(47,128,237,.08);font-size:12px;">
            <strong>Agent setup (3 steps):</strong>
            <ol style="margin:6px 0 0 0;padding-left:18px;">
              <li>On the <b>master</b>, copy the peering token shown there.</li>
              <li>Paste it below &mdash; it must match the master <i>exactly</i>.</li>
              <li>Enter master host, your callback host, port (if not 8787), then Save.</li>
            </ol>
          </div>
          <label>Master's peering token <span class="muted">(copy from master's Peering card)</span></label>
          <input name="peering_token" value="{html.escape(peering_token)}" placeholder="Paste the master's token here" style="margin-top:6px;">
          <label>Master host <span class="muted">(hostname or IP, no http/https/port)</span></label>
          <input name="peer_master_url" value="{html.escape(master_host)}" placeholder="master-nas or 192.168.31.32">
          <label>Agent callback host <span class="muted">(this NAS hostname or IP for master to reach you)</span></label>
          <input name="agent_callback_url" value="{html.escape(agent_callback_host)}" placeholder="this-nas or 192.168.31.1">
          <label>Port <span class="muted">(if not 8787)</span></label>
          <input name="peer_port" type="number" value="{peer_port}" placeholder="8787" min="1" max="65535" style="max-width:120px;">
          <div class="button-row" style="margin-top:10px;">
            <button type="submit">Save peering settings</button>
          </div>
        </form>
        <div class="button-row" style="gap:8px;">
          <form method="post" action="/peer/test-connection" style="margin:0;">
            <input type="hidden" name="peer_url" value="{html.escape(f'{master_host}:{peer_port}' if master_host else '')}">
            <input type="hidden" name="peer_token" value="{html.escape(peering_token)}">
            <button type="submit">Test connection to master</button>
          </form>
          <form method="post" action="/peer/sync-now" style="margin:0;">
            <button type="submit">Sync now</button>
          </form>
        </div>
        """
    elif role == "master":
        agent_fields = f"""
          <div class="button-row" style="margin-top:10px;">
            <button type="submit">Save peering settings</button>
          </div>
        </form>
        """
    else:
        agent_fields = """
          <div class="button-row" style="margin-top:10px;">
            <button type="submit">Save peering settings</button>
          </div>
        </form>
        """

    # Build security status panel
    _sec_style = "border:1px solid rgba(42,61,90,.35);border-radius:8px;background:rgba(15,23,38,.6);padding:10px 12px;margin-top:12px;"
    _sec_badge_style = "display:inline-block;padding:3px 8px;border-radius:6px;font-size:11px;font-weight:600;"
    if sec["mtls_active"]:
        _sec_level = f"<span style='{_sec_badge_style}background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.3);'>mTLS Active</span>"
    elif sec["ca_exists"]:
        _sec_level = f"<span style='{_sec_badge_style}background:rgba(245,158,11,.15);color:#f59e0b;border:1px solid rgba(245,158,11,.3);'>TLS Only (instance cert missing)</span>"
    elif peering_token and role != "standalone":
        _sec_level = f"<span style='{_sec_badge_style}background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3);'>Encrypted Payload (no TLS)</span>"
    else:
        _sec_level = ""

    _sec_rows = ""
    _signing_badge = ""
    if sec["signing_active"]:
        _signing_badge = f"<span style='{_sec_badge_style}background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.3);'>Request Signing Active</span>"
    elif role != "standalone" and sec["openssl_available"] and sec["instance_cert_ok"]:
        _signing_badge = f"<span style='{_sec_badge_style}background:rgba(245,158,11,.15);color:#f59e0b;border:1px solid rgba(245,158,11,.3);'>Signing Ready</span>"
    if role != "standalone":
        _sec_rows += f"<div style='display:flex;align-items:center;gap:8px;flex-wrap:wrap;'>"
        _sec_rows += f"<span class='muted' style='font-size:12px;'>Security:</span> {_sec_level} {_signing_badge}"
        _sec_rows += f"<span class='muted' style='font-size:11px;'>OpenSSL: {'available' if sec['openssl_available'] else 'not found'}</span>"
        _sec_rows += f"</div>"
        _sec_rows += f"<div class='muted' style='font-size:11px;margin-top:4px;'>Request signing provides identity verification through any reverse proxy.</div>"
        if sec["ca_exists"]:
            fp = sec["ca_fingerprint"]
            _sec_rows += f"<div class='muted' style='font-size:11px;margin-top:6px;'>CA Fingerprint: <code style='font-size:10px;word-break:break-all;'>{html.escape(fp[:48])}...</code></div>"
        if role == "agent" and sec.get("has_master_cert"):
            _sec_rows += f"<div class='muted' style='font-size:11px;margin-top:4px;color:#10b981;'>Master certificate: stored (response verification enabled)</div>"
        elif role == "agent" and not sec.get("has_master_cert") and sec["instance_cert_ok"]:
            _sec_rows += f"<div class='muted' style='font-size:11px;margin-top:4px;color:#f59e0b;'>Master certificate: not yet received (re-request cert to obtain it)</div>"

    # Master: CA management + signed agents
    _sec_actions_master = ""
    if role == "master":
        if not sec["ca_exists"]:
            _sec_actions_master = (
                "<div style='margin-top:8px;'>"
                "<form method='post' action='/peer/generate-ca' style='margin:0;'>"
                "<button type='submit'>Generate CA certificate</button>"
                "</form>"
                "<div class='muted' style='font-size:11px;margin-top:4px;'>Creates a private CA to sign agent certificates for mTLS.</div>"
                "</div>"
            )
        else:
            if not sec["instance_cert_ok"]:
                _sec_actions_master += (
                    "<div style='margin-top:8px;'>"
                    "<form method='post' action='/peer/generate-server-cert' style='margin:0;'>"
                    "<button type='submit'>Generate server certificate</button>"
                    "</form>"
                    "<div class='muted' style='font-size:11px;margin-top:4px;'>Required for TLS. Restart the addon after generating.</div>"
                    "</div>"
                )
            signed = sec["signed_agents"]
            if signed:
                _agent_certs = "".join(
                    f"<div style='display:flex;align-items:center;gap:6px;margin-top:4px;'>"
                    f"<span class='muted' style='font-size:11px;flex:1;'>{html.escape(a)}</span>"
                    f"<form method='post' action='/peer/revoke-agent-cert' style='margin:0;'>"
                    f"<input type='hidden' name='agent_id' value='{html.escape(a)}'>"
                    f"<button type='submit' style='padding:6px 12px;font-size:12px;border:1px solid #ef4444;color:#ef4444;background:transparent;border-radius:8px;font-weight:600;cursor:pointer;line-height:1.2;'"
                    f" onclick=\"return confirm('Revoke cert for {html.escape(a)}?')\">Revoke</button></form></div>"
                    for a in signed
                )
                _sec_actions_master += (
                    f"<div style='margin-top:8px;'>"
                    f"<div class='muted' style='font-size:12px;font-weight:600;'>Signed Agent Certificates ({len(signed)})</div>"
                    f"{_agent_certs}"
                    f"</div>"
                )

    # Agent: cert request status + re-request button
    _sec_actions_agent = ""
    if role == "agent":
        _req_btn = (
            "<form method='post' action='/peer/request-cert' style='margin:0;display:inline-block;'>"
            "<button type='submit'>Re-request certificate</button>"
            "</form>"
        )
        if sec["instance_cert_ok"] and sec["ca_exists"]:
            _sec_actions_agent = (
                f"<div style='margin-top:8px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;'>"
                f"<span class='muted' style='font-size:11px;color:#10b981;'>Certificate: signed by master CA</span>"
                f"{_req_btn}"
                f"</div>"
            )
        elif master_host and peering_token:
            _sec_actions_agent = (
                "<div style='margin-top:8px;'>"
                "<form method='post' action='/peer/request-cert' style='margin:0;'>"
                "<button type='submit'>Request certificate from master</button>"
                "</form>"
                "<div class='muted' style='font-size:11px;margin-top:4px;'>Sends a CSR to the master for signing.</div>"
                "</div>"
            )

    # Connection note (we auto-prefer HTTPS on connect)
    _http_warn = (
        "<div style='margin-top:8px;padding:8px 10px;border:1px solid rgba(16,185,129,.3);border-radius:8px;"
        "background:rgba(16,185,129,.06);font-size:11px;color:#10b981;'>"
        "Peering auto-detects HTTPS and uses it when available."
        "</div>"
    ) if role != "standalone" else ""

    security_panel = ""
    if role != "standalone":
        security_panel = (
            f"<div style='{_sec_style}'>"
            f"<div style='font-size:13px;font-weight:600;margin-bottom:6px;'>Connection Security</div>"
            f"{_sec_rows}"
            f"{_sec_actions_master}"
            f"{_sec_actions_agent}"
            f"{_http_warn}"
            f"</div>"
        )

    # Token section: role-specific labels and actions
    if role == "master":
        token_section = f"""
          <div style="margin-top:12px;padding:10px 12px;border:1px solid rgba(16,185,129,.3);border-radius:8px;background:rgba(16,185,129,.06);font-size:12px;">
            <strong>Master:</strong> Copy this token and share it with each agent. Agents must paste it exactly.
          </div>
          <label>Peering Token <span class="muted">(agents must use this exact token)</span></label>
          <div style="margin-top:4px;"><code style="word-break:break-all;font-size:11px;">{html.escape(token_display)}</code></div>
          <input name="peering_token" placeholder="Or paste to replace" style="margin-top:6px;">
          <div style="display:flex;gap:8px;margin-top:10px;align-items:center;">
            <form method="post" action="/peer/generate-token" style="margin:0;">
              <button type="submit">Generate new token</button>
            </form>
          </div>
        """
    elif role == "agent":
        token_section = ""
    else:
        token_section = ""  # standalone: no peering token

    return f"""
      <div class="card">
        <h3>Multi-Instance Peering</h3>
        <div class="muted">Connect multiple instances for cross-network monitoring. Agents push results to a master dashboard.</div>
        <div class="muted" style="margin-top:6px;">Instance ID: <code>{html.escape(instance_id)}</code></div>
        {"<div class='ok' style='margin-top:8px;white-space:pre-wrap;'>" + html.escape(peering_message) + "</div>" if peering_message else ""}
        {security_panel}
        <form method="post" action="/peer/save-settings">
          <div>
            <label>Role</label>
            <select name="peer_role">{role_opts}</select>
          </div>
          {master_peer_actions_html}
          {token_section}
          {agent_fields}
        {live_panel_html}
      </div>
    """


def _render_setup_html(
    message: str = "",
    error: str = "",
    action_output: str = "",
    elevated_check_message: str = "",
    elevated_check_output: str = "",
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
    peering_message: str = "",
    ssl_warning: str = "",
    ui_view: str = "overview",
    highlight_channel: str = "",
    log_source: str = "local",
    diagnose_agent: bool = False,
    open_server_panel: str = "",
) -> str:
    cfg = load_config()
    browser_instance_name = str(cfg.get("instance_name", "") or "").strip()
    if not browser_instance_name:
        browser_instance_name = str(cfg.get("instance_id", "") or "").strip()[:8]
    monitors = cfg.get("monitors", [])
    interval = int(cfg.get("cron_interval_minutes", 60))
    cron_enabled = bool(cfg.get("cron_enabled", False))
    history = _load_history()
    monitor_state = _load_monitor_state()

    edit_monitor = _find_monitor_by_name(monitors, edit_target) if edit_target else None
    if create_mode and not edit_monitor:
        current_name = "smart-unix-check"
        current_mode = "smart"
        current_url = ""
    else:
        current_name = (
            str(edit_monitor.get("name", ""))
            if edit_monitor
            else (monitors[0].get("name", "unix-main") if monitors else "unix-main")
        )
        current_mode = (
            str(edit_monitor.get("check_mode", "smart"))
            if edit_monitor
            else (monitors[0].get("check_mode", "smart") if monitors else "smart")
        )
        current_url = (
            str(edit_monitor.get("kuma_url", ""))
            if edit_monitor
            else (monitors[0].get("kuma_url", "") if monitors else "")
        )
    current_probe_host = str(edit_monitor.get("probe_host", "")) if edit_monitor else ""
    current_probe_port = str(edit_monitor.get("probe_port", "")) if edit_monitor else ""
    current_dns_name = str(edit_monitor.get("dns_name", "")) if edit_monitor else ""
    current_dns_server = str(edit_monitor.get("dns_server", "")) if edit_monitor else ""
    edit_original_name = str(edit_monitor.get("name", "")) if edit_monitor else ""
    current_interval = int(edit_monitor.get("interval", edit_monitor.get("cron_interval_minutes", cfg.get("cron_interval_minutes", 5)))) if edit_monitor else 5
    current_cron_enabled = bool(edit_monitor.get("cron_enabled", cfg.get("cron_enabled", True))) if edit_monitor else True

    status_html = ""
    # Elevated check result: only show in Setup & Elevated Access section, not at top
    from_elevated_check = bool(elevated_check_message or elevated_check_output)
    if message and not monitor_action_name and not from_elevated_check:
        status_html += f"<div class='ok'>{html.escape(message)}</div>"
    if error and not monitor_action_name and not from_elevated_check:
        status_html += f"<div class='err'>{html.escape(error)}</div>"
    if action_output and not monitor_action_name and not from_elevated_check:
        status_html += f"<pre>{html.escape(action_output)}</pre>"
    if ssl_warning:
        status_html = f"<div class='err'>{html.escape(ssl_warning)}</div>" + status_html
    peer_role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
    local_source_name = browser_instance_name or "Local"
    available_sources: List[Tuple[str, str]] = [("local", local_source_name)]
    if peer_role == "master":
        for sp in (cfg.get("peers", []) or []):
            sp_id = str(sp.get("instance_id", "") or "").strip()
            if not _is_valid_peer_instance_id(sp_id):
                continue
            sp_name = str(sp.get("instance_name", "") or sp_id[:8])
            available_sources.append((sp_id, sp_name))

    source_map = {sid: sname for sid, sname in available_sources}
    log_source = (log_source or "local").strip()
    if log_source not in source_map:
        log_source = "local"
    source_label = log_source
    source_name = source_map.get(source_label, local_source_name)
    source_is_remote = source_label != "local"

    agent_log_async = False
    if source_is_remote and diag_view in ("logs", "task", "config", "cache", "history", "paths", "system"):
        if diagnose_agent:
            log_text = _diagnose_agent_diag_connection(cfg, source_label)
        else:
            log_text = "Loading agent logs..."
            agent_log_async = True
    else:
        log_text = _build_diag_text(cfg, history, diag_view=diag_view, log_filter=log_filter)
    automation_status = _scheduler_status_text(cfg)
    auth_state = _load_auth_state()
    recovery_unused = _count_unused_recovery(auth_state)
    server_ip = _detect_primary_server_ip()
    all_ips = _list_system_ips()
    ntp_info = _ntp_sync_details()
    peer_last_sync = int(cfg.get("last_peer_sync", 0) or 0)
    peer_last_sync_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(peer_last_sync)) if peer_last_sync else "never"
    now_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    last_login_ip = str(auth_state.get("last_login_ip", "") or "n/a")
    last_login_at = int(auth_state.get("last_login_at", 0) or 0)
    last_login_at_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_login_at)) if last_login_at else "never"
    login_history = auth_state.get("login_history", []) if isinstance(auth_state.get("login_history", []), list) else []
    login_lines: List[str] = []
    for ev in reversed(login_history[-8:]):
        if not isinstance(ev, dict):
            continue
        ts = int(ev.get("ts", 0) or 0)
        ts_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "unknown"
        ip = str(ev.get("ip", "unknown") or "unknown")
        state = str(ev.get("state", "unknown") or "unknown")
        login_lines.append(f"{ts_text} | {ip} | {state}")
    if not login_lines:
        login_lines = ["No login history recorded yet."]

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

    setup_open_attr = " open" if (from_elevated_check or not elevated_ok) else ""
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

    # Overview gauges are scoped to the selected source context.
    source_snapshot = _build_live_snapshot_for_source(source_label)
    source_label = str(source_snapshot.get("source_id", source_label) or "local")
    source_name = str(source_snapshot.get("source_name", source_name) or source_name)
    source_is_remote = source_label != "local"
    source_channels = source_snapshot.get("channels", {}) if isinstance(source_snapshot.get("channels", {}), dict) else {}
    source_monitors = source_snapshot.get("monitors", []) if isinstance(source_snapshot.get("monitors", []), list) else []
    channels_order = ("smart", "storage", "ping", "port", "dns", "backup")
    overview_channels = [c for c in channels_order if c in source_channels]
    if not overview_channels:
        overview_channels = ["smart", "storage"]

    channel_cards: List[str] = []
    for channel in overview_channels:
        ch_data = source_channels.get(channel, {}) if isinstance(source_channels.get(channel, {}), dict) else {}
        st = str(ch_data.get("status", "unknown"))
        pct = int(ch_data.get("pct", status_pct(st)) or status_pct(st))
        last_ts = int(ch_data.get("ts", 0) or 0)
        ts_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_ts)) if last_ts else "n/a"
        history_statuses = ch_data.get("history_statuses", []) if isinstance(ch_data.get("history_statuses", []), list) else []
        dots = "".join(
            f"<span class='dot {status_class(str(x))}' title='{html.escape(str(x))}'></span>"
            for x in history_statuses[-20:]
        ) or "<span class='muted'>no history</span>"
        mapped = []
        for m in source_monitors:
            mode = str(m.get("mode", m.get("check_mode", "smart"))).lower()
            if mode == channel:
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
            f"<a class='gauge-link' href='/?view=overview&diag_view=logs&log_filter={channel}&highlight={channel}&source={html.escape(source_label)}'>"
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

    # Current-server section follows selected source context.
    display_source_name = source_name if source_name else local_source_name
    display_server_ip = server_ip
    display_now_text = now_text
    display_last_login_ip = last_login_ip
    display_last_login_at_text = last_login_at_text
    if source_is_remote:
        remote_snap = _load_peer_snapshot(source_label)
        peer_cfg = next(
            (p for p in (cfg.get("peers", []) or []) if str(p.get("instance_id", "") or "").strip() == source_label),
            None,
        )
        peer_url = str(peer_cfg.get("url", "") or "") if isinstance(peer_cfg, dict) else ""
        peer_host, _peer_port = _parse_peer_host_port(peer_url, PEER_DEFAULT_PORT)
        display_server_ip = peer_host or "remote"
        pushed_at = int((remote_snap or {}).get("pushed_at", 0) or 0)
        display_now_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pushed_at)) if pushed_at else "n/a"
        display_last_login_ip = "n/a (remote)"
        display_last_login_at_text = "n/a (remote)"

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

    # Build lookup of master-side remote monitor configs (keyed by name) for Kuma tokens.
    remote_monitor_cfg: Dict[str, Dict[str, Any]] = {}
    if peer_role == "master":
        for m in monitors:
            if m.get("_remote_peer"):
                remote_monitor_cfg[str(m.get("name", ""))] = m

    # Local monitor cards.
    local_cards: List[str] = []
    for m in monitors:
        if m.get("_remote_peer"):
            continue
        name = str(m.get("name", "?"))
        mode = str(m.get("check_mode", "smart"))
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
        local_cards.append(
            f"<div class='monitor-card {'hl-monitor' if (highlight_channel and highlight_channel == str(mode).lower()) else ''}' data-monitor='{html.escape(name)}' data-mode='{html.escape(str(mode).lower())}'>"
            + f"<div class='monitor-head'><div class='monitor-title'>{html.escape(name)}</div><span class='badge {status_class(st)}'>{status_label(st)}</span></div>"
            + f"<div class='monitor-meta' data-role='monitor-primary'>Mode: {html.escape(mode)} | Interval: {m.get('interval', cfg.get('cron_interval_minutes', 5))}m | Last ping: {html.escape(str(ping))} ms | Last run: {html.escape(ts_text)}</div>"
            + f"<div class='monitor-meta token-row'>Token: <code>{html.escape(token_label)}</code></div>"
            + f"<div data-role='monitor-live'>{monitor_action_html}</div>"
            + "<div class='button-row'>"
            + f"<button onclick=\"monitorAction('/run-check-monitor','{html.escape(name)}',this)\">Run check</button>"
            + f"<button onclick=\"monitorAction('/test-push-monitor','{html.escape(name)}',this)\">Test push</button>"
            + f"<button onclick=\"monitorAction('/edit-monitor','{html.escape(name)}',this)\">Edit</button>"
            + f"<button class='btn-remove' onclick=\"if(confirm('Delete monitor?'))monitorAction('/delete-monitor','{html.escape(name)}',this)\">Delete</button>"
            + "</div>"
            + "</div>"
        )

    # Remote / agent monitor cards.
    remote_cards: List[str] = []
    if peer_role == "master":
        for snap in _load_all_peer_snapshots():
            snap_name = str(snap.get("instance_name", "") or str(snap.get("instance_id", ""))[:8])
            snap_history = snap.get("history", [])
            snap_state = snap.get("state", {})
            snap_ml: Dict[str, Dict[str, Any]] = {}
            for e in snap_history:
                mn = str(e.get("monitor", ""))
                if mn:
                    snap_ml[mn] = e
            for pm in snap.get("monitors", []):
                pn = str(pm.get("name", "?"))
                pm_mode = str(pm.get("check_mode", "smart"))
                pl = snap_ml.get(pn, {})
                pst = str(pl.get("status", "unknown"))
                pp = pl.get("ping_ms", "n/a")
                pt = int(pl.get("ts", 0) or 0)
                pt_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pt)) if pt else "never"
                ps = snap_state.get(pn, {})
                pb = str(ps.get("banner", "") or "")
                po = str(ps.get("output", "") or "")
                plvl = "err" if str(ps.get("level", "ok")) == "err" else "ok"
                pa_html = (
                    f"<div class='{plvl}'>{html.escape(pb)}</div>"
                    + (f"<pre>{html.escape(po)}</pre>" if po else "")
                    if pb or po else ""
                )
                master_cfg = remote_monitor_cfg.get(pn, {})
                r_kuma = str(master_cfg.get("kuma_url", "") or "")
                r_token_label = kuma_token_label(r_kuma) if r_kuma else ""
                r_token_html = f"<div class='monitor-meta token-row'>Token: <code>{html.escape(r_token_label)}</code></div>" if r_token_label else ""
                remote_cards.append(
                    f"<div class='monitor-card {'hl-monitor' if (highlight_channel and highlight_channel == pm_mode.lower()) else ''}' data-monitor='{html.escape(pn)}' data-mode='{html.escape(pm_mode.lower())}'>"
                    + f"<div class='monitor-head'><div class='monitor-title'>{html.escape(pn)}</div>"
                    + f"<span class='badge {status_class(pst)}'>{status_label(pst)}</span></div>"
                    + f"<div class='monitor-meta' data-role='monitor-primary'>Mode: {html.escape(pm_mode)} | Last ping: {html.escape(str(pp))} ms | Last run: {html.escape(pt_text)} | Origin: {html.escape(snap_name)}</div>"
                    + r_token_html
                    + f"<div data-role='monitor-live'>{pa_html}</div>"
                    + "<div class='button-row'>"
                    + f"<button class='btn-remove' onclick=\"if(confirm('Remove remote monitor from master?'))monitorAction('/delete-monitor','{html.escape(pn)}',this)\">Remove</button>"
                    + "</div>"
                    + "</div>"
                )
    local_monitors_html = "".join(local_cards) if local_cards else "<p class='muted'>No local monitors configured yet.</p>"
    remote_monitors_html = ""
    if peer_role == "master":
        remote_grid = "".join(remote_cards) if remote_cards else "<p class='muted'>No agent monitors synced yet. Create a monitor on an agent or wait for the next sync.</p>"
        remote_monitors_html = (
            f"<div class='card' style='margin-top:12px;'>"
            f"<h3>Agent Monitors <span class='badge muted-badge'>{len(remote_cards)}</span></h3>"
            f"<div class='muted' style='margin-bottom:8px;'>Monitors running on remote agent instances. Status is updated via peering sync. "
            f"Kuma push is handled by the master.</div>"
            f"<div class='monitor-grid'>{remote_grid}</div>"
            f"</div>"
        )

    checked_cron = "checked" if current_cron_enabled else ""
    filter_label = {"all": "all", "smart": "smart", "storage": "storage", "ping": "ping", "port": "port", "dns": "dns", "backup": "backup"}.get((log_filter or "all").lower(), "all")
    diag_label = {
        "logs": "logs",
        "task": "task",
        "config": "config",
        "cache": "cache",
        "history": "history",
        "paths": "paths",
        "system": "system",
    }.get((diag_view or "logs").lower(), "logs")
    source_tabs_html = ""
    if peer_role == "master":
        q_base = f"view=overview&amp;diag_view={diag_label}&amp;log_filter={filter_label}"
        src_chips = []
        for sid, sname in available_sources:
            src_chips.append(
                f"<a class='chip {'active' if source_label==sid else ''}' "
                f"href='?{q_base}&amp;source={html.escape(sid)}'>"
                f"{html.escape(sname)}"
                "</a>"
            )
        source_tabs_html = (
            "<div class='chip-row source-tabs' style='margin-top:8px;'>"
            + "".join(src_chips)
            + "</div>"
        )
    modal_open = bool(create_mode or edit_original_name)
    modal_title = "Edit Monitor" if edit_original_name else "Create Monitor"
    is_master = peer_role == "master"
    peers_list = cfg.get("peers", []) if is_master else []
    if not isinstance(peers_list, list):
        peers_list = []
    target_options = ""
    if is_master and peers_list and not edit_original_name:
        target_options = "<option value='local' selected>Local (this instance)</option>"
        seen_target_ids: set[str] = set()
        for tp in peers_list:
            tp_id = str(tp.get("instance_id", "") or "").strip()
            # Ignore malformed/stale peer IDs in the create-monitor target selector.
            if (not _is_valid_peer_instance_id(tp_id)) or tp_id in seen_target_ids:
                continue
            seen_target_ids.add(tp_id)
            tp_name = str(tp.get("instance_name", "") or tp_id[:8])
            target_options += f"<option value='{html.escape(tp_id)}'>{html.escape(tp_name)}</option>"
    ui_view = (ui_view or "overview").strip().lower()
    if ui_view not in ("overview", "setup", "settings"):
        ui_view = "overview"
    if create_mode or edit_original_name:
        ui_view = "setup"

    stay_popup_field = "<input type='hidden' name='stay_popup' value='1'> " if show_setup_popup else ""
    gallery_urls_json = json.dumps(gallery_urls)
    elevated_check_html = ""
    if elevated_check_message:
        elevated_check_html += f"<div class='ok'>{html.escape(elevated_check_message)}</div>"
    if elevated_check_output:
        elevated_check_html += f"<pre>{html.escape(elevated_check_output)}</pre>"
    setup_card = f"""
    <details class="card"{setup_open_attr}>
      <summary>Setup & Elevated Access</summary>
      <div class="{setup_state_css}">{html.escape(setup_state_text)}</div>
      <div class="{elevated_css}">{html.escape(elevated_msg)}</div>
      {elevated_check_html}
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
        "<div class='card'><div class='chip-row nav-tabs'>"
        + f"<a class='chip {'active' if ui_view=='overview' else ''}' href='/?view=overview&diag_view={diag_label}&log_filter={filter_label}&source={html.escape(source_label)}'>Overview</a>"
        + f"<a class='chip {'active' if ui_view=='setup' else ''}' href='/?view=setup'>Monitor Setup</a>"
        + f"<a class='chip {'active' if ui_view=='settings' else ''}' href='/?view=settings'>Settings</a>"
        + "</div>"
        + (source_tabs_html if ui_view == "overview" else "")
        + "</div>"
    )
    source_scope_text = (
        f"Viewing remote source: {source_name} (gauges and diagnostics are scoped to this source)."
        if source_is_remote
        else f"Viewing local source: {source_name}."
    )
    update_channel = "main" if bool(cfg.get("update_from_main", False)) else "latest"
    update_curl_cmd = (
        "curl -sSL https://raw.githubusercontent.com/gsiscotty/Uptime.Kuma.Monitor.Tools/main/addons/unix-monitor/install.sh"
        f" | sudo env UNIX_MONITOR_UPDATE_CHANNEL={update_channel} bash"
    )
    has_update_helper = get_update_helper_path().exists()
    has_backup = (get_script_path().parent / "unix-monitor.py.prev").exists()
    autoupdate_enabled = bool(cfg.get("autoupdate_enabled", False))
    update_from_main = bool(cfg.get("update_from_main", False))
    selected_channel = "main" if update_from_main else "latest"
    selected_channel_label = "main" if update_from_main else "latest release"
    update_check_result = _load_update_check_result() if not source_is_remote else {}
    latest_version = str(update_check_result.get("public_version", "") or update_check_result.get("latest_version", "") or "")
    cached_channel = str(update_check_result.get("selected_channel", "") or "")
    effective_ref = str(update_check_result.get("effective_ref", "") or update_check_result.get("selected_ref", "") or selected_channel)
    public_label = f"{selected_channel} via {effective_ref}" if effective_ref and effective_ref != selected_channel else selected_channel
    channel_matches_cache = (cached_channel == selected_channel) or (not cached_channel and selected_channel == "latest")
    # Only show update available if cache says so AND current VERSION is actually older (stale cache fix after manual update)
    update_available = channel_matches_cache and bool(update_check_result.get("update_available")) and (
        latest_version and _version_tuple(VERSION) < _version_tuple(latest_version)
    )
    update_status_text = "unknown (use Recheck for updates)"
    if latest_version:
        update_status_text = "update available" if update_available else "up to date"
    update_confirm = (
        f"Update now from {selected_channel_label} to v{latest_version}? Current local version is v{VERSION}. "
        "Config and data will be preserved. Page will reload after update."
        if latest_version
        else f"Run update from {selected_channel_label}? Config and data will be preserved. Page will reload after update."
    )
    package_update_btns = ""
    if not source_is_remote:
        update_ready_banner = ""
        if autoupdate_enabled and update_available and has_update_helper:
            ver_text = f" (v{html.escape(latest_version)})" if latest_version else ""
            update_ready_banner = (
                "<div class='update-ready-banner'>"
                "<span>An update is available" + ver_text + ". </span>"
                "<form method='post' action='/self-update' style='display:inline;' onsubmit='return confirm(\"" + html.escape(update_confirm) + "\");'>"
                "<button type='submit' class='btn-inline'>Update now</button></form>"
                " <form method='post' action='/settings/request-autoupdate-on-logout' style='display:inline;'>"
                "<button type='submit' class='btn-inline btn-inline-muted'>Update after logout</button></form>"
                "</div>"
            )
        enable_btn_class = "autoupdate-btn autoupdate-btn-active" if autoupdate_enabled else "autoupdate-btn"
        disable_btn_class = "autoupdate-btn autoupdate-btn-active" if not autoupdate_enabled else "autoupdate-btn"
        from_main_enable_class = "autoupdate-btn autoupdate-btn-active" if update_from_main else "autoupdate-btn"
        from_main_disable_class = "autoupdate-btn autoupdate-btn-active" if not update_from_main else "autoupdate-btn"
        autoupdate_form = (
            update_ready_banner
            + "<div class='autoupdate-row'>"
            "<form method='post' action='/settings/save-autoupdate' class='autoupdate-form' style='display:inline;'>"
            "<input type='hidden' name='autoupdate_enabled' value='1'>"
            "<button type='submit' class='" + enable_btn_class + "'>Enable autoupdate</button></form>"
            " <form method='post' action='/settings/save-autoupdate' class='autoupdate-form' style='display:inline;'>"
            "<input type='hidden' name='autoupdate_enabled' value='0'>"
            "<button type='submit' class='" + disable_btn_class + "'>Disable autoupdate</button></form>"
            "<span class='autoupdate-hint'>Check on each visit, apply if newer.</span></div>"
            + "<div class='autoupdate-row'>"
            "<form method='post' action='/settings/save-update-from-main' class='autoupdate-form' style='display:inline;'>"
            "<input type='hidden' name='update_from_main' value='1'>"
            "<button type='submit' class='" + from_main_enable_class + "'>Update from main</button></form>"
            " <form method='post' action='/settings/save-update-from-main' class='autoupdate-form' style='display:inline;'>"
            "<input type='hidden' name='update_from_main' value='0'>"
            "<button type='submit' class='" + from_main_disable_class + "'>Update from latest</button></form>"
            "<span class='autoupdate-hint'>Update source controls which public version is checked/applied.</span></div>"
        )
        package_update_btns = autoupdate_form
        if has_update_helper:
            package_update_btns += "<div class='button-row' style='margin-bottom:8px;'><form method='post' action='/self-update' style='display:inline;' onsubmit='return confirm(\"" + html.escape(update_confirm) + "\");'><button type='submit' class='btn-inline'>Update now</button></form>"
        if has_backup and has_update_helper:
            package_update_btns += " <form method='post' action='/self-rollback' style='display:inline;' onsubmit='return confirm(\"Restore previous version?\");'><button type='submit' class='btn-inline' style='border-color:#ef4444;color:#ef4444;'>Rollback</button></form>"
        if "button-row" in package_update_btns:
            package_update_btns += "</div>"
    ip_list_text = "\n".join(all_ips) if all_ips else "No IP addresses detected."
    login_history_text = "\n".join(login_lines)
    package_panel_open = " open" if open_server_panel == "package" else ""
    package_panel_html = (
        "<div class='card server-action-panel" + package_panel_open + "' data-server-panel='package'>"
        "<h4>Unix runtime update</h4>"
        + package_update_btns
        + "<div class='button-row'>"
        + "<a class='btn-inline' href='" + html.escape(REPO_URL) + "' target='_blank' rel='noopener noreferrer'>Open GitHub repository</a>"
        + (" <form method='post' action='/settings/recheck-updates' style='display:inline;'><button type='submit' class='btn-inline btn-inline-muted'>Recheck for updates</button></form>" if not source_is_remote else "")
        + "</div>"
        + "<div class='muted'>Selected source: " + html.escape(selected_channel_label) + " | Local Unix runtime: " + html.escape(VERSION) + " | Public Unix runtime (" + html.escape(public_label) + "): " + html.escape(latest_version or "unknown") + " | Status: " + html.escape(update_status_text) + "</div>"
        + "<pre>" + html.escape(update_curl_cmd) + "</pre>"
        + "<div class='muted'>Update: backs up, downloads latest, validates, replaces. On failure restores previous. Config and data preserved.</div>"
        + "<div class='muted'>" + html.escape(source_scope_text) + "</div></div>"
    )
    server_info_card_html = (
        "<div class='server-info-grid'>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='name'><span class='muted'>Name</span><strong>{html.escape(display_source_name)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='ip'><span class='muted'>IP</span><strong>{html.escape(display_server_ip)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='time'><span class='muted'>Time</span><strong>{html.escape(display_now_text)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='package'><span class='muted'>Unix Runtime Version</span><strong>{html.escape(VERSION)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='login'><span class='muted'>Last Login Source IP</span><strong>{html.escape(display_last_login_ip)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='login-time'><span class='muted'>Last Login Time</span><strong>{html.escape(display_last_login_at_text)}</strong></button>"
        "</div>"
        "<div class='server-action-panels'>"
        f"<div class='card server-action-panel' data-server-panel='name'><h4>Change server name</h4><form method='post' action='/settings/save-instance-name'><label>Instance Name</label><input name='instance_name' value='{html.escape(str(cfg.get('instance_name', '') or ''))}' placeholder='e.g. HQ-NAS'><div class='button-row'><button type='submit'>Save name</button></div></form></div>"
        f"<div class='card server-action-panel' data-server-panel='ip'><h4>System IP addresses</h4><pre>{html.escape(ip_list_text)}</pre></div>"
        f"<div class='card server-action-panel' data-server-panel='time'><h4>Time sync details</h4><pre>Current time: {html.escape(now_text)}\nLast peer sync: {html.escape(peer_last_sync_text)}\nNTP synced: {html.escape(ntp_info.get('synced', 'unknown'))}\nNTP service: {html.escape(ntp_info.get('service', 'unknown'))}\nNTP source: {html.escape(ntp_info.get('source', 'unknown'))}\n\n{html.escape(ntp_info.get('detail', ''))}</pre></div>"
        + package_panel_html
        + f"<div class='card server-action-panel' data-server-panel='login'><h4>Recent login events (IP + state)</h4><pre>{html.escape(login_history_text)}</pre></div>"
        + f"<div class='card server-action-panel' data-server-panel='login-time'><h4>Recent login events (time + state)</h4><pre>{html.escape(login_history_text)}</pre></div>"
        + "</div>"
    )
    overview_view_html = f"""
      <div class="card">
        <h3>Current Server <span class="badge muted-badge">{html.escape(display_source_name)}</span></h3>
        <div class="muted" style="margin-bottom:8px;">{html.escape(source_scope_text)}</div>
        {server_info_card_html}
      </div>
      <div class="card">
        <h3>Monitoring Overview</h3>
        <div class="overview-grid">{overview_html}</div>
      </div>
      <div class="card">
        <h3>Logs & Diagnostics</h3>
        <div class="chip-row" style="flex-wrap:wrap;">
          <a class="chip {'active' if diag_label=='logs' else ''}" href="?view=overview&amp;diag_view=logs&amp;log_filter={html.escape(filter_label)}&amp;source={html.escape(source_label)}">Logs</a>
          <a class="chip {'active' if diag_label=='task' else ''}" href="?view=overview&amp;diag_view=task&amp;source={html.escape(source_label)}">Task</a>
          <a class="chip {'active' if diag_label=='cache' else ''}" href="?view=overview&amp;diag_view=cache&amp;source={html.escape(source_label)}">Cache</a>
          <a class="chip {'active' if diag_label=='config' else ''}" href="?view=overview&amp;diag_view=config&amp;source={html.escape(source_label)}">Config</a>
          <a class="chip {'active' if diag_label=='history' else ''}" href="?view=overview&amp;diag_view=history&amp;source={html.escape(source_label)}">History</a>
          <a class="chip {'active' if diag_label=='paths' else ''}" href="?view=overview&amp;diag_view=paths&amp;source={html.escape(source_label)}">Paths</a>
          <a class="chip {'active' if diag_label=='system' else ''}" href="?view=overview&amp;diag_view=system&amp;source={html.escape(source_label)}">System</a>
        </div>
        {"<div class='chip-row'><a class='chip " + ("active" if filter_label=='all' else "") + "' href='?view=overview&diag_view=logs&log_filter=all&source=" + html.escape(source_label) + "'>All</a><a class='chip " + ("active" if filter_label=='smart' else "") + "' href='?view=overview&diag_view=logs&log_filter=smart&source=" + html.escape(source_label) + "'>Smart</a><a class='chip " + ("active" if filter_label=='storage' else "") + "' href='?view=overview&diag_view=logs&log_filter=storage&source=" + html.escape(source_label) + "'>Storage</a><a class='chip " + ("active" if filter_label=='ping' else "") + "' href='?view=overview&diag_view=logs&log_filter=ping&source=" + html.escape(source_label) + "'>Ping</a><a class='chip " + ("active" if filter_label=='port' else "") + "' href='?view=overview&diag_view=logs&log_filter=port&source=" + html.escape(source_label) + "'>Port</a><a class='chip " + ("active" if filter_label=='dns' else "") + "' href='?view=overview&diag_view=logs&log_filter=dns&source=" + html.escape(source_label) + "'>DNS</a><a class='chip " + ("active" if filter_label=='backup' else "") + "' href='?view=overview&diag_view=logs&log_filter=backup&source=" + html.escape(source_label) + "'>Backup</a></div>" if diag_label=='logs' else ""}
        <pre id="log-diag-pre"{' data-agent-fetch="1" data-peer-id="' + html.escape(source_label) + '" data-view="' + html.escape(diag_label) + '" data-log-filter="' + html.escape(filter_label) + '"' if agent_log_async else ""}>{html.escape(log_text)}</pre>
        <div class="button-row">
          <form method="get" action="/"><input type="hidden" name="view" value="overview"><input type="hidden" name="diag_view" value="{html.escape(diag_label)}"><input type="hidden" name="log_filter" value="{html.escape(filter_label)}"><input type="hidden" name="source" value="{html.escape(source_label)}"><button type="submit">Refresh</button></form>
          {("<form method='get' action='/' style='margin-left:auto;'><input type='hidden' name='view' value='overview'><input type='hidden' name='diag_view' value='" + html.escape(diag_label) + "'><input type='hidden' name='log_filter' value='" + html.escape(filter_label) + "'><input type='hidden' name='source' value='" + html.escape(source_label) + "'><input type='hidden' name='diagnose' value='1'><button type='submit'>Diagnose connection</button></form>") if source_label != "local" else ""}
          {"<form method='post' action='/clear-logs'><button type='submit'>Clear logs</button></form>" if diag_label == "logs" else ""}
          {"<form method='post' action='/clear-task-status'><button type='submit'>Clear task data</button></form>" if diag_label == "task" else ""}
          {"<form method='post' action='/clear-cache'><button type='submit'>Clear cache</button></form>" if diag_label == "cache" else ""}
          {"<form method='post' action='/clear-history'><button type='submit'>Clear history</button></form>" if diag_label == "history" else ""}
          {"<form method='post' action='/clear-system-cache'><button type='submit'>Clear system logs</button></form>" if diag_label == "system" else ""}
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
        <h3>Monitor Setup</h3>
        <div class="muted">Create, edit, and delete monitors from this view.</div>
        <button onclick="openModal('/open-create', this)" style="margin-top:10px;">Create monitor</button>
      </div>
      <div class="card"><h3>Local Monitors <span class="badge muted-badge">{len(local_cards)}</span></h3><div class="monitor-grid">{local_monitors_html}</div></div>
      {remote_monitors_html}
    """
    settings_view_html = f"""
      <div class="card" id="settings">
        <h3>Application Settings & Security</h3>
        {"<div class='ok'>" + html.escape(security_message) + "</div>" if security_message else ""}
        {"<pre>" + html.escape(security_output) + "</pre>" if security_output else ""}
        <div class="muted">Admin account protected by password + mandatory TOTP 2FA.</div>
        <form method="post" action="/settings/save-instance-name">
          <label>Instance Name</label>
          <input name="instance_name" value="{html.escape(str(cfg.get('instance_name', '') or ''))}" placeholder="e.g. HQ-NAS">
          <div class="button-row"><button type="submit">Save instance name</button></div>
        </form>
        <form method="post" action="/auth/change-password">
          <input type="hidden" name="username" value="admin" autocomplete="username">
          <label>Change password</label>
          <div class="muted">Unused recovery codes: {recovery_unused}</div>
          <div class="row">
            <div><input name="current_password" type="password" autocomplete="current-password" placeholder="Current password" required></div>
            <div><input name="new_password" type="password" autocomplete="new-password" minlength="10" placeholder="New password" required></div>
          </div>
          <input name="new_password_confirm" type="password" autocomplete="new-password" minlength="10" placeholder="Confirm new password" required>
          <div class="button-row"><button type="submit">Update password</button></div>
        </form>
        <div class="button-row">
          <form method="post" action="/auth/regenerate-recovery"><button type="submit">Regenerate recovery codes</button></form>
        </div>
        <form method="post" action="/auth/rotate-totp">
          <label>Rotate TOTP secret (verify with current 6-digit code)</label>
          <div class="row">
            <div><input name="token" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required></div>
            <div><button type="submit">Rotate TOTP + recovery codes</button></div>
          </div>
        </form>
      </div>
      {_render_peering_card(cfg, peering_message=peering_message)}
      <div class="card">
        <h3>Danger Zone</h3>
        <div class="muted">Restart package services from UI (web UI + scheduler loop).</div>
        <div style="margin-bottom:18px;padding:12px 0;border-bottom:1px solid var(--border);">
          <label>Export</label>
          <div class="muted" style="margin-top:4px;">Full encrypted backup or public-only settings.</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px;">
            <form method="post" action="/auth/export-backup" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0;">
              <input name="backup_key" id="backup_key" type="password" placeholder="Encryption key (min 12 chars)" style="min-width:200px;" minlength="12" required>
              <button type="button" onclick="var k=document.getElementById('backup_key');k.value=Array.from(crypto.getRandomValues(new Uint8Array(24))).map(b=>b.toString(16).padStart(2,'0')).join('');k.type='text';k.select();">Generate key</button>
              <button type="submit">Export Encrypted Backup</button>
            </form>
          </div>
          <div style="margin-top:10px;">
            <a class="close-link" href="/auth/export">Export Backup</a>
          </div>
        </div>
        <form method="post" action="/auth/import" enctype="multipart/form-data">
          <label>Import settings backup</label>
          <div class="muted" style="margin-top:4px;">Encrypted backups require the decryption key. Paste JSON or choose file.</div>
          <label>Decryption key <span class="muted">(required for encrypted backups)</span></label>
          <input name="backup_key" type="password" placeholder="Enter the key you saved during export" style="margin-top:4px;">
          <label>Backup JSON</label>
          <textarea name="import_payload" rows="5" style="width:100%;margin-top:6px;box-sizing:border-box;border:1px solid #30405b;border-radius:8px;background:#0f1726;color:#d7e2f0;padding:8px;" placeholder="Paste backup JSON or use file below"></textarea>
          <label>Or import from file</label>
          <input name="import_file" type="file" accept=".json,application/json">
          <div class="button-row">
            <button type="submit">Import settings</button>
          </div>
        </form>
        <div class="card" style="margin-top:16px;border-color:rgba(239,68,68,.25);">
          <h3>Factory Settings</h3>
          <div class="button-row">
            <form method="post" action="/danger-restart" onsubmit="return confirm('Restart addon now? UI will disconnect briefly.');">
              <button type="submit" style="border-color:#ef4444;color:#ef4444;">Restart addon</button>
            </form>
            <form method="post" action="/danger-reset" onsubmit="return confirm('Reset configuration? All monitors and peering will be cleared. Auth will be kept.');">
              <button type="submit" style="border-color:#ef4444;color:#ef4444;">Reset configuration</button>
            </form>
          </div>
        </div>
      </div>
    """
    active_view_html = overview_view_html if ui_view == "overview" else (setup_view_html if ui_view == "setup" else settings_view_html)
    body_layout = nav_html + active_view_html + setup_popup_html

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <link rel="icon" type="image/png" href="{html.escape(BRAND_FAVICON_URL)}">
  <title>{(html.escape(browser_instance_name) + " - ") if browser_instance_name else ""}{html.escape(PRODUCT_NAME)} - Setup</title>
  <style>
    :root {{
      --bg: #0b1220; --card: #121d2f; --card-soft: #17243a; --border: #2a3d5a; --text: #d7e2f0; --muted: #8fa1b8;
      --blue: #2f80ed; --green: #22c55e; --yellow: #f59e0b; --red: #ef4444; --unknown: #64748b;
    }}
    html {{ min-height: 100%; background: radial-gradient(circle at 20% 0%, #1e4679 0%, var(--bg) 40%, #070b14 100%); }}
    body {{ font-family: "Inter","Segoe UI",-apple-system,BlinkMacSystemFont,Arial,sans-serif; margin: 12px; min-height: calc(100vh - 24px); background: radial-gradient(circle at 20% 0%, #1e4679 0%, var(--bg) 40%, #070b14 100%); background-repeat: no-repeat; background-attachment: fixed; color: var(--text); }}
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
    button {{ margin: 0; padding: 9px 14px; border: 1px solid #36517a; background: transparent; color: #c8dbf8; border-radius: 8px; cursor: pointer; font-weight: 600; line-height: 1.2; font-size: 13px; }}
    button:hover {{ background: rgba(54,81,122,.25); }}
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
    .monitor-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 10px; }}
    .monitor-card {{ border: 1px solid var(--border); border-radius: 10px; background: var(--card-soft); padding: 12px; display: flex; flex-direction: column; }}
    .monitor-card .button-row {{ margin-top: auto; padding-top: 14px; }}
    .monitor-card .btn-remove {{ background: transparent; border: 1px solid #ef4444; color: #ef4444; }}
    .monitor-card .btn-remove:hover {{ background: rgba(239,68,68,.12); }}
    .monitor-card.hl-monitor {{ border-color: #4c8ff6; box-shadow: 0 0 0 1px rgba(76,143,246,0.45) inset; }}
    .monitor-head {{ display: flex; justify-content: space-between; align-items: center; gap: 8px; }}
    .monitor-title {{ font-weight: 700; color: #d8e8ff; }}
    .badge {{ font-size: 11px; padding: 3px 8px; border-radius: 999px; border: 1px solid transparent; }}
    .badge.st-up {{ background: rgba(34,197,94,.15); border-color: rgba(34,197,94,.35); }}
    .badge.st-warning {{ background: rgba(245,158,11,.16); border-color: rgba(245,158,11,.4); }}
    .badge.st-down {{ background: rgba(239,68,68,.16); border-color: rgba(239,68,68,.4); }}
    .badge.st-unknown {{ background: rgba(100,116,139,.2); border-color: rgba(100,116,139,.4); }}
    .badge.muted-badge {{ background: rgba(100,116,139,.15); border-color: rgba(100,116,139,.35); color: var(--muted); font-size:.7rem; }}
    .badge.ok {{ background: rgba(34,197,94,.15); border-color: rgba(34,197,94,.35); }}
    .badge.err {{ background: rgba(239,68,68,.16); border-color: rgba(239,68,68,.4); }}
    .monitor-meta {{ margin-top: 8px; font-size: 12px; color: #9fb2cc; line-height: 1.35; }}
    .monitor-meta.token-row {{ margin-bottom: 10px; }}
    .monitor-meta code {{ display: inline-block; padding: 3px 6px; margin-left: 4px; line-height: 1.2; overflow-wrap: anywhere; }}
    .monitor-card .button-row {{ margin-bottom: 0; }}
    .pulse-hit {{ animation: pulseGlow 900ms ease; }}
    @keyframes pulseGlow {{
      0% {{ box-shadow: 0 0 0 0 rgba(47,128,237,0.65); transform: scale(1); }}
      45% {{ box-shadow: 0 0 0 8px rgba(47,128,237,0.0); transform: scale(1.01); }}
      100% {{ box-shadow: 0 0 0 0 rgba(47,128,237,0.0); transform: scale(1); }}
    }}
    .chip {{ display: inline-block; padding: 7px 14px; border-radius: 10px; border: 1px solid #3f5f88; color: #c5dcff; text-decoration: none; font-size: 12px; font-weight: 600; transition: all 140ms ease; line-height: 1.2; }}
    .chip:hover {{ border-color: #5aa1ff; color: #e6f2ff; }}
    .chip.active {{ background: linear-gradient(180deg, rgba(87,156,255,.35), rgba(47,128,237,.28)); border-color: #67abff; color: #eaf4ff; box-shadow: 0 0 0 1px rgba(103,171,255,.2) inset; }}
    .chip-row {{ display: flex; gap: 6px; flex-wrap: wrap; align-items: center; margin-top: 10px; margin-bottom: 4px; }}
    .nav-tabs {{ justify-content: center; gap: 12px; }}
    .source-tabs {{ justify-content: center; }}
    .server-info-grid {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap:8px; }}
    .server-info-item {{ border:1px solid var(--border); border-radius:10px; background:var(--card-soft); padding:10px; display:flex; flex-direction:column; gap:4px; }}
    .server-info-action {{ text-align:left; width:100%; cursor:pointer; transition:all .16s ease; }}
    .server-info-action:hover {{ border-color:#4c8ff6; box-shadow:0 0 0 1px rgba(76,143,246,.35) inset; transform: translateY(-1px); }}
    .server-action-panels {{ margin-top:10px; }}
    .server-action-panel {{ display:none; border-color:rgba(76,143,246,.3); }}
    .server-action-panel.open {{ display:block; }}
    .server-action-panel[data-server-panel='package'] {{ text-align:left; }}
    .autoupdate-row {{ margin-bottom:12px; display:flex; flex-wrap:wrap; align-items:center; gap:8px; }}
    .autoupdate-form {{ margin:0; }}
    .autoupdate-btn {{ padding:8px 14px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer; border:1px solid #36517a; background:transparent; color:#8fa1b8; transition:all .15s ease; }}
    .autoupdate-btn:hover {{ background:rgba(54,81,122,.25); color:#c8dbf8; }}
    .autoupdate-btn-active {{ background:linear-gradient(180deg,rgba(87,156,255,.35),rgba(47,128,237,.28)); border-color:#4c8ff6; color:#eaf4ff; }}
    .autoupdate-btn-active:hover {{ background:linear-gradient(180deg,rgba(87,156,255,.45),rgba(47,128,237,.38)); }}
    .autoupdate-hint {{ font-size:12px; color:var(--muted); margin-left:4px; }}
    .server-action-panel[data-server-panel='package'] .button-row {{ justify-content:flex-start; }}
    .btn-inline {{ display:inline-block; padding:9px 14px; border:1px solid #36517a; border-radius:8px; text-decoration:none; color:#c8dbf8; font-weight:600; }}
    .btn-inline:hover {{ background: rgba(54,81,122,.25); }}
    .btn-inline-muted {{ border-color:#3f5f88; color:#8fa1b8; }}
    .update-ready-banner {{ margin-bottom:12px; padding:10px 12px; background:rgba(47,128,237,.12); border:1px solid rgba(76,143,246,.35); border-radius:8px; display:flex; flex-wrap:wrap; align-items:center; gap:8px; }}
    .server-info-item strong {{ font-size:13px; color:#d9e8ff; }}
    .modal-backdrop {{ position: fixed; inset: 0; background: rgba(5,10,20,.74); display: none; align-items: center; justify-content: center; z-index: 2000; }}
    .modal-backdrop.open {{ display: flex; }}
    .modal {{ width: min(640px, 96vw); max-height: 92vh; overflow: auto; background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px; }}
    .close-link {{ color: #c8dbf8; text-decoration: none; padding: 9px 14px; border: 1px solid #36517a; border-radius: 8px; margin-top: 0; display: inline-block; line-height: 1.2; font-size: 13px; font-weight: 600; background: transparent; }}
    .close-link:hover {{ background: rgba(54,81,122,.25); }}
    .modal-toggle-row {{ display: flex; align-items: center; gap: 10px; margin-top: 12px; padding: 10px 12px; border: 1px solid #30405b; border-radius: 8px; background: rgba(15,23,38,.6); }}
    .modal-toggle-row label.toggle-label {{ display: flex; align-items: center; gap: 8px; margin: 0; font-weight: 500; font-size: 13px; cursor: pointer; }}
    .modal-toggle-row input[type="checkbox"] {{ width: auto; margin: 0; accent-color: #2f80ed; }}
    .required-asterisk {{ color: #ef4444; font-weight: 700; }}
    .modal-form-error {{ background: rgba(239,68,68,.15); border: 1px solid rgba(239,68,68,.35); color: #f8b2b2; padding: 8px 10px; border-radius: 6px; margin-top: 10px; font-size: 13px; display: none; }}
    .modal-form-error.show {{ display: block; }}
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
      padding: 9px 14px;
      border: 1px solid #36517a;
      border-radius: 8px;
      display: inline-block;
      line-height: 1.2;
      background: transparent;
      font-weight: 600;
      font-size: 13px;
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
<body data-ui-view="{html.escape(ui_view)}" data-diag-view="{html.escape(diag_label)}" data-log-filter="{html.escape(filter_label)}" data-log-source="{html.escape(source_label)}" data-form-error="{('1' if error and modal_open else '0')}">
  <div class="container" data-source="{html.escape(source_label)}">
    <div class="card">
      <div class="brand-head">
        <div class="top-actions">
          <form method="post" action="/auth/logout"><button class="ghost-btn" type="submit">Log out</button></form>
        </div>
        <div class="brand-center">
          <a href="{html.escape(BRAND_URL)}" target="_blank" rel="noopener noreferrer"><img class="brand-logo" src="{html.escape(BRAND_LOGO_URL)}" alt="{html.escape(BRAND_NAME)} logo"></a>
          <div class="brand-summary">All-in-one Unix monitoring: SMART, storage, backup, ping, port, DNS, secure peering, and instant Uptime Kuma alerts.</div>
        </div>
      </div>
      {status_html}
    </div>
    {body_layout}
    <div class="modal-backdrop {'open' if modal_open else ''}" id="monitor-modal">
      <div class="modal">
        <h3>{html.escape(modal_title)}</h3>
        <form method="post" action="/save" novalidate id="monitor-form">
          <input type="hidden" name="edit_original_name" value="{html.escape(edit_original_name)}">
          {"<div id='target-peer-wrap'><label>Target Instance</label><select id='target_peer' name='target_peer' onchange='window._onTargetChange && window._onTargetChange()'>" + target_options + "</select><div id='agent-kuma-info' class='muted' style='margin-top:4px;display:none;border:1px solid rgba(47,128,237,.3);background:rgba(47,128,237,.08);border-radius:6px;padding:6px 10px;font-size:12px;'>Kuma Push URL will be added to this master. The master pushes status to Kuma on behalf of the agent.</div></div>" if target_options else ""}
          <label>Monitor Name <span class="required-asterisk">*</span></label>
          <input id="name" name="name" value="{html.escape(current_name)}" required minlength="2" placeholder="e.g. smart-unix-check">
          <label>Kuma Push URL <span class="required-asterisk">*</span></label>
          <input name="kuma_url" value="{html.escape(current_url)}" required placeholder="https://kuma.example.com/api/push/TOKEN">
          <div class="row">
            <div>
              <label>Check Mode</label>
              <select id="check_mode" name="check_mode">
                <option value="smart" {"selected" if current_mode == "smart" else ""}>smart</option>
                <option value="storage" {"selected" if current_mode == "storage" else ""}>storage</option>
                <option value="ping" {"selected" if current_mode == "ping" else ""}>ping</option>
                <option value="port" {"selected" if current_mode == "port" else ""}>port</option>
                <option value="dns" {"selected" if current_mode == "dns" else ""}>dns</option>
                <option value="backup" {"selected" if current_mode == "backup" else ""}>backup</option>
              </select>
            </div>
            <div>
              <label>Interval (minutes)</label>
              <input name="interval" type="number" min="1" max="1440" value="{current_interval}">
            </div>
          </div>
          <div id="probe-host-wrap">
            <label>Probe Host (for ping/port) <span class="required-asterisk">*</span></label>
            <input name="probe_host" value="{html.escape(current_probe_host)}" placeholder="example.com or 192.168.1.10">
          </div>
          <div id="probe-port-wrap">
            <label>Probe Port (for port mode) <span class="required-asterisk">*</span></label>
            <input name="probe_port" type="number" min="1" max="65535" value="{html.escape(current_probe_port)}" placeholder="443">
          </div>
          <div id="dns-name-wrap">
            <label>DNS Name (for dns mode) <span class="required-asterisk">*</span></label>
            <input name="dns_name" value="{html.escape(current_dns_name)}" placeholder="example.com">
          </div>
          <div id="dns-server-wrap">
            <label>DNS Server (optional)</label>
            <input name="dns_server" value="{html.escape(current_dns_server)}" placeholder="8.8.8.8">
          </div>
          <div class="modal-toggle-row">
            <label class="toggle-label"><input type="checkbox" name="cron_enabled" value="1" {checked_cron}> <span>Enable automatic checks</span></label>
          </div>
          <div id="monitor-form-error" class="modal-form-error" role="alert"></div>
          <div class="button-row">
            <button type="submit">{'Update monitor' if edit_original_name else 'Create monitor'}</button>
            <button type="button" class="close-link" onclick="document.getElementById('monitor-modal').classList.remove('open')">Cancel</button>
          </div>
        </form>
      </div>
    </div>
    <div class="modal-backdrop" id="add-agent-modal">
      <div class="modal">
        <h3>Add Agent</h3>
        <div class="muted" style="margin-bottom:10px;">Manually register an agent instance. The agent will appear once it pushes data, or you can set its URL to enable master-initiated sync.</div>
        <form method="post" action="/peer/add-agent">
          <label>Agent Name</label>
          <input name="agent_name" placeholder="e.g. Branch-NAS" required>
          <label>Agent Instance ID <span class="muted">(from the agent's peering card)</span></label>
          <input name="agent_id" placeholder="e.g. a1b2c3d4-..." required>
          <label>Agent host <span class="muted">(optional, hostname or IP; port 8787 if omitted)</span></label>
          <input name="agent_url" placeholder="agent-nas or 192.168.31.10">
          <div class="button-row">
            <button type="submit">Add agent</button>
            <button type="button" class="close-link" onclick="document.getElementById('add-agent-modal').classList.remove('open')">Cancel</button>
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
    <div class="modal-backdrop" id="update-modal">
      <div class="modal">
        <h3>Package update</h3>
        <div id="update-modal-content"></div>
      </div>
    </div>
    <div class="modal-backdrop" id="agent-update-modal">
      <div class="modal">
        <h3>Agent update</h3>
        <div id="agent-update-modal-content"></div>
      </div>
    </div>
    <div class="card footer-note">
      {html.escape(BRAND_COPYRIGHT)} | Author: {html.escape(BRAND_AUTHOR)} |
      <a href="{html.escape(BRAND_URL)}" target="_blank" rel="noopener noreferrer">EasySystems GmbH</a>
    </div>
    <script>
      (function () {{
        var bodyMeta = document.body || null;
        var uiView = bodyMeta ? (bodyMeta.getAttribute("data-ui-view") || "overview") : "overview";
        var diagView = bodyMeta ? (bodyMeta.getAttribute("data-diag-view") || "logs") : "logs";
        var logFilter = bodyMeta ? (bodyMeta.getAttribute("data-log-filter") || "all") : "all";
        var logSource = bodyMeta ? (bodyMeta.getAttribute("data-log-source") || "local") : "local";
        var qs = new URLSearchParams();
        qs.set("view", uiView);
        qs.set("diag_view", diagView);
        qs.set("log_filter", logFilter);
        qs.set("source", logSource);
        var canonicalPath = "/?" + qs.toString();
        try {{
          if (window.location.pathname !== "/" || window.location.search !== ("?" + qs.toString())) {{
            window.history.replaceState(null, "", canonicalPath);
          }}
        }} catch (e) {{
          /* ignore history API edge-cases */
        }}
        try {{
          var restoreY = sessionStorage.getItem("synmon_scroll_y");
          if (restoreY !== null) {{
            sessionStorage.removeItem("synmon_scroll_y");
            var yVal = parseInt(restoreY, 10);
            if (!isNaN(yVal) && yVal > 0) window.scrollTo(0, yVal);
          }}
        }} catch (e) {{
          /* ignore session storage errors */
        }}
        // Async fetch agent logs (avoids blocking page load when agent is unreachable)
        var logPre = document.getElementById("log-diag-pre");
        if (logPre && logPre.getAttribute("data-agent-fetch") === "1") {{
          var peerId = logPre.getAttribute("data-peer-id") || "";
          var view = logPre.getAttribute("data-view") || "logs";
          var lf = logPre.getAttribute("data-log-filter") || "all";
          if (peerId) {{
            var url = "/api/agent-diag?peer_id=" + encodeURIComponent(peerId) + "&view=" + encodeURIComponent(view) + "&log_filter=" + encodeURIComponent(lf);
            fetch(url, {{ credentials: "same-origin" }}).then(function(r) {{ return r.json(); }}).then(function(data) {{
              if (data && data.text !== undefined) logPre.textContent = data.text;
            }}).catch(function(err) {{
              logPre.textContent = "Failed to load agent logs: " + (err && err.message ? err.message : String(err));
            }});
          }}
        }}
        function ensureUiViewField(form) {{
          if (!form || !form.querySelector) return;
          if (!form.querySelector("input[name='ui_view']")) {{
            var uiInput = document.createElement("input");
            uiInput.type = "hidden";
            uiInput.name = "ui_view";
            uiInput.value = uiView;
            form.appendChild(uiInput);
          }}
        }}
        var postForms = document.querySelectorAll("form[method='post'], form[method='POST']");
        postForms.forEach(function(form) {{ ensureUiViewField(form); }});
        // Ensure source chips (Local, agent names) navigate reliably when clicked (handles subpath + edge cases)
        document.addEventListener("click", function(ev) {{
          var a = ev.target && ev.target.closest ? ev.target.closest("a.chip[href*='source=']") : null;
          if (a && a.getAttribute("href")) {{
            ev.preventDefault();
            window.location.href = a.getAttribute("href");
          }}
        }}, true);
        document.addEventListener("click", function(ev) {{
          var b = ev.target && ev.target.closest ? ev.target.closest(".server-info-action[data-server-action]") : null;
          if (!b) return;
          var key = b.getAttribute("data-server-action");
          var panel = document.querySelector(".server-action-panel[data-server-panel='" + key + "']");
          if (!panel) return;
          document.querySelectorAll(".server-action-panel.open").forEach(function(p) {{
            if (p !== panel) p.classList.remove("open");
          }});
          panel.classList.toggle("open");
          if (panel.classList.contains("open")) {{
            panel.scrollIntoView({{ behavior: "smooth", block: "nearest" }});
          }}
        }}, true);
        // Intercept POST forms: fetch and update page without reload (except auth, danger, exports)
        document.addEventListener("submit", async function(ev) {{
          var form = ev && ev.target ? ev.target : null;
          if (!form || !form.getAttribute) return;
          if ((form.getAttribute("method") || "get").toLowerCase() !== "post") return;
          if (form.id === "monitor-form") return;
          var act = (form.getAttribute("action") || "") + "";
          var skip = /\\/(auth\\/(logout|login|setup|verify-2fa|recovery|import|export))|\\/danger-(restart|reset)|\\/self-rollback/.test(act) || (form.enctype || "").toLowerCase().indexOf("multipart") >= 0;
          if (skip) return;
          ev.preventDefault();
          ev.stopImmediatePropagation();
          ensureUiViewField(form);
          var submitBtn = form.querySelector("button[type='submit']");
          if (submitBtn) {{ submitBtn.disabled = true; submitBtn.textContent = (submitBtn.textContent || "").replace(/…$/, "") + "…"; }}
          var isSelfUpdate = (act || "").indexOf("/self-update") >= 0;
          if (isSelfUpdate) {{
            var m = document.getElementById("update-modal");
            var mContent = document.getElementById("update-modal-content");
            if (m && mContent) {{
              m.classList.add("open");
              mContent.innerHTML = "<p>Updating…</p><p class='muted'>Downloading latest version, validating, replacing.</p>";
            }}
          }}
          try {{
            var fd = new FormData(form);
            var params = new URLSearchParams();
            fd.forEach(function(v, k) {{ params.append(k, v); }});
            var r = await fetch(act, {{
              method: "POST",
              headers: {{ "Content-Type": "application/x-www-form-urlencoded" }},
              body: params.toString()
            }});
            var txt = await r.text();
            if (r.redirected && (r.url || "").indexOf("auth") >= 0) {{ location.href = r.url; return; }}
            if (isSelfUpdate) {{
              var doc = new DOMParser().parseFromString(txt, "text/html");
              var errEl = doc.querySelector(".err");
              var okEl = doc.querySelector(".ok");
              var preEl = doc.querySelector("pre");
              var m = document.getElementById("update-modal");
              var mContent = document.getElementById("update-modal-content");
              if (m && mContent) {{
                var status = errEl ? (errEl.textContent || "").trim() : (okEl ? (okEl.textContent || "").trim() : "Update complete.");
                var output = preEl ? (preEl.textContent || "").trim() : "";
                mContent.innerHTML = "<p class='" + (errEl ? "err" : "ok") + "'>" + escapeHtml(status) + "</p>" + (output ? "<pre>" + escapeHtml(output) + "</pre>" : "") + "<p class='muted'>Reloading page in 5 seconds…</p>";
                setTimeout(function() {{ location.reload(); }}, 5000);
              }} else {{
                _updatePageFromResponse(txt);
              }}
            }} else {{
              _updatePageFromResponse(txt);
            }}
            var addAgentModal = document.getElementById("add-agent-modal");
            if (addAgentModal) addAgentModal.classList.remove("open");
          }} catch (e) {{
            if (isSelfUpdate) {{
              var m = document.getElementById("update-modal");
              var mContent = document.getElementById("update-modal-content");
              if (m && mContent) {{
                mContent.innerHTML = "<p class='err'>Update failed: " + escapeHtml(String(e)) + "</p><p><a href='/'>Return to overview</a></p>";
              }} else {{
                location.reload();
              }}
            }} else {{
              location.reload();
            }}
          }} finally {{
            if (submitBtn) {{ submitBtn.disabled = false; submitBtn.textContent = (submitBtn.textContent || "").replace("…", ""); }}
          }}
        }}, true);
        document.addEventListener("submit", function(ev) {{
          var form = ev && ev.target ? ev.target : null;
          if (!form || !form.getAttribute) return;
          if ((form.getAttribute("method") || "get").toLowerCase() !== "post") return;
          ensureUiViewField(form);
          try {{
            sessionStorage.setItem("synmon_scroll_y", String(Math.max(0, Math.round(window.scrollY || 0))));
          }} catch (e) {{}}
        }}, true);
        document.addEventListener("click", async function(ev) {{
          var btn = ev && ev.target ? ev.target.closest(".agent-update-btn") : null;
          if (!btn) return;
          ev.preventDefault();
          var peerId = btn.getAttribute("data-peer-id") || "";
          var peerName = btn.getAttribute("data-peer-name") || peerId;
          if (!peerId) return;
          var modal = document.getElementById("agent-update-modal");
          var mContent = document.getElementById("agent-update-modal-content");
          if (!modal || !mContent) return;
          modal.classList.add("open");
          mContent.innerHTML = "<p>Starting update on " + escapeHtml(peerName) + "…</p>";
          btn.disabled = true;
          try {{
            var r = await fetch("/agent-update", {{
              method: "POST",
              headers: {{ "Content-Type": "application/x-www-form-urlencoded" }},
              body: "peer_id=" + encodeURIComponent(peerId)
            }});
            var rawText = "";
            try {{ rawText = await r.text(); }} catch (e) {{ rawText = String(e); }}
            var data = null;
            try {{ data = rawText ? JSON.parse(rawText) : null; }} catch (e) {{}}
            var errMsg = (data && data.error) ? String(data.error) : "Failed to start update";
            var diagLines = ["HTTP " + r.status, "Error: " + errMsg];
            if (data && data.diagnostic) diagLines.push("", data.diagnostic);
            else if (rawText && rawText.length > 0) diagLines.push("", "Response: " + (rawText.length < 400 ? rawText.replace(/\\n/g, " ").trim() : rawText.substring(0, 300) + "..."));
            var diagBlock = "<div style='margin-top:10px;padding:10px;background:#0b1321;border:1px solid #283852;border-radius:8px;font-size:11px;font-family:monospace;white-space:pre-wrap;word-break:break-all;max-height:180px;overflow:auto;'>" + escapeHtml(diagLines.join("\\n")) + "</div>";
            if (!r.ok || !data || data.error) {{
              mContent.innerHTML = "<p class='err'>" + escapeHtml(errMsg) + "</p>" + diagBlock;
              mContent.innerHTML += "<p style='margin-top:12px;'><button type='button' class='close-link' onclick=\\"document.getElementById('agent-update-modal').classList.remove('open')\\">Close</button></p>";
              btn.disabled = false;
              return;
            }}
            var sessionId = data.session_id;
            if (!sessionId) {{
              mContent.innerHTML = "<p class='err'>No session ID returned</p>";
              mContent.innerHTML += "<p><button type='button' class='close-link' onclick=\\"document.getElementById('agent-update-modal').classList.remove('open')\\">Close</button></p>";
              btn.disabled = false;
              return;
            }}
            var pollInterval = setInterval(async function() {{
              try {{
                var sr = await fetch("/api/agent-update-status?peer_id=" + encodeURIComponent(peerId) + "&session_id=" + encodeURIComponent(sessionId), {{ credentials: "same-origin" }});
                var sraw = "";
                try {{ sraw = await sr.text(); }} catch (e) {{ sraw = String(e); }}
                var sdata = sr.ok && sraw ? (function() {{ try {{ return JSON.parse(sraw); }} catch(e) {{ return {{}}; }} }})() : {{}};
                if (sdata.error && !sdata.log) {{
                  var sdiagLines = ["HTTP " + sr.status, "Error: " + (sdata.error || "unknown")];
                  if (sraw && sraw.length > 0) sdiagLines.push("", "Response: " + (sraw.length < 400 ? sraw.replace(/\\n/g, " ").trim() : sraw.substring(0, 300) + "..."));
                  var sdiagBlock = "<div style='margin-top:10px;padding:10px;background:#0b1321;border:1px solid #283852;border-radius:8px;font-size:11px;font-family:monospace;white-space:pre-wrap;word-break:break-all;max-height:180px;overflow:auto;'>" + escapeHtml(sdiagLines.join("\\n")) + "</div>";
                  mContent.innerHTML = "<p class='err'>" + escapeHtml(sdata.error) + "</p>" + sdiagBlock;
                  mContent.innerHTML += "<p style='margin-top:12px;'><button type='button' class='close-link' onclick=\\"document.getElementById('agent-update-modal').classList.remove('open')\\">Close</button></p>";
                  clearInterval(pollInterval);
                  btn.disabled = false;
                  return;
                }}
                var log = sdata.log || [];
                var stage = sdata.stage || "running";
                var err = sdata.error || "";
                var html = "<p><strong>" + escapeHtml(peerName) + "</strong> – " + escapeHtml(stage) + "</p>";
                if (log.length) html += "<pre style='max-height:200px;overflow:auto;font-size:11px;'>" + escapeHtml(log.join("\\n")) + "</pre>";
                if (err) html += "<p class='err'>" + escapeHtml(err) + "</p>";
                mContent.innerHTML = html;
                if (stage === "done" || stage === "failed") {{
                  clearInterval(pollInterval);
                  html += (stage === "done" ? "<p class='ok'>Update complete. Agent may restart.</p>" : "<p class='err'>Update failed.</p>");
                  html += "<p><button type='button' class='close-link' onclick=\\"document.getElementById('agent-update-modal').classList.remove('open')\\">Close</button></p>";
                  mContent.innerHTML = html;
                  btn.disabled = false;
                  if (stage === "done") setTimeout(function() {{ refreshLive && refreshLive(); }}, 3000);
                }}
              }} catch (e) {{
                mContent.innerHTML += "<p class='err'>Poll error: " + escapeHtml(String(e)) + "</p>";
              }}
            }}, 600);
          }} catch (e) {{
            mContent.innerHTML = "<p class='err'>" + escapeHtml(String(e)) + "</p>";
            mContent.innerHTML += "<p><button type='button' class='close-link' onclick=\\"document.getElementById('agent-update-modal').classList.remove('open')\\">Close</button></p>";
            btn.disabled = false;
          }}
        }}, true);
        var modeEl = document.getElementById("check_mode");
        var nameEl = document.getElementById("name");
        var probeHostWrap = document.getElementById("probe-host-wrap");
        var probePortWrap = document.getElementById("probe-port-wrap");
        var dnsNameWrap = document.getElementById("dns-name-wrap");
        var dnsServerWrap = document.getElementById("dns-server-wrap");
        if (modeEl && nameEl) {{
          function toggleProbeFields() {{
            var selected = modeEl.value || "smart";
            var showHost = (selected === "ping" || selected === "port");
            var showPort = (selected === "port");
            var showDns = (selected === "dns");
            if (probeHostWrap) {{ probeHostWrap.style.display = showHost ? "block" : "none"; var inp = probeHostWrap.querySelector("input"); if (inp) inp.disabled = !showHost; }}
            if (probePortWrap) {{ probePortWrap.style.display = showPort ? "block" : "none"; var inp = probePortWrap.querySelector("input"); if (inp) inp.disabled = !showPort; }}
            if (dnsNameWrap) {{ dnsNameWrap.style.display = showDns ? "block" : "none"; var inp = dnsNameWrap.querySelector("input"); if (inp) inp.disabled = !showDns; }}
            if (dnsServerWrap) {{ dnsServerWrap.style.display = showDns ? "block" : "none"; var inp = dnsServerWrap.querySelector("input"); if (inp) inp.disabled = !showDns; }}
          }}
          function autoName() {{
            var selected = modeEl.value || "smart";
            var defaultName = selected + "-unix-check";
            var current = (nameEl.value || "").trim();
            var known = ["smart-unix-check", "storage-unix-check", "ping-unix-check", "port-unix-check", "dns-unix-check", "backup-unix-check", "unix-main"];
            if (!current || known.indexOf(current) >= 0) nameEl.value = defaultName;
            toggleProbeFields();
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
      async function monitorAction(url, name, btn) {{
        var orig = btn.textContent;
        btn.disabled = true;
        btn.textContent = orig + "…";
        try {{
          var body = "monitor_name=" + encodeURIComponent(name);
          var r = await fetch(url, {{
            method: "POST",
            headers: {{ "Content-Type": "application/x-www-form-urlencoded" }},
            body: body
          }});
          if (url === "/delete-monitor" && r.ok) {{
            var card = btn.closest(".monitor-card");
            if (card) card.remove();
          }}
          if (url === "/edit-monitor" && r.ok) {{
            _injectModal(await r.text());
            return;
          }}
          await refreshLive();
        }} catch (e) {{
          /* ignore */
        }} finally {{
          btn.disabled = false;
          btn.textContent = orig;
        }}
      }}

      async function openModal(url, btn) {{
        var orig = btn.textContent;
        btn.disabled = true;
        btn.textContent = orig + "…";
        try {{
          var r = await fetch(url, {{
            method: "POST",
            headers: {{ "Content-Type": "application/x-www-form-urlencoded" }},
            body: ""
          }});
          if (r.ok) _injectModal(await r.text());
        }} catch (e) {{
          /* ignore */
        }} finally {{
          btn.disabled = false;
          btn.textContent = orig;
        }}
      }}

      window.monitorAction = monitorAction;
      window.openModal = openModal;

      function _updatePageFromResponse(txt) {{
        var doc = new DOMParser().parseFromString(txt, "text/html");
        var newContainer = doc.querySelector(".container");
        var newBody = doc.querySelector("body");
        var curContainer = document.querySelector(".container");
        if (newContainer && curContainer) {{
          curContainer.innerHTML = newContainer.innerHTML;
          if (newBody) {{
            ["data-ui-view", "data-diag-view", "data-log-filter", "data-log-source", "data-form-error"].forEach(function(attr) {{
              var v = newBody.getAttribute(attr);
              if (v !== null) document.body.setAttribute(attr, v);
            }});
          }}
          try {{
            var path = window.location.pathname || "/";
            var view = (newBody && newBody.getAttribute("data-ui-view")) || new URLSearchParams(window.location.search).get("view") || "overview";
            history.replaceState({{}}, "", path + "?view=" + view);
          }} catch (e) {{}}
          _hookModalSave();
          if (typeof refreshLive === "function") refreshLive();
        }}
      }}

      function _injectModal(html) {{
        var doc = new DOMParser().parseFromString(html, "text/html");
        var modal = doc.querySelector(".modal-backdrop.open");
        if (modal) {{
          var existing = document.getElementById("monitor-modal");
          if (existing) existing.remove();
          document.body.insertAdjacentHTML("beforeend", modal.outerHTML);
          _hookModalSave();
        }}
      }}

      function _hookModalSave() {{
        var modal = document.getElementById("monitor-modal");
        if (!modal) return;
        var modeEl = modal.querySelector("#check_mode");
        var phw = modal.querySelector("#probe-host-wrap");
        var ppw = modal.querySelector("#probe-port-wrap");
        var dnw = modal.querySelector("#dns-name-wrap");
        var dsw = modal.querySelector("#dns-server-wrap");
        function _toggleFields() {{
          if (!modeEl) return;
          var m = modeEl.value || "smart";
          var showHost = (m === "ping" || m === "port");
          var showPort = (m === "port");
          var showDns = (m === "dns");
          if (phw) {{ phw.style.display = showHost ? "block" : "none"; var inp = phw.querySelector("input"); if (inp) inp.disabled = !showHost; }}
          if (ppw) {{ ppw.style.display = showPort ? "block" : "none"; var inp = ppw.querySelector("input"); if (inp) inp.disabled = !showPort; }}
          if (dnw) {{ dnw.style.display = showDns ? "block" : "none"; var inp = dnw.querySelector("input"); if (inp) inp.disabled = !showDns; }}
          if (dsw) {{ dsw.style.display = showDns ? "block" : "none"; var inp = dsw.querySelector("input"); if (inp) inp.disabled = !showDns; }}
        }}
        var nameEl = modal.querySelector("#name");
        var autoNames = ["smart-unix-check","storage-unix-check","ping-unix-check","port-unix-check","dns-unix-check","backup-unix-check","unix-main"];
        function _autoName() {{
          if (!modeEl || !nameEl) return;
          var cur = (nameEl.value || "").trim();
          if (!cur || autoNames.indexOf(cur) >= 0) {{
            nameEl.value = (modeEl.value || "smart") + "-unix-check";
          }}
          _toggleFields();
        }}
        if (modeEl) {{
          modeEl.addEventListener("change", _autoName);
          _autoName();
        }}
        var targetEl = modal.querySelector("#target_peer");
        var agentInfo = modal.querySelector("#agent-kuma-info");
        function _onTarget() {{
          if (!targetEl || !agentInfo) return;
          agentInfo.style.display = (targetEl.value && targetEl.value !== "local") ? "block" : "none";
        }}
        if (targetEl) {{
          targetEl.addEventListener("change", _onTarget);
          _onTarget();
        }}
        var form = modal.querySelector("form");
        if (!form) return;
        var errEl = form.querySelector("#monitor-form-error");
        function showFormError(msg) {{
          if (errEl) {{ errEl.textContent = msg || ""; errEl.classList.toggle("show", !!msg); }}
        }}
        form.addEventListener("submit", function (e) {{
          showFormError("");
          var name = (form.querySelector("#name") || {{}}).value.trim();
          var kumaUrl = (form.querySelector("input[name='kuma_url']") || {{}}).value.trim();
          var mode = (form.querySelector("#check_mode") || {{}}).value || "smart";
          var probeHost = (form.querySelector("input[name='probe_host']") || {{}}).value.trim();
          var probePort = parseInt((form.querySelector("input[name='probe_port']") || {{}}).value, 10) || 0;
          var dnsName = (form.querySelector("input[name='dns_name']") || {{}}).value.trim();
          if (!name || name.length < 2) {{
            e.preventDefault();
            showFormError("Monitor name is required (min 2 characters).");
            return;
          }}
          if (!kumaUrl) {{
            e.preventDefault();
            showFormError("Kuma Push URL is required.");
            return;
          }}
          var urlCheck = kumaUrl;
          if (!urlCheck.match(/^https?:\\/\\//i)) urlCheck = "https://" + urlCheck;
          try {{
            var pu = new URL(urlCheck);
            if (!pu.hostname) {{ e.preventDefault(); showFormError("Kuma Push URL must include a hostname."); return; }}
            if (!/^\\/api\\/push\\/[A-Za-z0-9_-]+$/.test(pu.pathname)) {{
              e.preventDefault();
              showFormError("Kuma Push URL path must be /api/push/TOKEN (e.g. https://kuma.example.com/api/push/abc123).");
              return;
            }}
          }} catch (uerr) {{
            e.preventDefault();
            showFormError("Kuma Push URL is invalid.");
            return;
          }}
          if (mode === "ping" && !probeHost) {{
            e.preventDefault();
            showFormError("Ping mode requires a probe host.");
            return;
          }}
          if (mode === "port") {{
            if (!probeHost) {{ e.preventDefault(); showFormError("Port mode requires a probe host."); return; }}
            if (probePort < 1 || probePort > 65535) {{ e.preventDefault(); showFormError("Port mode requires a valid TCP port (1-65535)."); return; }}
          }}
          if (mode === "dns" && !dnsName) {{
            e.preventDefault();
            showFormError("DNS mode requires a DNS name/domain.");
            return;
          }}
          ensureUiViewField(form);
        }});
      }}
      _hookModalSave();
      window._onTargetChange = function() {{
        var sel = document.getElementById("target_peer");
        var info = document.getElementById("agent-kuma-info");
        if (!sel || !info) return;
        info.style.display = (sel.value && sel.value !== "local") ? "block" : "none";
      }};
      if (document.getElementById("target_peer")) window._onTargetChange();

      window._openAddAgent = function(btn) {{
        var m = document.getElementById("add-agent-modal");
        if (m) m.classList.add("open");
      }};
      (function() {{
        var agentModal = document.getElementById("add-agent-modal");
        if (!agentModal) return;
        var form = agentModal.querySelector("form");
        if (!form) return;
        form.addEventListener("submit", async function(e) {{
          e.preventDefault();
          var submitBtn = form.querySelector("button[type='submit']");
          if (submitBtn) {{ submitBtn.disabled = true; submitBtn.textContent += "\u2026"; }}
          try {{
            var fd = new FormData(form);
            var params = new URLSearchParams();
            fd.forEach(function(v, k) {{ params.append(k, v); }});
            var r = await fetch(form.action, {{
              method: "POST",
              headers: {{ "Content-Type": "application/x-www-form-urlencoded" }},
              body: params.toString()
            }});
            if (r.ok) {{
              agentModal.classList.remove("open");
              form.reset();
              await refreshLive();
              location.reload();
            }}
          }} catch(ex) {{}}
          finally {{
            if (submitBtn) {{ submitBtn.disabled = false; submitBtn.textContent = submitBtn.textContent.replace("\u2026",""); }}
          }}
        }});
      }})();

      var prevChannelTs = {{}};
      var prevMonitorTs = {{}};
      var selectedHighlight = "{html.escape(highlight_channel)}";

      function applyLiveSnapshot(data) {{
        if (!data || !data.channels || !data.monitors) return;
        Object.keys(data.channels || {{}}).forEach(function (channel) {{
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
          if (selectedHighlight === "smart") hit = (mode === "smart");
          if (selectedHighlight === "storage") hit = (mode === "storage");
          if (selectedHighlight === "ping") hit = (mode === "ping");
          if (selectedHighlight === "port") hit = (mode === "port");
          if (selectedHighlight === "dns") hit = (mode === "dns");
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
            var originTag = (m.origin && m.origin !== "local") ? " | Origin: " + m.origin : "";
            primary.textContent = "Mode: " + (m.mode || "smart") + " | Last ping: " + ping + " ms | Last run: " + tsText(m.ts || 0) + originTag;
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

        var peerPanel = document.getElementById("peer-live-panel");
        if (peerPanel && data.peers) {{
          var onlineCount = 0, offlineCount = 0, remoteMon = 0;
          data.peers.forEach(function(p) {{
            if (p.status === "online") onlineCount++; else offlineCount++;
            remoteMon += (p.monitor_count || 0);
          }});
          var ob = document.getElementById("peer-online-badge");
          var fb = document.getElementById("peer-offline-badge");
          var rc = document.getElementById("peer-remote-count");
          if (ob) ob.textContent = onlineCount + " online";
          if (fb) {{ fb.textContent = offlineCount + " offline"; fb.style.display = offlineCount ? "" : "none"; }}
          if (rc) rc.textContent = "Remote monitors: " + remoteMon;
          if (data.peers.length) {{
            var defPort = 8787;
            function peerUrlForInput(u) {{
              if (!u) return "";
              var m = u.match(/^(.+):(\\d+)$/);
              if (m && parseInt(m[2], 10) === defPort) return m[1];
              return u;
            }}
            var ph = data.peers.map(function (p) {{
              var cls = p.status === "online" ? "ok" : "err";
              var latTxt = p.latency_ms ? p.latency_ms + " ms" : "-";
              var seenTxt = tsText(p.last_seen || 0);
              var pUrl = p.url || "";
              var openUrl = p.open_url || (pUrl && pUrl.indexOf("://") >= 0 ? pUrl : (pUrl ? "http://" + pUrl : ""));
              var pUrlDisplay = peerUrlForInput(pUrl);
              var pid = escapeHtml(p.instance_id || "");
              var pbs = "padding:6px 12px;font-size:12px;border-radius:8px;font-weight:600;white-space:nowrap;cursor:pointer;line-height:1.2;border:1px solid #36517a;background:transparent;color:#c8dbf8;";
              var openBtn = openUrl
                ? "<a href='" + escapeHtml(openUrl) + "' target='_blank' rel='noopener noreferrer' style='" + pbs + "text-decoration:none;display:inline-block;text-align:center;'>Open</a>"
                : "";
              var removeBtn = "<form method='post' action='/peer/remove' style='margin:0;'>"
                + "<input type='hidden' name='peer_id' value='" + pid + "'>"
                + "<button type='submit' onclick='return confirm(&#39;Remove this agent?&#39;)' "
                + "style='" + pbs + "border-color:#ef4444;color:#ef4444;'>Remove</button></form>";
              var versionBadge = p.version ? "<span class='badge muted-badge' data-role='peer-version'>v" + escapeHtml(p.version) + "</span>" : "";
              var syncedTime = seenTxt.split(" ").pop();
              var syncedBadge = "<span class='badge muted-badge' data-role='peer-synced'>Synced: " + syncedTime + "</span>";
              return "<div class='peer-row' data-peer-id='" + pid + "' data-peer-url='" + escapeHtml(pUrl) + "' "
                + "style='border:1px solid rgba(42,61,90,.35);border-radius:8px;background:rgba(15,23,38,.6);padding:10px 12px;margin-bottom:8px;'>"
                + "<div style='display:flex;align-items:center;gap:10px;flex-wrap:wrap;'>"
                + "<span class='badge " + cls + "' style='min-width:56px;text-align:center;'>" + escapeHtml(p.status) + "</span>"
                + "<strong style='flex:1;font-size:13px;'>" + escapeHtml(p.instance_name || p.instance_id || "?") + "</strong>"
                + syncedBadge
                + "<span class='badge muted-badge' data-role='peer-monitors'>" + (p.monitor_count || 0) + " monitors</span>"
                + versionBadge
                + "</div>"
                + "<div style='display:flex;align-items:center;gap:8px;margin-top:6px;'>"
                + "<span class='muted' style='font-size:11px;'>Last seen: " + syncedTime + " (" + latTxt + ")</span>"
                + "<span class='muted' style='font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>" + escapeHtml(pUrl || "no URL") + "</span>"
                + "</div>"
                + "<div style='display:flex;align-items:center;gap:6px;margin-top:8px;'>"
                + "<form method='post' action='/peer/update-peer-url' style='margin:0;display:flex;gap:4px;flex:1;'>"
                + "<input type='hidden' name='peer_id' value='" + pid + "'>"
                + "<input name='peer_url' value='" + escapeHtml(pUrlDisplay) + "' placeholder='agent-nas or 192.168.31.10' style='flex:1;padding:4px 6px;font-size:11px;'>"
                + "<button type='submit' style='" + pbs + "'>Set URL</button>"
                + "</form>"
                + "<form method='post' action='/peer/sync-one' style='margin:0;'>"
                + "<input type='hidden' name='peer_id' value='" + pid + "'>"
                + "<button type='submit' style='" + pbs + "'>Sync</button>"
                + "</form>"
                + "<button type='button' class='agent-update-btn' data-peer-id='" + escapeHtml(p.instance_id || "") + "' data-peer-name='" + escapeHtml(p.instance_name || p.instance_id || "?") + "' style='" + pbs + "'>Update</button>"
                + openBtn
                + removeBtn
                + "</div></div>";
            }}).join("");
            peerPanel.innerHTML = ph;
          }}
        }}
      }}

      async function refreshLive() {{
        try {{
          var srcEl = document.querySelector(".container[data-source]");
          var activeSource = (srcEl && srcEl.getAttribute("data-source")) ? srcEl.getAttribute("data-source") : "local";
          var r = await fetch("/status-json?source=" + encodeURIComponent(activeSource), {{ cache: "no-store" }});
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
    try:
        cfg = load_config()
        browser_instance_name = str(cfg.get("instance_name", "") or "").strip()
    except Exception:
        browser_instance_name = ""
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
  <link rel="icon" type="image/png" href="{html.escape(BRAND_FAVICON_URL)}">
  <title>{(html.escape(browser_instance_name) + " - ") if browser_instance_name else ""}{html.escape(PRODUCT_NAME)} - Security</title>
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
    button, .btn {{ border:1px solid #36517a; border-radius:8px; padding:9px 14px; background:transparent; color:#c8dbf8; font-weight:600; font-size:13px; cursor:pointer; text-decoration:none; }}
    button:hover, .btn:hover {{ background:rgba(54,81,122,.25); }}
    .btn.secondary {{ background:transparent; border-color:#36517a; color:#c8dbf8; }}
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
        <div class="hero-tagline">All-in-one Unix monitoring: SMART, storage, backup, ping, port, DNS, secure peering, and instant Uptime Kuma alerts.</div>
        <div class="muted" style="text-align:center;margin-top:10px;">Recommendation: publish this UI behind reverse proxy with HTTPS.</div>
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
        <div style="margin-top:10px;"><b>TOTP Secret</b><br><code id="totp-secret">{html.escape(str(provision.get("totp_secret", "")))}</code></div>
        <div class="muted">If QR is unavailable, add this secret manually in your authenticator app.</div>
        <div class="button-row">
          <button type="button" class="btn secondary" onclick="copyTotpSecret(this)">Copy TOTP Secret</button>
        </div>
        <div style="margin-top:10px;"><b>Recovery Codes (shown once)</b></div>
        <pre id="recovery-codes">{html.escape(recovery_codes_text)}</pre>
        <div class="button-row">
          <button type="button" class="btn secondary" onclick="copyRecoveryCodes(this)">Copy Recovery Codes</button>
        </div>
        <div class="button-row">
          <a class="btn" href="/auth/login">Continue to Login</a>
        </div>
        <script>
        function copyText(text) {{
          if (navigator.clipboard && window.isSecureContext) {{
            return navigator.clipboard.writeText(text);
          }}
          return new Promise(function(resolve, reject) {{
            try {{
              var ta = document.createElement('textarea');
              ta.value = text;
              ta.setAttribute('readonly', '');
              ta.style.position = 'fixed';
              ta.style.opacity = '0';
              ta.style.left = '-9999px';
              document.body.appendChild(ta);
              ta.focus();
              ta.select();
              var ok = document.execCommand('copy');
              document.body.removeChild(ta);
              if (ok) resolve();
              else reject(new Error('copy command failed'));
            }} catch (e) {{
              reject(e);
            }}
          }});
        }}
        function copyTotpSecret(btn) {{
          var el = document.getElementById('totp-secret');
          if (!el) return;
          copyText(el.textContent || '').then(function() {{
            var t = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(function() {{ btn.textContent = t; }}, 1500);
          }}).catch(function() {{
            alert('Failed to copy. Please copy manually from the field.');
          }});
        }}
        function copyRecoveryCodes(btn) {{
          var el = document.getElementById('recovery-codes');
          if (!el) return;
          copyText((el.textContent || '').trim()).then(function() {{
            var t = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(function() {{ btn.textContent = t; }}, 1500);
          }}).catch(function() {{
            alert('Failed to copy. Please copy manually from the field.');
          }});
        }}
        </script>
        """
    body = (
        provision_html
        if provision
        else """
        <form method="post" action="/auth/setup">
          <input type="hidden" name="username" value="admin" autocomplete="username">
          <label>Create admin password</label>
          <input name="password" type="password" autocomplete="new-password" minlength="10" required>
          <label>Confirm password</label>
          <input name="password_confirm" type="password" autocomplete="new-password" minlength="10" required>
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
      <input type="hidden" name="username" value="admin" autocomplete="username">
      <label>Admin password</label>
      <input name="password" type="password" autocomplete="current-password" required>
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
      <input name="token" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required>
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
        mode = str(m.get("check_mode", "smart")).lower()
        if mode not in CHECK_MODES:
            mode = "smart"
        devices = [str(x) for x in m.get("devices", [])]
        url = m.get("kuma_url", "")
        if not url:
            line = f"x {name}: no Kuma URL"
            lines.append(line)
            _set_monitor_state(str(name), "Monitor check failed", line, level="err")
            append_ui_log(f"run-check | {name} | no Kuma URL")
            continue
        status, msg, lat = check_host_with_monitor(mode, devices, monitor=m, debug=dbg)
        ok = push_to_kuma(url, status, msg, lat, debug=dbg)
        recorded_status = status if ok else "warning"
        _record_history(str(name), mode, recorded_status, lat)
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
    if not target_monitor:
        role = str(cfg.get("peer_role", "")).lower()
        if role == "agent":
            try:
                sync_msg = _peer_push_to_master(cfg)
                lines.append(f"[peer-sync] {sync_msg}")
                append_ui_log(f"peer-sync | {sync_msg}")
            except Exception as e:
                lines.append(f"[peer-sync] error: {e}")
                append_ui_log(f"peer-sync | error: {type(e).__name__}: {e}")
        elif role == "master":
            try:
                sync_msg = _peer_sync_from_master(load_config())
                lines.append(f"[peer-sync] {sync_msg}")
                append_ui_log(f"peer-sync | master auto-sync: {sync_msg}")
            except Exception as e:
                lines.append(f"[peer-sync] error: {e}")
                append_ui_log(f"peer-sync | error: {type(e).__name__}: {e}")
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
    lines: List[str] = []
    for m in monitors:
        source_platform = _monitor_source_platform(m)
        flavor = "synology-monitor" if source_platform == "synology" else "unix-monitor"
        msg = f"Test push @ {now} - {BRAND_NAME} {flavor} connectivity check"
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
    _trigger_peer_sync_bg(cfg)
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
    cfg = load_config()
    details: List[str] = []
    backend = str(cfg.get("scheduler_backend", "cron")).strip().lower()
    if backend not in ("systemd", "cron"):
        backend = "cron"
    service_script = _scheduler_service_path()
    if service_script.exists():
        rc, out = _run_cmd([str(service_script), "start"], timeout_sec=12)
        details.append(f"service start rc={rc}")
        if out.strip():
            details.append(out.strip().replace("\n", " ")[:240])
    else:
        details.append(f"service script missing: {service_script}")

    if backend == "systemd":
        if not Path("/run/systemd/system").exists():
            details.append("systemd backend selected but systemd runtime not detected.")
        else:
            for unit in (
                "unix-monitor-scheduler.timer",
                "unix-monitor-smart-helper.timer",
                "unix-monitor-backup-helper.timer",
                "unix-monitor-system-log-helper.timer",
            ):
                rc, out = _run_cmd(["systemctl", "enable", "--now", unit], timeout_sec=15)
                details.append(f"{unit}: {'ok' if rc == 0 else f'failed rc={rc}'}")
                if rc != 0 and out.strip():
                    details.append(out.strip().replace("\n", " ")[:240])
            rc, out = _run_cmd(["systemctl", "start", "unix-monitor-scheduler.service"], timeout_sec=20)
            details.append(f"unix-monitor-scheduler.service start: {'ok' if rc == 0 else f'failed rc={rc}'}")
            if rc != 0 and out.strip():
                details.append(out.strip().replace("\n", " ")[:240])
    else:
        # Cron backend: install deterministic entries based on the active script path.
        helper = str(get_smart_helper_script_path())
        interval = int(cfg.get("cron_interval_minutes", 60) or 60)
        sched_line = build_cron_line(get_script_path(), interval)
        helper_line = f"*/5 * * * * {helper} # unix-monitor smart helper auto"
        for line in (helper_line, sched_line):
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


class _DualProtocolSocket:
    """Wraps a server socket to auto-detect TLS vs plain HTTP on the same port.

    On each accepted connection, peeks at the first byte:
      - 0x16 (TLS ClientHello) -> wrap with the provided SSL context
      - Anything else (plain HTTP) -> leave unwrapped, handler will redirect to HTTPS
    """

    def __init__(self, raw_socket: socket.socket, ssl_ctx: ssl.SSLContext):
        self._raw = raw_socket
        self._ctx = ssl_ctx

    def accept(self) -> Tuple[socket.socket, Any]:
        conn, addr = self._raw.accept()
        try:
            conn.settimeout(5.0)
            first = conn.recv(1, socket.MSG_PEEK)
            if first and first[0] == 0x16:
                conn = self._ctx.wrap_socket(conn, server_side=True)
        except Exception:
            pass
        return conn, addr

    def fileno(self) -> int:
        return self._raw.fileno()

    def close(self) -> None:
        return self._raw.close()

    def getsockname(self) -> Any:
        return self._raw.getsockname()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


def run_setup_ui(host: str = "0.0.0.0", port: int = 8787) -> int:
    class Handler(BaseHTTPRequestHandler):
        _tls_available = False

        def _client_source_ip(self) -> str:
            xff = str(self.headers.get("X-Forwarded-For", "") or "").strip()
            if xff:
                first = xff.split(",")[0].strip()
                if first:
                    return first
            xrip = str(self.headers.get("X-Real-IP", "") or "").strip()
            if xrip:
                return xrip
            try:
                return str(self.client_address[0] or "").strip() or "unknown"
            except Exception:
                return "unknown"

        def _redirect_http_to_https(self) -> bool:
            """If TLS is active but this request arrived over plain HTTP, redirect to HTTPS.
            Returns True if redirect was sent (caller should return), False otherwise.
            Peer API paths are exempt -- they use application-layer security.
            Requests arriving through a reverse proxy are exempt -- the proxy handles TLS.
            Raw IP access is exempt -- redirecting http://IP:port to https://IP:port can cause
            ERR_SSL_PROTOCOL_ERROR when TLS later becomes unavailable (certs removed, reinstall)."""
            if not self._tls_available:
                return False
            if isinstance(self.connection, ssl.SSLSocket):
                return False
            if self.path.startswith("/api/peer/"):
                return False
            fwd_proto = (self.headers.get("X-Forwarded-Proto", "") or
                         self.headers.get("X-Forwarded-Protocol", "")).lower()
            if fwd_proto:
                return False
            if self.headers.get("X-Forwarded-For") or self.headers.get("X-Real-IP"):
                return False
            host = self.headers.get("Host", "")
            if not host:
                host = f"localhost:{self.server.server_address[1]}"
            hostname = (host.split("]:")[0].lstrip("[") if "]" in host else host).split(":")[0]
            if not hostname:
                return False
            if (hostname in ("localhost", "127.0.0.1") or
                    re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) or
                    ":" in hostname):
                return False
            location = f"https://{host}{self.path}"
            self.send_response(301)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return True

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
            if isinstance(self.connection, ssl.SSLSocket):
                morsel[name]["secure"] = True
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
            if isinstance(self.connection, ssl.SSLSocket):
                return ""
            forwarded = (self.headers.get("X-Forwarded-Proto", "") or self.headers.get("X-Forwarded-Protocol", "")).lower()
            if "https" in forwarded:
                return ""
            host = self.headers.get("Host", "")
            return (
                f"Connection appears to be plain HTTP ({host or 'direct access'}). "
                "Use reverse proxy with HTTPS to protect login credentials and 2FA codes."
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

        def _verify_peer_token(self) -> bool:
            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return False
            token = auth_header[7:].strip()
            if not token:
                return False
            cfg = load_config()
            expected = str(cfg.get("peering_token", "") or "").strip()
            if not expected:
                return False
            return hmac.compare_digest(token, expected)

        def _peer_mtls_enforced(self) -> bool:
            cfg = load_config()
            cert, key, ca = _get_mtls_cert_paths(cfg)
            return bool(cert and key and ca)

        def _peer_client_cert_present(self) -> bool:
            if not isinstance(self.connection, ssl.SSLSocket):
                return False
            try:
                cert = self.connection.getpeercert()
                return bool(cert)
            except Exception:
                return False

        def _require_peer_mtls(self, allow_token_only: bool = False) -> bool:
            if allow_token_only or not self._peer_mtls_enforced():
                return True
            if self._peer_client_cert_present():
                return True
            self._reply_json({"error": "mTLS client certificate required"}, 401)
            return False

        def _read_peer_body(self) -> Tuple[str, bool]:
            raw_len = int(self.headers.get("Content-Length", "0"))
            body_raw = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
            if isinstance(self.connection, ssl.SSLSocket):
                return body_raw, True
            if not body_raw:
                return body_raw, True
            try:
                wrapped = json.loads(body_raw)
            except (json.JSONDecodeError, ValueError):
                return body_raw, True
            if not isinstance(wrapped, dict) or not isinstance(wrapped.get("enc"), str):
                return body_raw, True
            cfg = load_config()
            token = str(cfg.get("peering_token", "") or "").strip()
            if not token:
                return "", False
            dec = _decrypt_payload(str(wrapped.get("enc", "")), token)
            if dec is None:
                return "", False
            return dec, True

        def _reply_peer_json(self, data: Dict[str, Any], code: int = 200) -> None:
            if isinstance(self.connection, ssl.SSLSocket):
                self._reply_json(data, code)
                return
            cfg = load_config()
            token = str(cfg.get("peering_token", "") or "").strip()
            if not token:
                self._reply_json(data, code)
                return
            payload = json.dumps({"enc": _encrypt_payload(json.dumps(data), token)}).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Peer-Encrypted", "1")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _check_get_signature(self) -> None:
            """Best-effort signature verification for GET peer requests (empty body)."""
            sig = self.headers.get("X-Peer-Sig", "")
            if sig:
                sig_headers = {
                    "X-Peer-Sig": sig,
                    "X-Peer-Ts": self.headers.get("X-Peer-Ts", ""),
                    "X-Peer-Nonce": self.headers.get("X-Peer-Nonce", ""),
                    "X-Peer-Id": self.headers.get("X-Peer-Id", ""),
                }
                vfy_cfg = load_config()
                valid, vmsg = _verify_peer_signature(sig_headers, b"", vfy_cfg)
                if valid:
                    append_ui_log(f"peer-sig | GET verified: {vmsg}")
                else:
                    append_ui_log(f"peer-sig | GET signature failed: {vmsg}")

        def do_GET(self) -> None:  # noqa: N802
            if self._redirect_http_to_https():
                return
            parsed = urlparse(self.path)
            if parsed.path == "/connection-info":
                port = self.server.server_address[1]
                host = self.headers.get("Host", "").split(":")[0] or "localhost"
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Access-Control-Allow-Origin", "*")
                info = {
                    "tls_available": bool(Handler._tls_available),
                    "port": port,
                    "over_tls": isinstance(self.connection, ssl.SSLSocket),
                    "suggestion": (
                        "Use https:// when TLS is available."
                        if Handler._tls_available
                        else "Server is HTTP-only. Use http:// explicitly. If your browser forces HTTPS (HSTS), try another browser or clear site data."
                    ),
                }
                self.end_headers()
                self.wfile.write(json.dumps(info).encode("utf-8"))
                return
            if parsed.path == "/api/peer/health":
                if not self._require_peer_mtls():
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                self._check_get_signature()
                cfg = load_config()
                mtls_status = _get_mtls_security_status(cfg)
                self._reply_peer_json({
                    "status": "ok",
                    "instance_id": _get_instance_id(cfg),
                    "instance_name": str(cfg.get("instance_name", "") or ""),
                    "version": VERSION,
                    "role": str(cfg.get("peer_role", "standalone") or "standalone"),
                    "monitor_count": len(cfg.get("monitors", [])),
                    "ts": int(time.time()),
                    "signing_active": mtls_status.get("signing_active", False),
                }, 200)
                return
            if parsed.path == "/api/peer/snapshot":
                if not self._require_peer_mtls():
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                self._check_get_signature()
                cfg = load_config()
                history = _load_history()
                state = _load_monitor_state()
                self._reply_peer_json({
                    "instance_id": _get_instance_id(cfg),
                    "instance_name": str(cfg.get("instance_name", "") or ""),
                    "version": VERSION,
                    "monitors": cfg.get("monitors", []),
                    "history": history[-200:],
                    "state": state,
                    "pushed_at": int(time.time()),
                }, 200)
                return
            if parsed.path == "/api/peer/config":
                if not self._require_peer_mtls():
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                self._check_get_signature()
                cfg = load_config()
                safe_cfg = {
                    "cron_enabled": bool(cfg.get("cron_enabled", False)),
                    "cron_interval_minutes": int(cfg.get("cron_interval_minutes", 60) or 60),
                    "instance_id": _get_instance_id(cfg),
                    "instance_name": str(cfg.get("instance_name", "") or ""),
                    "peer_role": str(cfg.get("peer_role", "standalone") or "standalone"),
                }
                self._reply_peer_json(safe_cfg, 200)
                return
            if parsed.path == "/api/peer/diag":
                if not self._require_peer_mtls(allow_token_only=True):
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                self._check_get_signature()
                qs = parse_qs(parsed.query)
                view = str(qs.get("view", ["logs"])[0] or "logs").strip().lower()
                lf = str(qs.get("log_filter", ["all"])[0] or "all").strip().lower()
                cfg = load_config()
                history = _load_history()
                text = _build_diag_text(cfg, history, diag_view=view, log_filter=lf)
                self._reply_peer_json({"text": text}, 200)
                return
            if parsed.path == "/api/peer/update-status":
                if not self._require_peer_mtls(allow_token_only=True):
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                self._check_get_signature()
                qs = parse_qs(parsed.query)
                session_id = str(qs.get("session_id", [""])[0] or "").strip()
                sess = _load_agent_update_session()
                if not session_id or sess.get("session_id") != session_id:
                    self._reply_peer_json({"error": "session not found", "stage": "unknown"}, 404)
                    return
                self._reply_peer_json({
                    "session_id": sess.get("session_id"),
                    "stage": sess.get("stage", "unknown"),
                    "log": sess.get("log", []),
                    "error": sess.get("error"),
                    "started_at": sess.get("started_at"),
                    "updated_at": sess.get("updated_at"),
                }, 200)
                return
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
                            "check_mode": str(m.get("check_mode", "smart")),
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
                    extra_headers=[("Content-Disposition", 'attachment; filename="unix-monitor-settings-export.json"')],
                )
                return
            if not _auth_initialized(auth):
                self._redirect("/auth/setup")
                return
            if not self._is_authenticated():
                self._redirect("/auth/login")
                return
            if parsed.path == "/status-json":
                qs = parse_qs(parsed.query)
                source_ctx = (qs.get("source", ["local"])[0] or "local").strip()
                self._reply_json(_build_live_snapshot_for_source(source_ctx), 200)
                return
            if parsed.path == "/api/agent-update-status":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                qs = parse_qs(parsed.query)
                peer_id = (qs.get("peer_id", [""])[0] or "").strip()
                session_id = (qs.get("session_id", [""])[0] or "").strip()
                if not peer_id or not session_id:
                    self._reply_json({"error": "Missing peer_id or session_id"}, 400)
                    return
                cfg = load_config()
                if str(cfg.get("peer_role", "")) != "master":
                    self._reply_json({"error": "Master role required"}, 403)
                    return
                data = _fetch_agent_update_status(cfg, peer_id, session_id)
                self._reply_json(data, 200)
                return
            if parsed.path == "/api/agent-diag":
                qs = parse_qs(parsed.query)
                peer_id = (qs.get("peer_id", [""])[0] or "").strip()
                view = (qs.get("view", ["logs"])[0] or "logs").strip().lower()
                log_filter = (qs.get("log_filter", ["all"])[0] or "all").strip().lower()
                if not peer_id:
                    self._reply_json({"error": "Missing peer_id"}, 400)
                    return
                cfg = load_config()
                text = _fetch_agent_diag(
                    cfg,
                    peer_id,
                    view,
                    log_filter,
                    resolve_timeout=5,
                    fetch_timeout=10,
                )
                self._reply_json({"text": text}, 200)
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
            source_ctx = (qs.get("source", [qs.get("log_source", ["local"])[0]])[0] or "local").strip()
            diagnose = (qs.get("diagnose", ["0"])[0] or "0").strip().lower() in ("1", "true", "yes")
            if highlight not in ("smart", "storage", "ping", "port", "dns", "backup"):
                highlight = ""
            threading.Thread(target=_maybe_run_autoupdate, daemon=True).start()
            self._reply_html(
                _render_setup_html(
                    log_filter=log_filter,
                    diag_view=diag_view,
                    ui_view=ui_view,
                    highlight_channel=highlight,
                    log_source=source_ctx,
                    diagnose_agent=diagnose,
                    ssl_warning=ssl_warning,
                )
            )

        def do_POST(self) -> None:  # noqa: N802
            if self._redirect_http_to_https():
                return
            if self.path == "/api/peer/push":
                if not self._require_peer_mtls():
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                body, ok_body = self._read_peer_body()
                if not ok_body:
                    self._reply_json({"error": "invalid encrypted payload"}, 400)
                    return
                try:
                    data = json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    self._reply_json({"error": "invalid json"}, 400)
                    return
                peer_id = str(data.get("instance_id", "") or "").strip()
                if not peer_id:
                    self._reply_json({"error": "missing instance_id"}, 400)
                    return
                data["received_at"] = int(time.time())
                _save_peer_snapshot(peer_id, data)
                cfg = load_config()
                peers = cfg.get("peers", [])
                if not isinstance(peers, list):
                    peers = []
                agent_url = str(data.get("callback_url", "") or "").strip()
                found = False
                for p in peers:
                    if str(p.get("instance_id", "")) == peer_id:
                        p["instance_name"] = str(data.get("instance_name", "") or "")
                        p["last_seen"] = int(time.time())
                        p["monitor_count"] = len(data.get("monitors", []))
                        p["version"] = str(data.get("version", "") or "")
                        p["platform"] = str(data.get("platform", "") or "")
                        p["status"] = "online"
                        existing_url = str(p.get("url", "") or "").strip()
                        # Preserve a manually set URL; only auto-fill from callback when unlocked.
                        if agent_url and (not existing_url or not bool(p.get("url_locked", False))):
                            p["url"] = agent_url
                        found = True
                        break
                if not found:
                    new_peer: Dict[str, Any] = {
                        "instance_id": peer_id,
                        "instance_name": str(data.get("instance_name", "") or ""),
                        "last_seen": int(time.time()),
                        "monitor_count": len(data.get("monitors", [])),
                        "version": str(data.get("version", "") or ""),
                        "platform": str(data.get("platform", "") or ""),
                        "status": "online",
                        "role": "agent",
                    }
                    if agent_url:
                        new_peer["url"] = agent_url
                    peers.append(new_peer)
                cfg["peers"] = peers
                save_config(cfg, reapply_cron=False)
                append_ui_log(f"peer-push | received from {data.get('instance_name', peer_id)} | monitors={len(data.get('monitors', []))}")
                self._reply_peer_json({"status": "ok", "received": True}, 200)
                return
            if self.path == "/api/peer/register":
                if not self._require_peer_mtls(allow_token_only=True):
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                body, ok_body = self._read_peer_body()
                if not ok_body:
                    self._reply_json({"error": "invalid encrypted payload"}, 400)
                    return
                try:
                    data = json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    self._reply_json({"error": "invalid json"}, 400)
                    return
                peer_id = str(data.get("instance_id", "") or "").strip()
                if not peer_id:
                    self._reply_json({"error": "missing instance_id"}, 400)
                    return
                cfg = load_config()
                peers = cfg.get("peers", [])
                if not isinstance(peers, list):
                    peers = []
                found = False
                for p in peers:
                    if str(p.get("instance_id", "")) == peer_id:
                        p["instance_name"] = str(data.get("instance_name", "") or "")
                        p["last_seen"] = int(time.time())
                        p["monitor_count"] = int(data.get("monitor_count", 0) or 0)
                        p["version"] = str(data.get("version", "") or "")
                        p["status"] = "online"
                        found = True
                        break
                if not found:
                    peers.append({
                        "instance_id": peer_id,
                        "instance_name": str(data.get("instance_name", "") or ""),
                        "last_seen": int(time.time()),
                        "monitor_count": int(data.get("monitor_count", 0) or 0),
                        "version": str(data.get("version", "") or ""),
                        "status": "online",
                        "role": "agent",
                    })
                csr_pem = str(data.get("csr_pem", "") or "").strip()
                signed_cert = ""
                ca_cert = ""
                master_cert = ""
                if csr_pem:
                    ca_key = get_certs_dir() / "ca.key"
                    ca_crt = get_certs_dir() / "ca.crt"
                    if not ca_key.exists() or not ca_crt.exists():
                        ok_ca, msg_ca = _generate_ca(force=False)
                        if not ok_ca:
                            self._reply_json({"error": f"master CA unavailable: {msg_ca}"}, 500)
                            return
                        cfg2 = load_config()
                        inst_id = _get_instance_id(cfg2)
                        _generate_instance_cert(inst_id, cn_prefix="master")
                    signed_pem, sign_msg = _sign_agent_csr(csr_pem, peer_id)
                    if not signed_pem:
                        self._reply_json({"error": f"CSR signing failed: {sign_msg}"}, 500)
                        return
                    signed_cert = signed_pem
                    try:
                        ca_cert = (get_certs_dir() / "ca.crt").read_text(encoding="utf-8")
                    except OSError:
                        ca_cert = ""
                    cfg3 = load_config()
                    m_cert, _, _ = _get_mtls_cert_paths(cfg3)
                    if m_cert:
                        try:
                            master_cert = Path(m_cert).read_text(encoding="utf-8")
                        except OSError:
                            master_cert = ""
                cfg["peers"] = peers
                save_config(cfg, reapply_cron=False)
                append_ui_log(f"peer-register | {data.get('instance_name', peer_id)} registered")
                reply_data: Dict[str, Any] = {"status": "ok", "registered": True}
                if signed_cert and ca_cert:
                    reply_data["signed_cert"] = signed_cert
                    reply_data["ca_cert"] = ca_cert
                    if master_cert:
                        reply_data["master_cert"] = master_cert
                self._reply_peer_json(reply_data, 200)
                return
            if self.path == "/api/peer/create-monitor":
                if not self._require_peer_mtls():
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                body, ok_body = self._read_peer_body()
                if not ok_body:
                    self._reply_json({"error": "invalid encrypted payload"}, 400)
                    return
                try:
                    data = json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    self._reply_json({"error": "invalid json"}, 400)
                    return
                m_name = str(data.get("name", "") or "").strip()
                m_mode = str(data.get("check_mode", "smart") or "smart").strip().lower()
                m_url = str(data.get("kuma_url", "") or "").strip()
                if not m_name:
                    self._reply_json({"error": "missing monitor name"}, 400)
                    return
                cfg = load_config()
                monitors = cfg.get("monitors", [])
                if not isinstance(monitors, list):
                    monitors = []
                if any(str(em.get("name", "")) == m_name for em in monitors):
                    self._reply_json({"error": f"monitor '{m_name}' already exists"}, 409)
                    return
                new_mon: Dict[str, Any] = {"name": m_name, "check_mode": m_mode, "kuma_url": m_url}
                for extra_key in ("probe_host", "probe_port", "dns_name", "dns_server", "source_platform"):
                    val = str(data.get(extra_key, "") or "").strip()
                    if val:
                        new_mon[extra_key] = val
                monitors.append(new_mon)
                cfg["monitors"] = monitors
                save_config(cfg)
                append_ui_log(f"peer-create-monitor | remote created '{m_name}' mode={m_mode}")
                _trigger_peer_sync_bg(cfg)
                self._reply_peer_json({"status": "ok", "created": m_name}, 201)
                return
            if self.path == "/api/peer/update":
                append_ui_log("peer-update | request received from master")
                try:
                    append_ui_log("peer-update | checking mTLS")
                    if not self._require_peer_mtls(allow_token_only=True):
                        append_ui_log("peer-update | mTLS check failed")
                        return
                    append_ui_log("peer-update | checking token")
                    if not self._verify_peer_token():
                        append_ui_log("peer-update | token verification failed")
                        self._reply_json({"error": "unauthorized"}, 401)
                        return
                    helper = get_update_helper_path()
                    append_ui_log(f"peer-update | helper path: {helper} exists={helper.exists()}")
                    if not helper.exists():
                        append_ui_log("peer-update | update helper not found")
                        self._reply_peer_json({"error": "Update helper not found"}, 400)
                        return
                    append_ui_log("peer-update | starting background update")
                    session_id = _run_agent_update_background()
                    append_ui_log(f"peer-update | started session {session_id}")
                    self._reply_peer_json({"status": "started", "session_id": session_id}, 202)
                except Exception as e:
                    tb = traceback.format_exc()
                    err_msg = f"{type(e).__name__}: {e}"
                    append_ui_log(f"peer-update | error: {err_msg}")
                    append_ui_log(f"peer-update | traceback: {tb}")
                    self._reply_peer_json({"error": err_msg, "traceback": tb[:2000]}, 500)
                return
            if self.path == "/peer/test-connection":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                test_url_raw = (form.get("peer_url", [""])[0] or "").strip()
                test_token = (form.get("peer_token", [""])[0] or "").strip()
                test_url = _resolve_peer_url_from_stored(test_url_raw, test_token, timeout=8) if test_url_raw and test_token else test_url_raw
                result = _peer_test_connection(test_url, test_token) if test_url else "Missing host or token."
                ssl_warning = self._ssl_warning_text()
                ui_view = self._view_from_referer()
                self._reply_html(_render_setup_html(
                    peering_message=f"Peer test: {result}",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/save-settings":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                cfg = load_config()
                prev_role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
                role = (form.get("peer_role", ["standalone"])[0] or "standalone").strip().lower()
                if role not in PEER_ROLES:
                    role = "standalone"
                cfg["peer_role"] = role
                _m_raw = (form.get("peer_master_url", [""])[0] or "").strip()
                _cb_raw = (form.get("agent_callback_url", [""])[0] or "").strip()
                _port_val = (form.get("peer_port", [""])[0] or "").strip()
                _port = int(_port_val) if _port_val and _port_val.isdigit() else PEER_DEFAULT_PORT
                cfg["peer_master_url"] = _parse_peer_host_port(_m_raw, _port)[0]
                cfg["agent_callback_url"] = _parse_peer_host_port(_cb_raw, _port)[0]
                cfg["peer_port"] = _port if 1 <= _port <= 65535 else PEER_DEFAULT_PORT
                token_val = (form.get("peering_token", [""])[0] or "").strip()
                token_auto_generated = False
                if token_val:
                    cfg["peering_token"] = token_val
                elif role == "master":
                    # Auto-generate token when switching to master so it's ready to share
                    existing = str(cfg.get("peering_token", "") or "").strip()
                    switching_to_master = prev_role != "master"
                    if switching_to_master or not existing:
                        cfg["peering_token"] = secrets.token_hex(32)
                        token_auto_generated = True
                inst_id = _get_instance_id(cfg)
                save_config(cfg, reapply_cron=False)
                _extra_msg = " Peering token auto-generated." if token_auto_generated else ""
                if role == "master" and _openssl_available():
                    ca_path = get_certs_dir() / "ca.crt"
                    if not ca_path.exists():
                        ok_ca, msg_ca = _generate_ca(force=False)
                        if ok_ca:
                            ok_sc, msg_sc = _generate_instance_cert(inst_id, cn_prefix="master")
                            _extra_msg += f" CA auto-generated. {msg_sc}"
                        else:
                            _extra_msg += f" CA generation failed: {msg_ca}"
                elif role == "agent" and cfg.get("peer_master_url") and cfg.get("peering_token"):
                    sec_st = _get_mtls_security_status(cfg)
                    if not sec_st["instance_cert_ok"] and _openssl_available():
                        cr = _agent_request_cert(cfg)
                        _extra_msg = f" Cert request: {cr}"
                append_ui_log(f"peer-settings | saved | role={role} | name={cfg.get('instance_name', '')}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=f"Peering settings saved.{_extra_msg}",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/generate-token":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                cfg = load_config()
                cfg["peering_token"] = secrets.token_hex(32)
                save_config(cfg, reapply_cron=False)
                append_ui_log("peer-settings | new peering token generated")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message="New peering token generated.",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/remove":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                rm_id = (form.get("peer_id", [""])[0] or "").strip()
                cfg = load_config()
                peers = [p for p in cfg.get("peers", []) if str(p.get("instance_id", "")) != rm_id]
                cfg["peers"] = peers
                save_config(cfg, reapply_cron=False)
                snap_file = get_peer_data_dir() / f"{rm_id}.json"
                _clear_file(snap_file)
                append_ui_log(f"peer-remove | removed peer {rm_id}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message="Peer removed.",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/sync-now":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                cfg = load_config()
                role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
                if role == "agent":
                    result = _peer_push_to_master(cfg)
                    cfg["last_peer_sync"] = int(time.time())
                    cfg["last_peer_sync_result"] = result
                    save_config(cfg, reapply_cron=False)
                    append_ui_log(f"peer-sync | manual agent push: {result}")
                elif role == "master":
                    result = _peer_sync_from_master(cfg)
                    cfg = load_config()
                    cfg["last_peer_sync_result"] = result
                    save_config(cfg, reapply_cron=False)
                    append_ui_log(f"peer-sync | manual master sync: {result}")
                else:
                    result = "Standalone mode - no sync needed."
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=f"Sync result: {result}",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/sync-one":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                sync_pid = (form.get("peer_id", [""])[0] or "").strip()
                cfg = load_config()
                token = str(cfg.get("peering_token", "") or "").strip()
                peers = cfg.get("peers", [])
                target_p = None
                for p in peers:
                    if str(p.get("instance_id", "")) == sync_pid:
                        target_p = p
                        break
                if not target_p or not token:
                    result = "Peer not found or no token."
                else:
                    pname = str(target_p.get("instance_name", "") or sync_pid[:8])
                    p_url_raw = str(target_p.get("url", "") or "").strip().rstrip("/")
                    if not p_url_raw:
                        result = f"{pname}: no URL configured."
                    else:
                        p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=10)
                        if not p_url:
                            result = f"{pname}: cannot reach {p_url_raw}."
                        else:
                            try:
                                t0 = time.time()
                                status, resp_body = _peer_http_request(p_url, token, "GET", "/api/peer/snapshot", timeout=10)
                                latency_ms = round((time.time() - t0) * 1000)
                                if status < 300:
                                    target_p["last_seen"] = int(time.time())
                                    target_p["status"] = "online"
                                    target_p["latency_ms"] = latency_ms
                                    try:
                                        snap = json.loads(resp_body)
                                        target_p["monitor_count"] = len(snap.get("monitors", []))
                                        target_p["instance_name"] = str(snap.get("instance_name", "") or pname)
                                        target_p["version"] = str(snap.get("version", "") or "")
                                        snap["received_at"] = int(time.time())
                                        _save_peer_snapshot(sync_pid, snap)
                                    except (json.JSONDecodeError, ValueError):
                                        pass
                                    result = f"{pname}: online ({latency_ms} ms)"
                                else:
                                    target_p["status"] = "offline"
                                    target_p["latency_ms"] = None
                                    result = f"{pname}: HTTP {status}"
                            except Exception as e:
                                target_p["status"] = "offline"
                                target_p["latency_ms"] = None
                                result = f"{pname}: {type(e).__name__}: {e}"
                    cfg["peers"] = peers
                    cfg["last_peer_sync"] = int(time.time())
                    save_config(cfg, reapply_cron=False)
                append_ui_log(f"peer-sync-one | {sync_pid} | {result}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=f"Sync: {result}",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/create-remote-monitor":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                target_peer = (form.get("target_peer", [""])[0] or "").strip()
                m_name = (form.get("monitor_name", [""])[0] or "").strip()
                m_mode = (form.get("check_mode", ["smart"])[0] or "smart").strip().lower()
                m_url = (form.get("kuma_url", [""])[0] or "").strip()
                mon_cfg: Dict[str, Any] = {"name": m_name, "check_mode": m_mode, "kuma_url": m_url}
                for extra in ("probe_host", "probe_port", "dns_name", "dns_server"):
                    v = (form.get(extra, [""])[0] or "").strip()
                    if v:
                        mon_cfg[extra] = v
                cfg = load_config()
                if target_peer and len(target_peer) < 4:
                    ssl_warning = self._ssl_warning_text()
                    self._reply_html(_render_setup_html(
                        peering_message=f"Invalid target peer '{target_peer}'.",
                        ui_view="settings",
                        ssl_warning=ssl_warning,
                    ))
                    return
                result = _peer_create_remote_monitor(cfg, target_peer, mon_cfg)
                append_ui_log(f"peer-create-remote | peer={target_peer} monitor={m_name} result={result}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=result,
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/update-peer-url":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                upd_id = (form.get("peer_id", [""])[0] or "").strip()
                upd_url_raw = (form.get("peer_url", [""])[0] or "").strip()
                upd_url = f"{_parse_peer_host_port(upd_url_raw)[0]}:{_parse_peer_host_port(upd_url_raw)[1]}" if upd_url_raw else ""
                cfg = load_config()
                peers = cfg.get("peers", [])
                if not isinstance(peers, list):
                    peers = []
                updated = False
                for p in peers:
                    if str(p.get("instance_id", "")) == upd_id:
                        p["url"] = upd_url
                        p["url_locked"] = bool(upd_url)
                        updated = True
                        break
                cfg["peers"] = peers
                save_config(cfg, reapply_cron=False)
                msg = f"Peer URL updated." if updated else f"Peer not found."
                append_ui_log(f"peer-update-url | {upd_id} -> {upd_url}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=msg,
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/add-agent":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                a_name = (form.get("agent_name", [""])[0] or "").strip()
                a_id = (form.get("agent_id", [""])[0] or "").strip()
                a_url = (form.get("agent_url", [""])[0] or "").strip()
                if not a_id:
                    ssl_warning = self._ssl_warning_text()
                    self._reply_html(_render_setup_html(error="Agent Instance ID is required.", ui_view="settings", ssl_warning=ssl_warning))
                    return
                cfg = load_config()
                peers = cfg.get("peers", [])
                if not isinstance(peers, list):
                    peers = []
                if any(str(p.get("instance_id", "")) == a_id for p in peers):
                    ssl_warning = self._ssl_warning_text()
                    self._reply_html(_render_setup_html(error=f"Agent '{a_id}' already exists.", ui_view="settings", ssl_warning=ssl_warning))
                    return
                new_peer: Dict[str, Any] = {
                    "instance_id": a_id,
                    "instance_name": a_name or a_id[:8],
                    "last_seen": 0,
                    "monitor_count": 0,
                    "status": "offline",
                    "role": "agent",
                }
                if a_url:
                    _ah, _ap = _parse_peer_host_port(a_url)
                    new_peer["url"] = f"{_ah}:{_ap}" if _ah else a_url
                    new_peer["url_locked"] = True
                peers.append(new_peer)
                cfg["peers"] = peers
                save_config(cfg, reapply_cron=False)
                append_ui_log(f"peer-add | manually added agent {a_name or a_id[:8]} ({a_id})")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=f"Agent '{a_name or a_id[:8]}' added. It will sync when it pushes data or you click Sync.",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/generate-ca":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                ok, msg = _generate_ca(force=False)
                cfg = load_config()
                inst_id = _get_instance_id(cfg)
                if ok:
                    ok2, msg2 = _generate_instance_cert(inst_id, cn_prefix="master")
                    if ok2:
                        msg += f" Server cert: {msg2}"
                    else:
                        msg += f" Server cert failed: {msg2}"
                append_ui_log(f"mtls | CA generate: {msg}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=msg,
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/generate-server-cert":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                cfg = load_config()
                inst_id = _get_instance_id(cfg)
                ok, msg = _generate_instance_cert(inst_id, cn_prefix="master")
                append_ui_log(f"mtls | server cert generate: {msg}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=msg + " Restart the addon for TLS to take effect.",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/request-cert":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                cfg = load_config()
                result = _agent_request_cert(cfg)
                append_ui_log(f"mtls | agent cert request: {result}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=result,
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/revoke-agent-cert":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                revoke_id = (form.get("agent_id", [""])[0] or "").strip()
                if revoke_id:
                    _revoke_agent_cert(revoke_id)
                    append_ui_log(f"mtls | revoked cert for {revoke_id}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=f"Certificate revoked for agent {revoke_id}." if revoke_id else "No agent ID provided.",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
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
                "/auth/export-backup",
            )
            auth = _load_auth_state()
            ssl_warning = self._ssl_warning_text()
            ui_view = self._view_from_referer()
            if self.path in auth_routes:
                content_type = (self.headers.get("Content-Type", "") or "").lower()
                import_file_json = ""
                if self.path == "/auth/import" and "multipart/form-data" in content_type and cgi is not None:
                    fs = cgi.FieldStorage(
                        fp=self.rfile,
                        headers=self.headers,
                        environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": self.headers.get("Content-Type", "")},
                        keep_blank_values=True,
                    )
                    raw_payload = fs.getvalue("import_payload")
                    if isinstance(raw_payload, bytes):
                        raw_payload = raw_payload.decode("utf-8", errors="ignore")
                    bk = fs.getvalue("backup_key")
                    if isinstance(bk, bytes):
                        bk = bk.decode("utf-8", errors="ignore")
                    form = {"import_payload": [str(raw_payload or "")], "backup_key": [str(bk or "")]}
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
                    flag_path = _get_autoupdate_on_logout_flag_path()
                    if flag_path.exists():
                        try:
                            flag_path.unlink(missing_ok=True)
                        except OSError:
                            pass
                        threading.Thread(
                            target=lambda: _maybe_run_autoupdate(defer_if_user_logged_in=False),
                            daemon=True,
                        ).start()
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
                        _append_login_event(auth, self._client_source_ip(), "failed-password")
                        _save_auth_state(auth)
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
                        _append_login_event(auth, self._client_source_ip(), "failed-2fa")
                        _save_auth_state(auth)
                        self._reply_html(_render_auth_verify_page(error="Invalid authenticator code.", ssl_warning=ssl_warning))
                        return
                    _register_auth_success(auth)
                    auth["last_login_ip"] = self._client_source_ip()
                    auth["last_login_at"] = int(time.time())
                    _append_login_event(auth, auth["last_login_ip"], "success-2fa")
                    _save_auth_state(auth)
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
                        _append_login_event(auth, self._client_source_ip(), "failed-recovery")
                        _save_auth_state(auth)
                        self._reply_html(_render_auth_recovery_page(error="Invalid or already used recovery code.", ssl_warning=ssl_warning))
                        return
                    _register_auth_success(auth)
                    auth["last_login_ip"] = self._client_source_ip()
                    auth["last_login_at"] = int(time.time())
                    _append_login_event(auth, auth["last_login_ip"], "success-recovery")
                    _save_auth_state(auth)
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
                if self.path == "/auth/export-backup":
                    if not self._is_authenticated():
                        self._redirect("/auth/login")
                        return
                    backup_key = (form.get("backup_key", [""])[0] or "").strip()
                    if len(backup_key) < 12:
                        self._reply_html(_render_setup_html(
                            error="Encryption key must be at least 12 characters. Save this key securely; you need it to restore.",
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                        return
                    cfg = load_config()
                    auth_state = _load_auth_state()
                    payload = {
                        "config": cfg,
                        "auth": auth_state,
                        "exported_at": int(time.time()),
                        "v": 1,
                    }
                    plaintext = json.dumps(payload)
                    try:
                        enc = _encrypt_backup(plaintext, backup_key)
                    except Exception as e:
                        self._reply_html(_render_setup_html(
                            error=f"Encryption failed: {type(e).__name__}: {e}",
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                        return
                    result = json.dumps({"v": 1, "enc": enc, "exported_at": payload["exported_at"]})
                    append_ui_log("auth-security | full encrypted backup exported")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Disposition", 'attachment; filename="unix-monitor-backup.enc.json"')
                    self.send_header("Content-Length", str(len(result.encode("utf-8"))))
                    self.end_headers()
                    self.wfile.write(result.encode("utf-8"))
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
                        parsed = json.loads(raw)
                    except json.JSONDecodeError:
                        self._reply_html(_render_setup_html(error="Import payload is not valid JSON.", ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    if not isinstance(parsed, dict):
                        self._reply_html(_render_setup_html(error="Import payload must be a JSON object.", ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    if parsed.get("enc") and parsed.get("v"):
                        backup_key = (form.get("backup_key", [""])[0] or "").strip()
                        if not backup_key:
                            self._reply_html(_render_setup_html(
                                error="Encrypted backup requires the decryption key.",
                                ui_view=ui_view,
                                ssl_warning=ssl_warning,
                            ))
                            return
                        dec = _decrypt_backup(str(parsed.get("enc", "")), backup_key)
                        if dec is None:
                            self._reply_html(_render_setup_html(
                                error="Decryption failed. Wrong key or corrupted backup.",
                                ui_view=ui_view,
                                ssl_warning=ssl_warning,
                            ))
                            return
                        try:
                            payload = json.loads(dec)
                        except json.JSONDecodeError:
                            self._reply_html(_render_setup_html(error="Decrypted backup is not valid JSON.", ui_view=ui_view, ssl_warning=ssl_warning))
                            return
                    else:
                        payload = parsed
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
                "/settings/save-instance-name",
                "/settings/save-autoupdate",
                "/settings/save-update-from-main",
                "/settings/request-autoupdate-on-logout",
                "/settings/recheck-updates",
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
                "/clear-task-status",
                "/clear-cache",
                "/clear-history",
                "/clear-system-cache",
                "/check-elevated",
                "/auto-create-task",
                "/danger-restart",
                "/danger-reset",
                "/self-update",
                "/self-rollback",
                "/agent-update",
            ):
                self._reply_html(_render_setup_html(error="Unsupported endpoint"), 404)
                return
            try:
                if self.path == "/settings/save-instance-name":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    instance_name = (form.get("instance_name", [""])[0] or "").strip()
                    cfg = load_config()
                    cfg["instance_name"] = instance_name
                    save_config(cfg, reapply_cron=False)
                    append_ui_log(f"settings | instance name saved: {instance_name or '-'}")
                    self._reply_html(_render_setup_html(
                        security_message="Instance name saved.",
                        ui_view="settings",
                        ssl_warning=ssl_warning,
                    ))
                    return
                if self.path == "/settings/save-autoupdate":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    vals = form.get("autoupdate_enabled", []) or []
                    enabled = "1" in vals
                    cfg = load_config()
                    cfg["autoupdate_enabled"] = enabled
                    save_config(cfg, reapply_cron=False)
                    append_ui_log(f"settings | autoupdate {'enabled' if enabled else 'disabled'}")
                    self._reply_html(_render_setup_html(
                        security_message="Autoupdate " + ("enabled" if enabled else "disabled") + ".",
                        ui_view=ui_view,
                        ssl_warning=ssl_warning,
                        open_server_panel="package",
                    ))
                    return
                if self.path == "/settings/save-update-from-main":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    vals = form.get("update_from_main", []) or []
                    enabled = "1" in vals
                    cfg = load_config()
                    cfg["update_from_main"] = enabled
                    save_config(cfg, reapply_cron=False)
                    check_result = _run_update_check(cfg)
                    _save_update_check_result(check_result)
                    selected = "main" if enabled else "latest release"
                    public_version = str(check_result.get("public_version", "") or check_result.get("latest_version", "") or "")
                    append_ui_log(f"settings | update source set to {selected}")
                    self._reply_html(_render_setup_html(
                        security_message="Update source set to " + selected + (f". Public version: {public_version}." if public_version else "."),
                        ui_view=ui_view,
                        ssl_warning=ssl_warning,
                        open_server_panel="package",
                    ))
                    return
                if self.path == "/agent-update":
                    if not self._is_authenticated():
                        self._reply_json({"error": "unauthorized"}, 401)
                        return
                    peer_id = (form.get("peer_id", [""])[0] or "").strip()
                    if not peer_id:
                        self._reply_json({"error": "Missing peer_id"}, 400)
                        return
                    cfg = load_config()
                    if str(cfg.get("peer_role", "")) != "master":
                        self._reply_json({"error": "Master role required"}, 403)
                        return
                    session_id, err = _trigger_agent_update(cfg, peer_id)
                    if err:
                        peers = cfg.get("peers", []) or []
                        target = next((p for p in peers if str(p.get("instance_id", "")) == peer_id), None)
                        pname = str(target.get("instance_name", "") or peer_id[:8]) if target else peer_id[:8]
                        p_url = str(target.get("url", "") or "").strip() if target else ""
                        diag_lines = [
                            f"Agent: {pname} ({peer_id[:16]}...)",
                            f"URL: {p_url or '(not set)'}",
                            f"Error: {err}",
                        ]
                        self._reply_json({
                            "error": err,
                            "diagnostic": "\n".join(diag_lines),
                        }, 400)
                        return
                    append_ui_log(f"agent-update | triggered for {peer_id}, session {session_id}")
                    self._reply_json({"status": "started", "session_id": session_id, "peer_id": peer_id}, 202)
                    return
                if self.path == "/settings/recheck-updates":
                    cfg = load_config()
                    result = _run_update_check(cfg)
                    _save_update_check_result(result)
                    selected_channel = str(result.get("selected_channel", "") or "latest")
                    public_version = str(result.get("public_version", "") or result.get("latest_version", "") or "")
                    if result.get("error"):
                        append_ui_log(f"settings | recheck updates failed ({selected_channel}): {result.get('error')}")
                        self._reply_html(_render_setup_html(
                            error=f"Recheck failed ({selected_channel}): {result.get('error')}",
                            ui_view="overview",
                            ssl_warning=ssl_warning,
                            open_server_panel="package",
                        ))
                        return
                    append_ui_log(f"settings | recheck updates ok ({selected_channel}) public={public_version or '?'} local={VERSION}")
                    self._reply_html(_render_setup_html(
                        security_message=f"Rechecked updates ({selected_channel}). Local: {VERSION}. Public: {public_version or 'unknown'}.",
                        ui_view="overview",
                        ssl_warning=ssl_warning,
                        open_server_panel="package",
                    ))
                    return
                if self.path == "/settings/request-autoupdate-on-logout":
                    flag_path = _get_autoupdate_on_logout_flag_path()
                    try:
                        flag_path.parent.mkdir(parents=True, exist_ok=True)
                        flag_path.write_text("1", encoding="utf-8")
                    except OSError:
                        pass
                    append_ui_log("settings | autoupdate will run on next logout")
                    self._reply_html(_render_setup_html(
                        security_message="Update will run when you log out. You can keep working until then.",
                        ui_view=ui_view,
                        ssl_warning=ssl_warning,
                        open_server_panel="package",
                    ))
                    return
                if self.path == "/danger-restart":
                    service_script = "/usr/local/bin/unix-monitor-service"
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
                if self.path == "/danger-reset":
                    cfg = load_config()
                    reset_cfg: Dict[str, Any] = {"monitors": []}
                    if cfg.get("instance_id"):
                        reset_cfg["instance_id"] = cfg["instance_id"]
                    save_config(reset_cfg, reapply_cron=True)
                    append_ui_log("danger-zone | configuration reset from UI")
                    self._reply_html(
                        _render_setup_html(
                            security_message="Configuration reset. All monitors and peering cleared.",
                            ui_view="settings",
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/self-update":
                    helper = get_update_helper_path()
                    script_dir = str(get_script_path().parent)
                    if not helper.exists():
                        self._reply_html(_render_setup_html(
                            error="Update helper not found. Reinstall to add self-update.",
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                        return
                    try:
                        cfg = load_config()
                        rc, out = _run_cmd([str(helper), script_dir, "update", "no-restart"], timeout_sec=30, env=_update_helper_env(cfg))
                        if rc != 0:
                            self._reply_html(_render_setup_html(
                                error=f"Update failed: {out.strip() or 'exit ' + str(rc)}",
                                action_output=out,
                                ui_view=ui_view,
                                ssl_warning=ssl_warning,
                            ))
                            return
                        append_ui_log("self-update | completed successfully")
                        try:
                            _save_update_check_result(_run_update_check(load_config()))
                        except Exception:
                            pass
                        self._reply_html(_render_setup_html(
                            security_message="Update complete. Config and data preserved. Restarting services…",
                            action_output=out,
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                        def _delayed_restart() -> None:
                            time.sleep(2)
                            for u in ("unix-monitor-ui.service", "unix-monitor-scheduler.timer", "unix-monitor-smart-helper.timer", "unix-monitor-backup-helper.timer", "unix-monitor-system-log-helper.timer"):
                                _run_cmd(["systemctl", "restart", u], timeout_sec=10)
                        threading.Thread(target=_delayed_restart, daemon=True).start()
                    except Exception as e:
                        self._reply_html(_render_setup_html(
                            error=f"Update failed: {type(e).__name__}: {e}",
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                    return
                if self.path == "/self-rollback":
                    helper = get_update_helper_path()
                    script_dir = str(get_script_path().parent)
                    backup_path = Path(script_dir) / "unix-monitor.py.prev"
                    if not helper.exists():
                        self._reply_html(_render_setup_html(
                            error="Update helper not found.",
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                        return
                    if not backup_path.exists():
                        self._reply_html(_render_setup_html(
                            error="No backup found. Run an update first to create one.",
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                        return
                    try:
                        rc, out = _run_cmd([str(helper), script_dir, "rollback"], timeout_sec=30)
                        if rc != 0:
                            self._reply_html(_render_setup_html(
                                error=f"Rollback failed: {out.strip() or 'exit ' + str(rc)}",
                                action_output=out,
                                ui_view=ui_view,
                                ssl_warning=ssl_warning,
                            ))
                            return
                        append_ui_log("self-rollback | restored from backup")
                        self._reply_html(_render_setup_html(
                            security_message="Rollback complete. Restored previous version. Restarting services…",
                            action_output=out,
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                    except Exception as e:
                        self._reply_html(_render_setup_html(
                            error=f"Rollback failed: {type(e).__name__}: {e}",
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
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
                    self._reply_html(_render_setup_html(message="Logs cleared", ui_view="overview", ssl_warning=ssl_warning))
                    return
                if self.path == "/clear-task-status":
                    clear_task_status()
                    append_ui_log("task status cleared")
                    self._reply_html(_render_setup_html(message="Task data cleared", ui_view="overview", ssl_warning=ssl_warning))
                    return
                if self.path == "/clear-cache":
                    clear_smart_cache()
                    clear_backup_cache()
                    clear_system_log_cache()
                    append_ui_log("cache cleared (smart + backup + system-log)")
                    self._reply_html(_render_setup_html(message="Cache cleared", ui_view="overview", ssl_warning=ssl_warning))
                    return
                if self.path == "/clear-history":
                    clear_history()
                    append_ui_log("monitor history cleared")
                    self._reply_html(_render_setup_html(message="History cleared", ui_view="overview", ssl_warning=ssl_warning))
                    return
                if self.path == "/clear-system-cache":
                    clear_system_log_cache()
                    append_ui_log("system log cache cleared")
                    self._reply_html(_render_setup_html(message="System log cache cleared", ui_view="overview", ssl_warning=ssl_warning))
                    return
                if self.path == "/check-elevated":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    stay_popup = "stay_popup" in form
                    output = _ui_check_elevated_access()
                    self._reply_html(
                        _render_setup_html(
                            elevated_check_message="Elevated access check completed",
                            elevated_check_output=output,
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
                mode = (form.get("check_mode", ["smart"])[0] or "smart").strip().lower()
                kuma_url = (form.get("kuma_url", [""])[0] or "").strip()
                interval_raw = (form.get("interval", ["60"])[0] or "60").strip()
                probe_host = (form.get("probe_host", [""])[0] or "").strip()
                probe_port_raw = (form.get("probe_port", [""])[0] or "").strip()
                dns_name = (form.get("dns_name", [""])[0] or "").strip()
                dns_server = (form.get("dns_server", [""])[0] or "").strip()
                cron_enabled = "cron_enabled" in form
                edit_original_name = (form.get("edit_original_name", [""])[0] or "").strip()

                if mode not in CHECK_MODES:
                    append_ui_log(f"save-config | invalid mode: {mode}")
                    self._reply_html(_render_setup_html(error="Invalid check mode", ui_view=ui_view, ssl_warning=ssl_warning, create_mode=not edit_original_name, edit_original_name=edit_original_name or None))
                    return
                if not name:
                    name = f"{mode}-unix-check"
                if len(name) < 2:
                    self._reply_html(_render_setup_html(error="Monitor name must be at least 2 characters.", ui_view=ui_view, ssl_warning=ssl_warning, create_mode=not edit_original_name, edit_original_name=edit_original_name or None))
                    return
                if not kuma_url.strip():
                    self._reply_html(_render_setup_html(error="Kuma Push URL is required.", ui_view=ui_view, ssl_warning=ssl_warning, create_mode=not edit_original_name, edit_original_name=edit_original_name or None))
                    return
                if not kuma_url.startswith(("http://", "https://")):
                    kuma_url = "https://" + kuma_url
                kuma_url = normalize_kuma_url(kuma_url)
                err = validate_kuma_url(kuma_url)
                if err:
                    append_ui_log(f"save-config | invalid Kuma URL: {err}")
                    self._reply_html(_render_setup_html(error=f"Invalid Kuma URL: {err}", ui_view=ui_view, ssl_warning=ssl_warning, create_mode=not edit_original_name, edit_original_name=edit_original_name or None))
                    return
                try:
                    interval = max(INTERVAL_MIN, min(INTERVAL_MAX, int(interval_raw)))
                except ValueError:
                    interval = 60
                try:
                    probe_port = int(probe_port_raw) if probe_port_raw else 0
                except ValueError:
                    probe_port = 0
                if mode == "ping" and not probe_host:
                    self._reply_html(_render_setup_html(error="Ping mode requires a probe host.", ui_view="setup", ssl_warning=ssl_warning, create_mode=not edit_original_name, edit_original_name=edit_original_name or None))
                    return
                if mode == "port":
                    if not probe_host or probe_port < 1 or probe_port > 65535:
                        self._reply_html(_render_setup_html(error="Port mode requires valid probe host and TCP port (1-65535).", ui_view="setup", ssl_warning=ssl_warning, create_mode=not edit_original_name, edit_original_name=edit_original_name or None))
                        return
                if mode == "dns" and not dns_name:
                    self._reply_html(_render_setup_html(error="DNS mode requires a DNS name/domain.", ui_view="setup", ssl_warning=ssl_warning, create_mode=not edit_original_name, edit_original_name=edit_original_name or None))
                    return

                cfg = load_config()
                target_peer = (form.get("target_peer", ["local"])[0] or "local").strip()
                if target_peer and target_peer != "local" and not edit_original_name:
                    source_platform = _infer_peer_source_platform(cfg, target_peer)
                    agent_monitor_cfg: Dict[str, Any] = {
                        "name": name,
                        "check_mode": mode,
                        "kuma_url": kuma_url,
                        "source_platform": source_platform,
                    }
                    for ek, ev in (("probe_host", probe_host), ("probe_port", probe_port), ("dns_name", dns_name), ("dns_server", dns_server)):
                        if ev:
                            agent_monitor_cfg[ek] = ev
                    result = _peer_create_remote_monitor(cfg, target_peer, agent_monitor_cfg)
                    master_monitor = {
                        "name": name,
                        "check_mode": mode,
                        "devices": [],
                        "kuma_url": kuma_url,
                        "probe_host": probe_host,
                        "probe_port": probe_port,
                        "dns_name": dns_name,
                        "dns_server": dns_server,
                        "interval": interval,
                        "cron_enabled": cron_enabled,
                        "_remote_peer": target_peer,
                        "source_platform": source_platform,
                    }
                    cfg.setdefault("monitors", []).append(master_monitor)
                    cfg["cron_enabled"] = any(m.get("cron_enabled", False) for m in cfg.get("monitors", []))
                    save_config(cfg, reapply_cron=False)
                    sync_result = _peer_sync_from_master(load_config())
                    append_ui_log(f"save-config | remote create on {target_peer} | name={name} | mode={mode} | result={result}")
                    append_ui_log(f"peer-sync | auto-sync after remote create: {sync_result}")
                    self._reply_html(_render_setup_html(
                        message=f"Monitor '{name}' created on agent and registered on master.\n{result}",
                        ui_view="setup", ssl_warning=ssl_warning,
                    ))
                    return

                new_monitor = {
                    "name": name,
                    "check_mode": mode,
                    "devices": [],
                    "kuma_url": kuma_url,
                    "probe_host": probe_host,
                    "probe_port": probe_port,
                    "dns_name": dns_name,
                    "dns_server": dns_server,
                    "interval": interval,
                    "cron_enabled": cron_enabled,
                }
                if edit_original_name:
                    updated = False
                    for i, m in enumerate(cfg.get("monitors", [])):
                        if str(m.get("name", "")) == edit_original_name:
                            keep_devices = [str(x) for x in m.get("devices", [])]
                            new_monitor["devices"] = keep_devices
                            if m.get("_remote_peer"):
                                new_monitor["_remote_peer"] = m["_remote_peer"]
                            if m.get("source_platform"):
                                new_monitor["source_platform"] = m["source_platform"]
                            cfg["monitors"][i] = new_monitor
                            updated = True
                            break
                    if not updated:
                        cfg.setdefault("monitors", []).append(new_monitor)
                else:
                    existing = _find_monitor_by_name(cfg.get("monitors", []), name)
                    if existing is not None:
                        existing["check_mode"] = mode
                        existing["kuma_url"] = kuma_url
                        existing["interval"] = interval
                        existing["cron_enabled"] = cron_enabled
                    else:
                        cfg.setdefault("monitors", []).append(new_monitor)
                any_cron = any(m.get("cron_enabled", False) for m in cfg.get("monitors", []))
                cfg["cron_enabled"] = any_cron
                # Package runtime uses headless scheduler helper; avoid per-user crontab dependencies.
                save_config(cfg, reapply_cron=False)
                append_ui_log(
                    f"save-config | name={name} | mode={mode} | cron={'on' if cron_enabled else 'off'} | interval={interval} | edit_target={edit_original_name or '-'}"
                )
                _trigger_peer_sync_bg(cfg)
                self._reply_html(_render_setup_html(message="Saved successfully", ui_view="setup", ssl_warning=ssl_warning))
            except Exception as e:
                append_ui_log(f"ui-error | {type(e).__name__}: {e}")
                self._reply_html(_render_setup_html(error=f"Failed to save: {type(e).__name__}: {e}", ui_view=ui_view, ssl_warning=ssl_warning), code=500)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    _srv_cfg = load_config()
    _srv_cert, _srv_key, _srv_ca = _get_mtls_cert_paths(_srv_cfg)
    _tls_available = False
    if _srv_cert and _srv_key and _srv_ca:
        try:
            _srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            _srv_ctx.load_cert_chain(_srv_cert, _srv_key)
            _srv_ctx.load_verify_locations(_srv_ca)
            _srv_ctx.verify_mode = ssl.CERT_OPTIONAL
            server.socket = _DualProtocolSocket(server.socket, _srv_ctx)
            _tls_available = True
            Handler._tls_available = True
            append_ui_log("tls | dual-protocol listener active (HTTPS + HTTP redirect on same port)")
        except Exception as _ssl_err:
            append_ui_log(f"tls | TLS setup failed, running plain HTTP only: {_ssl_err}")
    if _tls_available:
        print(f"Setup UI running on https://{host}:{port} (HTTP auto-redirects)")
    else:
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
    monitors = [m for m in cfg.get("monitors", []) if isinstance(m, dict)]
    cfg_path = str(get_config_path())
    runtime_dir = str(get_runtime_data_dir())
    if not monitors:
        append_ui_log(f"scheduled-run | skipped | no monitors | cfg={cfg_path} | data_dir={runtime_dir}")
        return 0
    global_cron = bool(cfg.get("cron_enabled", False))
    global_interval = int(cfg.get("cron_interval_minutes", 60) or 60)
    dbg = bool(cfg.get("debug", False))
    due_count = 0
    attempted_count = 0
    ran_any = False
    append_ui_log(
        "scheduled-run | start | "
        f"monitors={len(monitors)} | global_cron={'on' if global_cron else 'off'} | "
        f"global_interval={global_interval} | cfg={cfg_path} | data_dir={runtime_dir}"
    )
    for m in monitors:
        name = str(m.get("name", "")).strip()
        if not name:
            continue
        mon_cron = bool(m.get("cron_enabled", global_cron))
        if not mon_cron:
            continue
        try:
            mon_interval = int(m.get("interval", global_interval) or global_interval)
        except (TypeError, ValueError):
            mon_interval = global_interval
        mon_interval = max(1, mon_interval)
        due = _is_scheduled_due(mon_interval, monitor_name=name)
        if not due:
            continue
        due_count += 1
        mode = str(m.get("check_mode", "smart")).lower()
        if mode not in CHECK_MODES:
            mode = "smart"
        attempted_count += 1
        ran_any = True
        try:
            url = m.get("kuma_url", "")
            if not url:
                line = f"x {name}: no Kuma URL"
                _set_monitor_state(name, "Automatic monitor check skipped", line, level="err")
                append_ui_log(f"scheduled-check | {name} | mode={mode} | skipped | no Kuma URL")
                continue
            devices = [str(x) for x in m.get("devices", [])]
            status, msg, lat = check_host_with_monitor(mode, devices, monitor=m, debug=dbg)
            ok = push_to_kuma(url, status, msg, lat, debug=dbg)
            recorded_status = status if ok else "warning"
            _record_history(name, mode, recorded_status, lat)
            line = f"{'ok' if ok else 'x'} {name}: {status} (ping={lat:.2f}ms) push {'OK' if ok else 'FAILED'}"
            _set_monitor_state(
                name,
                "Automatic monitor check completed" if ok else "Automatic monitor check completed with errors",
                line,
                level="ok" if ok else "err",
            )
            append_ui_log(
                f"scheduled-check | {name} | mode={mode} | status={status} | ping_ms={lat:.2f} | push={'OK' if ok else 'FAILED'}"
            )
        except Exception as e:
            err_line = f"x {name}: scheduler error {type(e).__name__}: {e}"
            _set_monitor_state(name, "Automatic monitor check failed", err_line, level="err")
            append_ui_log(f"scheduled-check | {name} | mode={mode} | error={type(e).__name__}: {e}")
        finally:
            _touch_scheduled_run(monitor_name=name)
    if ran_any:
        _touch_scheduled_run()
        _trigger_peer_sync_bg(cfg)
    append_ui_log(
        "scheduled-run | done | "
        f"due={due_count} | attempted={attempted_count} | ran_any={'yes' if ran_any else 'no'}"
    )
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
    print("  1) Add monitor (Mount / SMART / Storage / Ping / Port / DNS / Backup)")
    print("  2) Run check (all configured monitors)")
    print("  3) List configured monitors")
    print("  4) Remove monitor")
    print("  5) Schedule automatic checks (cron)")
    print("  6) Test push (send test message to Kuma)")
    print("  7) Toggle debug mode")
    from_main = cfg.get("update_from_main", False)
    print(f"  8) Toggle update from main (testing) — {('ON' if from_main else 'OFF')}")
    print("  9) Exit")
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
            toggle_update_from_main()
        elif choice == "9":
            print("Bye.")
            return 0
        else:
            print("Invalid choice.")


def _agent_only_gate() -> Tuple[bool, str]:
    cfg = load_config()
    if bool(cfg.get("web_enabled", True)):
        return True, ""
    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
    if role != "agent":
        return False, "Webserver is disabled. This installation is agent-only and requires peer_role=agent."
    if not str(cfg.get("peer_master_url", "") or "").strip() or not str(cfg.get("peering_token", "") or "").strip():
        return False, "Webserver is disabled. Agent mode requires peer_master_url and peering_token."
    return True, ""


def _print_usage() -> None:
    print("Usage:")
    print("  python3 unix-monitor.py")
    print("  python3 unix-monitor.py --run|-r [--debug|-d]")
    print("  python3 unix-monitor.py --run-scheduled")
    print("  python3 unix-monitor.py --run-scheduled-loop")
    print("  python3 unix-monitor.py --run-smart-helper")
    print("  python3 unix-monitor.py --run-backup-helper")
    print("  python3 unix-monitor.py --run-system-log-helper")
    print("  python3 unix-monitor.py --ui [--host 0.0.0.0] [--port 8787]")
    print("  python3 unix-monitor.py --agent-menu")


if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        _print_usage()
        sys.exit(0)
    if "--run-smart-helper" in sys.argv:
        sys.exit(run_smart_helper())
    if "--run-backup-helper" in sys.argv:
        sys.exit(run_backup_helper())
    if "--run-system-log-helper" in sys.argv:
        sys.exit(run_system_log_helper())
    if "--run-scheduled" in sys.argv:
        sys.exit(run_scheduled())
    if "--run-scheduled-loop" in sys.argv:
        sys.exit(run_scheduled_loop())
    if "--agent-menu" in sys.argv:
        ok, reason = _agent_only_gate()
        if not ok:
            print(reason)
            sys.exit(2)
        sys.exit(main())
    if "--ui" in sys.argv:
        cfg = load_config()
        if not bool(cfg.get("web_enabled", True)):
            print("Webserver is disabled in config (agent-only installation).")
            sys.exit(2)
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
    ok, reason = _agent_only_gate()
    if not ok:
        print(reason)
        print("Use --agent-menu after configuring master URL and peering token.")
        sys.exit(2)
    sys.exit(main())
