#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
INFO_FILE="${ROOT_DIR}/package/INFO"
PACKAGES_FILE="${ROOT_DIR}/repo/packages.json"
SPK_FILE="${ROOT_DIR}/dist/synology-monitor-basic.spk"
ONLINE_CHECK="${ONLINE_CHECK:-0}"

pass() { echo "[PASS] $*"; }
warn() { echo "[WARN] $*"; }
fail() { echo "[FAIL] $*"; FAILED=1; }

FAILED=0

if [ ! -f "${INFO_FILE}" ]; then
  echo "[FAIL] Missing INFO file: ${INFO_FILE}"
  exit 1
fi
if [ ! -f "${PACKAGES_FILE}" ]; then
  echo "[FAIL] Missing packages index: ${PACKAGES_FILE}"
  exit 1
fi

read_info_value() {
  local key="$1"
  awk -F'=' -v k="$key" '$1==k {gsub(/^"|"$/, "", $2); print $2}' "${INFO_FILE}" | head -n1
}

INFO_VERSION="$(read_info_value version)"
INFO_PACKAGE="$(read_info_value package)"
INFO_DISPLAYNAME="$(read_info_value displayname)"
INFO_DESC="$(read_info_value description)"

if [ -z "${INFO_VERSION}" ] || [ -z "${INFO_PACKAGE}" ]; then
  fail "INFO missing required keys (version/package)."
else
  pass "INFO has version=${INFO_VERSION}, package=${INFO_PACKAGE}."
fi

python3 - "${PACKAGES_FILE}" "${INFO_VERSION}" "${INFO_PACKAGE}" "${INFO_DISPLAYNAME}" "${INFO_DESC}" "${SPK_FILE}" <<'PY'
import json
import hashlib
import sys
from pathlib import Path

packages_path = Path(sys.argv[1])
info_version = sys.argv[2]
info_package = sys.argv[3]
info_displayname = sys.argv[4]
info_desc = sys.argv[5]
spk_path = Path(sys.argv[6])

failed = False

def ok(msg: str) -> None:
    print(f"[PASS] {msg}")

def fail(msg: str) -> None:
    global failed
    print(f"[FAIL] {msg}")
    failed = True

data = json.loads(packages_path.read_text(encoding="utf-8"))
packages = data.get("packages")
if not isinstance(packages, list) or not packages:
    fail("packages.json has no package entries.")
    sys.exit(1)

pkg = packages[0]
if str(pkg.get("version", "")) != info_version:
    fail(f"Version mismatch: INFO={info_version}, packages.json={pkg.get('version')}")
else:
    ok(f"Version matches INFO ({info_version}).")

if str(pkg.get("package", "")) != info_package:
    fail(f"Package mismatch: INFO={info_package}, packages.json={pkg.get('package')}")
else:
    ok(f"Package key matches INFO ({info_package}).")

if str(pkg.get("displayname", "")) != info_displayname:
    fail("Displayname mismatch between INFO and packages.json.")
else:
    ok("Displayname matches INFO.")

if str(pkg.get("description", "")) != info_desc:
    fail("Description mismatch between INFO and packages.json.")
else:
    ok("Description matches INFO.")

link = str(pkg.get("link", ""))
if not link.startswith("https://github.com/") or "/releases/" not in link or not link.endswith("synology-monitor-basic.spk"):
    fail(f"Link format looks wrong: {link}")
else:
    ok("Link format looks valid for GitHub release asset.")

checksum = str(pkg.get("checksum_sha256", ""))
size = int(pkg.get("size", 0) or 0)
if checksum and len(checksum) == 64:
    ok("checksum_sha256 is present.")
else:
    fail("checksum_sha256 missing or invalid length.")

if size > 0:
    ok(f"size is set ({size} bytes).")
else:
    fail("size is missing or zero.")

if spk_path.exists():
    raw = spk_path.read_bytes()
    actual_size = len(raw)
    actual_sha = hashlib.sha256(raw).hexdigest()
    if actual_size != size:
        fail(f"SPK size mismatch: packages.json={size}, actual={actual_size}")
    else:
        ok("SPK size matches packages.json.")
    if actual_sha != checksum:
        fail("SPK SHA256 mismatch vs packages.json.")
    else:
        ok("SPK SHA256 matches packages.json.")
else:
    print("[WARN] dist/synology-monitor-basic.spk not present locally (skipping hash/size validation).")

if failed:
    sys.exit(1)
PY

if git -C "${ROOT_DIR}" rev-parse --show-toplevel >/dev/null 2>&1; then
  TOP="$(git -C "${ROOT_DIR}" rev-parse --show-toplevel)"
  TRACKED_BUILD="$(git -C "${TOP}" ls-files "addons/synology-monitor/community-package/.build/**" "addons/synology-monitor/community-package/dist/**" || true)"
  DELETED_BUILD="$(git -C "${TOP}" ls-files --deleted "addons/synology-monitor/community-package/.build/**" "addons/synology-monitor/community-package/dist/**" || true)"
  EFFECTIVE_TRACKED="${TRACKED_BUILD}"
  if [ -n "${DELETED_BUILD}" ] && [ -n "${EFFECTIVE_TRACKED}" ]; then
    EFFECTIVE_TRACKED="$(python3 - <<'PY' "${TRACKED_BUILD}" "${DELETED_BUILD}"
import sys
tracked = [x for x in sys.argv[1].splitlines() if x.strip()]
deleted = set(x for x in sys.argv[2].splitlines() if x.strip())
print("\n".join([x for x in tracked if x not in deleted]))
PY
)"
  fi
  if [ -n "${EFFECTIVE_TRACKED}" ]; then
    fail "Generated artifacts are still tracked under .build/ or dist/."
  else
    pass "No tracked generated artifacts under .build/ or dist/."
  fi
else
  warn "Not in git repo; skipped tracked-file hygiene check."
fi

if [ "${ONLINE_CHECK}" = "1" ]; then
  LINK_URL="$(python3 - "${PACKAGES_FILE}" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
print(data["packages"][0].get("link",""))
PY
)"
  if command -v curl >/dev/null 2>&1; then
    if curl -fsI "${LINK_URL}" >/dev/null; then
      pass "Online check passed for release asset URL."
    else
      fail "Online check failed for release asset URL: ${LINK_URL}"
    fi
  else
    warn "curl not available; skipped online URL check."
  fi
else
  warn "Online URL check skipped (set ONLINE_CHECK=1 to enable)."
fi

if [ "${FAILED}" -ne 0 ]; then
  echo ""
  echo "Release verification FAILED."
  exit 1
fi

echo ""
echo "Release verification PASSED."
