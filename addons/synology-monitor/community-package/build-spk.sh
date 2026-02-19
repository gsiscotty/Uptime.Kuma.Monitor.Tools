#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PACKAGE_DIR="${ROOT_DIR}/package"
DIST_DIR="${ROOT_DIR}/dist"
WORK_DIR="${ROOT_DIR}/.build"
TARGET_DIR="${WORK_DIR}/package-root"
PACKAGE_TGZ="${WORK_DIR}/package.tgz"
SPK_PATH="${DIST_DIR}/synology-monitor-basic.spk"

rm -rf "${WORK_DIR}" "${DIST_DIR}"
mkdir -p "${TARGET_DIR}" "${DIST_DIR}"

# Copy runtime payload
cp "${ROOT_DIR}/../synology-monitor.py" "${TARGET_DIR}/synology-monitor.py"
chmod 700 "${TARGET_DIR}/synology-monitor.py"
cp "${ROOT_DIR}"/../task-*.png "${TARGET_DIR}/"
chmod 644 "${TARGET_DIR}"/task-*.png

# Build package.tgz and .spk using Python tarfile to avoid macOS AppleDouble files (._*).
ROOT_DIR="${ROOT_DIR}" python3 - <<'PY'
import tarfile
import os
from pathlib import Path

root = Path(os.environ["ROOT_DIR"])
work = root / ".build"
pkg_root = work / "package-root"
pkg_tgz = work / "package.tgz"
spk = root / "dist" / "synology-monitor-basic.spk"
package_dir = root / "package"

def add_file(tf: tarfile.TarFile, src: Path, arcname: str, mode: int | None = None) -> None:
    ti = tf.gettarinfo(str(src), arcname)
    if mode is not None:
        ti.mode = mode
    ti.uid = 0
    ti.gid = 0
    ti.uname = "root"
    ti.gname = "root"
    ti.mtime = 1700000000
    with src.open("rb") as f:
        tf.addfile(ti, f)

with tarfile.open(pkg_tgz, "w:gz", format=tarfile.GNU_FORMAT) as tf:
    add_file(tf, pkg_root / "synology-monitor.py", "synology-monitor.py", mode=0o700)
    for img in sorted(pkg_root.glob("task-*.png")):
        add_file(tf, img, img.name, mode=0o644)

with tarfile.open(spk, "w", format=tarfile.GNU_FORMAT) as tf:
    add_file(tf, package_dir / "INFO", "INFO", mode=0o644)
    add_file(tf, pkg_tgz, "package.tgz", mode=0o644)
    add_file(tf, package_dir / "PACKAGE_ICON.PNG", "PACKAGE_ICON.PNG", mode=0o644)
    add_file(tf, package_dir / "PACKAGE_ICON_256.PNG", "PACKAGE_ICON_256.PNG", mode=0o644)

    for rel in sorted((package_dir / "scripts").iterdir()):
        if rel.name.startswith("."):
            continue
        add_file(tf, rel, f"scripts/{rel.name}", mode=0o755)
    for rel in sorted((package_dir / "conf").iterdir()):
        if rel.name.startswith("."):
            continue
        add_file(tf, rel, f"conf/{rel.name}", mode=0o644)
PY

echo "Built: ${SPK_PATH}"
