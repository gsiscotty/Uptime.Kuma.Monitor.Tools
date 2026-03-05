#!/usr/bin/env python3
"""
Bump addon version across all version locations.

Run before release. Requires explicit user confirmation before applying changes.

Usage:
  python3 scripts/bump-addon-version.py synology-monitor 1.0.0-0056
  python3 scripts/bump-addon-version.py unix-monitor 1.0.0-0056
  python3 scripts/bump-addon-version.py --dry-run synology-monitor 1.0.0-0056

Options:
  --dry-run    Show proposed changes only, do not apply or prompt.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Per-addon: list of (relative_path, pattern, replacement_template)
# {group_name} in pattern/replacement is replaced with the new version for matching
VERSION_LOCATIONS = {
    "synology-monitor": [
        # (file, regex pattern to find current version, replacement format)
        (
            "addons/synology-monitor/synology-monitor.py",
            r'VERSION\s*=\s*["\']([^"\']+)["\']',
            'VERSION = "{version}"',
        ),
        (
            "addons/synology-monitor/community-package/package/INFO",
            r'version\s*=\s*["\']?([^"\'\s]+)["\']?',
            'version="{version}"',
        ),
    ],
    "unix-monitor": [
        (
            "addons/unix-monitor/unix-monitor.py",
            r'VERSION\s*=\s*["\']([^"\']+)["\']',
            'VERSION = "{version}"',
        ),
    ],
}


def read_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def find_current_version(path: Path, pattern: str) -> str | None:
    text = read_file(path)
    m = re.search(pattern, text)
    return m.group(1) if m else None


def replace_version(path: Path, pattern: str, template: str, new_version: str) -> tuple[bool, str]:
    """Returns (changed, new_content)."""
    text = read_file(path)
    m = re.search(pattern, text)
    if not m:
        return False, text
    old = m.group(0)
    # Build replacement: the template uses {version}
    new_sub = template.format(version=new_version)
    new_text = text[: m.start()] + new_sub + text[m.end() :]
    return new_text != text, new_text


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bump addon version. Requires confirmation before applying."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show proposed changes only, do not apply or prompt.",
    )
    parser.add_argument(
        "addon",
        choices=list(VERSION_LOCATIONS),
        help="Addon name",
    )
    parser.add_argument(
        "new_version",
        help="New version string (e.g. 1.0.0-0056)",
    )
    args = parser.parse_args()

    addon = args.addon
    new_version = args.new_version.strip()
    if not new_version:
        print("Error: new_version cannot be empty.", file=sys.stderr)
        return 1

    locations = VERSION_LOCATIONS[addon]
    changes: list[tuple[Path, str, str, str]] = []  # (path, old, new, new_content)

    print(f"Addon: {addon}")
    print(f"New version: {new_version}")
    print()

    for rel_path, pattern, template in locations:
        path = REPO_ROOT / rel_path
        if not path.exists():
            print(f"  [SKIP] {rel_path} (file not found)")
            continue

        old_version = find_current_version(path, pattern)
        if old_version is None:
            print(f"  [WARN] {rel_path}: could not find version with pattern {pattern}")
            continue

        if old_version == new_version:
            print(f"  [OK]   {rel_path}: already {new_version}")
            continue

        changed, new_content = replace_version(path, pattern, template, new_version)
        if not changed:
            print(f"  [WARN] {rel_path}: pattern matched but replacement produced no change")
            continue

        changes.append((path, old_version, new_version, new_content))
        print(f"  [→]    {rel_path}")
        print(f"         {old_version} → {new_version}")

    if not changes:
        print()
        print("No changes to apply.")
        return 0

    print()
    if args.dry_run:
        print("DRY RUN: No changes applied. Run without --dry-run to apply.")
        return 0

    print("The following files will be modified:")
    for path, old, new, _ in changes:
        print(f"  - {path.relative_to(REPO_ROOT)} ({old} → {new})")
    print()
    try:
        response = input("Apply these changes? [y/N]: ").strip().lower()
    except EOFError:
        response = "n"
    if response not in ("y", "yes"):
        print("Aborted. No changes applied.")
        return 0

    for path, _, _, new_content in changes:
        write_file(path, new_content)
        print(f"  Updated: {path.relative_to(REPO_ROOT)}")

    print()
    print("Done. Run build before release (e.g. ./build-spk.sh for synology-monitor).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
