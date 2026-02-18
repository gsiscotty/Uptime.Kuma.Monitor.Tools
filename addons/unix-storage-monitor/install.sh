#!/bin/bash

#########################################
# Created by: gsi_scotty                #
# Date: 2026-02-18                      #
# Description: Download and set up the  #
# unix-storage-monitor.py script for    #
# Ubuntu/Unix storage + SMART checks.   #
# Version: 1.0.0                        #
#########################################

set -euo pipefail

REPO="gsiscotty/Uptime.Kuma.Monitor.Tools"
BRANCH="main"
SCRIPT_NAME="unix-storage-monitor.py"
REMOTE_PATH="addons/unix-storage-monitor/${SCRIPT_NAME}"
RAW_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/${REMOTE_PATH}"
DEFAULT_INSTALL_DIR="/opt/unix-storage-monitor"
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=8

read_input() {
    read -r "$@" </dev/tty
}

if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    GREEN='' YELLOW='' RED='' BOLD='' NC=''
fi

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*"; }

install_python() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "${ID:-}${ID_LIKE:-}" in
            *debian*|*ubuntu*) sudo apt-get update -qq && sudo apt-get install -y -qq python3 ;;
            *fedora*|*rhel*|*centos*) sudo dnf install -y -q python3 ;;
            *arch*) sudo pacman -Sy --noconfirm python ;;
            *suse*) sudo zypper install -y python3 ;;
            *) return 1 ;;
        esac
    elif [ "$(uname -s)" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
        brew install python3
    else
        return 1
    fi
}

echo ""
echo -e "${BOLD}Unix Storage Monitor — Installer${NC}"
echo -e "${BOLD}Uptime Kuma Monitor Tools${NC}"
echo "─────────────────────────────────────"
echo ""

if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 not found."
    echo -e "Install python3 now? (y/N): \c"
    read_input INSTALL_PY || true
    if [[ "${INSTALL_PY:-n}" =~ ^[Yy]$ ]]; then
        warn "Installing python3..."
        if ! install_python; then
            err "Automatic install failed/unsupported."
            exit 1
        fi
        info "python3 installed."
    else
        err "python3 required. Aborting."
        exit 1
    fi
fi

PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [ "${PY_MAJOR}" -lt ${MIN_PYTHON_MAJOR} ] || { [ "${PY_MAJOR}" -eq ${MIN_PYTHON_MAJOR} ] && [ "${PY_MINOR}" -lt ${MIN_PYTHON_MINOR} ]; }; then
    err "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ required."
    exit 1
fi
info "Python $(python3 -c 'import sys; print(f\"{sys.version_info.major}.{sys.version_info.minor}\")') found"

if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER="wget"
else
    err "curl or wget required."
    exit 1
fi

echo -e "Install directory [${BOLD}${DEFAULT_INSTALL_DIR}${NC}]: \c"
read_input CUSTOM_DIR || true
INSTALL_DIR="${CUSTOM_DIR:-${DEFAULT_INSTALL_DIR}}"

if [ ! -d "${INSTALL_DIR}" ]; then
    warn "Directory ${INSTALL_DIR} does not exist."
    echo -e "Create it? (y/N): \c"
    read_input CREATE || true
    if [[ "${CREATE:-n}" =~ ^[Yy]$ ]]; then
        if [ -w "$(dirname "${INSTALL_DIR}")" ]; then
            mkdir -p "${INSTALL_DIR}"
        else
            sudo mkdir -p "${INSTALL_DIR}"
            sudo chown "$(id -u):$(id -g)" "${INSTALL_DIR}"
        fi
    else
        err "Aborted."
        exit 1
    fi
fi

if [ ! -w "${INSTALL_DIR}" ]; then
    err "No write permission to ${INSTALL_DIR}"
    exit 1
fi

TARGET="${INSTALL_DIR}/${SCRIPT_NAME}"
info "Downloading ${SCRIPT_NAME}..."
if [ "${DOWNLOADER}" = "curl" ]; then
    curl -fsSL "${RAW_URL}" -o "${TARGET}"
else
    wget -qO "${TARGET}" "${RAW_URL}"
fi

if [ ! -s "${TARGET}" ]; then
    err "Download failed."
    exit 1
fi
FIRST_LINE="$(head -1 "${TARGET}")"
if [[ "${FIRST_LINE}" != "#!/usr/bin/env python3"* ]]; then
    err "Downloaded file is not the expected script."
    rm -f "${TARGET}"
    exit 1
fi

chmod 700 "${TARGET}"
info "Installed to ${TARGET}"

echo ""
echo "Next steps:"
echo "  1) cd ${INSTALL_DIR} && python3 ${SCRIPT_NAME}"
echo "  2) Add monitor(s) and Kuma push URL"
echo "  3) Optional: enable cron in menu"
echo ""
echo "Note: SMART checks require root and smartctl."
echo "      Install smartctl via: sudo apt install smartmontools"
echo "─────────────────────────────────────"
