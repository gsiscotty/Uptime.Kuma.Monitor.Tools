#!/bin/bash

#########################################
# Created by: gsi_scotty                #
# Date: 2026-02-19                      #
# Description: Download and set up the  #
# synology-monitor.py script for        #
# Synology NAS SMART + storage checks.  #
# Version: 1.0.0                        #
#########################################

set -euo pipefail

REPO="gsiscotty/Uptime.Kuma.Monitor.Tools"
BRANCH="main"
SCRIPT_NAME="synology-monitor.py"
REMOTE_PATH="addons/synology-monitor/${SCRIPT_NAME}"
RAW_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/${REMOTE_PATH}"
DEFAULT_INSTALL_DIR="/opt/synology-monitor"
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

info()  { echo -e "${GREEN}[ok]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[x]${NC} $*"; }

echo ""
echo -e "${BOLD}EasySystems GmbH - Kuma Monitor Addon Installer${NC}"
echo -e "${BOLD}EasySystems GmbH${NC} | https://www.easysystems.ch/de"
echo "-------------------------------------"
echo ""

if ! command -v python3 >/dev/null 2>&1; then
    err "python3 not found."
    echo -e "Please install Python 3.8+ and re-run."
    exit 1
fi

PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [ "${PY_MAJOR}" -lt ${MIN_PYTHON_MAJOR} ] || { [ "${PY_MAJOR}" -eq ${MIN_PYTHON_MAJOR} ] && [ "${PY_MINOR}" -lt ${MIN_PYTHON_MINOR} ]; }; then
    err "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ required."
    exit 1
fi
info "Python $(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")') found"

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

FIRST_LINE="$(sed -n '1p' "${TARGET}")"
if [[ "${FIRST_LINE}" != "#!/usr/bin/env python3"* ]]; then
    err "Downloaded file is not the expected script."
    rm -f "${TARGET}"
    exit 1
fi

chmod 700 "${TARGET}"
info "Installed to ${TARGET}"

echo ""
echo "Next steps:"
echo "  1) Start UI setup: python3 ${TARGET} --ui --port 8787"
echo "  2) Open http://<synology-ip>:8787"
echo "  3) Optional: use CLI setup via python3 ${TARGET}"
echo "  4) Optional: enable cron in menu (custom interval)"
echo ""
echo "Dependencies for full checks:"
echo "  - smartctl (smartmontools)"
echo "  - nvme-cli (optional, for NVMe checks)"
echo "  - synospace (native Synology command)"
echo ""
echo "Author: Konrad von Burg"
echo "Copyright (c) 2026 EasySystems GmbH. All rights reserved."
echo "Website: https://www.easysystems.ch/de"
echo "-------------------------------------"
