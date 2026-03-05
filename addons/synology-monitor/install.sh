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
UPDATE_CHANNEL="${UNIX_MONITOR_UPDATE_CHANNEL:-}"
if [ "${UNIX_MONITOR_USE_MAIN:-0}" = "1" ]; then
    UPDATE_CHANNEL="main"
fi
if [ "${UPDATE_CHANNEL}" != "main" ] && [ "${UPDATE_CHANNEL}" != "latest" ]; then
    UPDATE_CHANNEL="latest"
fi
REF="${BRANCH}"
SCRIPT_NAME="synology-monitor.py"
REMOTE_PATH="addons/synology-monitor/${SCRIPT_NAME}"
RAW_URL="https://raw.githubusercontent.com/${REPO}/${REF}/${REMOTE_PATH}"
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

resolve_ref_from_channel() {
    REF="${BRANCH}"
    if [ "${UPDATE_CHANNEL}" = "main" ]; then
        return 0
    fi
    local tag=""
    if command -v curl >/dev/null 2>&1; then
        tag=$(curl -sfL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep -o '"tag_name":[[:space:]]*"[^"]*"' | sed 's/"tag_name":[[:space:]]*"\([^"]*\)"/\1/' | head -n 1)
    elif command -v wget >/dev/null 2>&1; then
        tag=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep -o '"tag_name":[[:space:]]*"[^"]*"' | sed 's/"tag_name":[[:space:]]*"\([^"]*\)"/\1/' | head -n 1)
    fi
    [ -n "${tag}" ] && REF="${tag}"
}

detect_local_version() {
    local script_path="$1"
    if [ ! -f "${script_path}" ]; then
        echo ""
        return 0
    fi
    sed -n 's/^VERSION = "\([^"]*\)".*/\1/p' "${script_path}" | head -n 1
}

fetch_public_version_for_ref() {
    local ref="$1"
    local url="https://raw.githubusercontent.com/${REPO}/${ref}/${REMOTE_PATH}"
    local content=""
    if command -v curl >/dev/null 2>&1; then
        content="$(curl -fsSL "${url}" 2>/dev/null || true)"
    elif command -v wget >/dev/null 2>&1; then
        content="$(wget -qO- "${url}" 2>/dev/null || true)"
    fi
    printf '%s\n' "${content}" | sed -n 's/^VERSION = "\([^"]*\)".*/\1/p' | head -n 1
}

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

resolve_ref_from_channel
RAW_URL="https://raw.githubusercontent.com/${REPO}/${REF}/${REMOTE_PATH}"
LOCAL_VERSION="$(detect_local_version "${INSTALL_DIR}/${SCRIPT_NAME}")"
PUBLIC_VERSION="$(fetch_public_version_for_ref "${REF}")"
if [ -z "${PUBLIC_VERSION}" ] && [ "${REF}" != "main" ]; then
    warn "Selected ref ${REF} missing synology monitor script; falling back to main for version check."
    PUBLIC_VERSION="$(fetch_public_version_for_ref "main")"
fi
echo ""
info "Selected update source: ${UPDATE_CHANNEL} (ref: ${REF})"
info "Local version: ${LOCAL_VERSION:-unknown}"
info "Public (${UPDATE_CHANNEL}) version: ${PUBLIC_VERSION:-unknown}"

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
