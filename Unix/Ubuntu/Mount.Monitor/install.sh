#!/bin/bash

#########################################
# Created by: gsi_scotty                #
# Date: 2026-02-18                      #
# Description: Download and set up the  #
# mount-monitor.py script for Uptime    #
# Kuma push monitoring of mounted       #
# shares and filesystems.               #
# Version: 1.1.0                        #
#                                       #
# Usage:                                #
#   curl -sL <raw-url> | bash           #
#   or: bash install.sh                 #
#                                       #
# Note:                                 #
# - Works when piped (curl | bash)      #
# - Verifies download succeeded         #
# - Checks write permissions            #
# - Sets secure file permissions (700)  #
#########################################

set -euo pipefail

REPO="gsiscotty/kuma-management-console"
BRANCH="main"
SCRIPT_NAME="mount-monitor.py"
REMOTE_PATH="Unix/Ubuntu/Mount.Monitor/${SCRIPT_NAME}"
RAW_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/${REMOTE_PATH}"
DEFAULT_INSTALL_DIR="/opt/mount-monitor"
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=8

# Read from /dev/tty so prompts work even when piped (curl | bash)
read_input() {
    read -r "$@" </dev/tty
}

# Colors (disabled if not a terminal)
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

echo ""
echo -e "${BOLD}Mount Monitor — Installer${NC}"
echo -e "${BOLD}Uptime Kuma Monitor Tools${NC}"
echo "─────────────────────────────────────"
echo ""

# ── Check / install Python 3.8+ ──
install_python() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "${ID:-}${ID_LIKE:-}" in
            *debian*|*ubuntu*)
                warn "Installing python3 via apt..."
                sudo apt-get update -qq && sudo apt-get install -y -qq python3 ;;
            *fedora*|*rhel*|*centos*)
                warn "Installing python3 via dnf..."
                sudo dnf install -y -q python3 ;;
            *arch*)
                warn "Installing python3 via pacman..."
                sudo pacman -Sy --noconfirm python ;;
            *suse*)
                warn "Installing python3 via zypper..."
                sudo zypper install -y python3 ;;
            *)
                return 1 ;;
        esac
    elif [ "$(uname -s)" = "Darwin" ]; then
        if command -v brew &>/dev/null; then
            warn "Installing python3 via Homebrew..."
            brew install python3
        else
            return 1
        fi
    else
        return 1
    fi
}

if ! command -v python3 &>/dev/null; then
    warn "python3 is not installed."
    echo ""
    echo -e "  The mount-monitor script requires Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+."
    echo -e "  Would you like to install it now? (y/N): \c"
    read_input INSTALL_PY || true
    if [[ "${INSTALL_PY:-n}" =~ ^[Yy]$ ]]; then
        if install_python; then
            if command -v python3 &>/dev/null; then
                info "python3 installed successfully."
            else
                err "Installation finished but python3 was not found in PATH."
                exit 1
            fi
        else
            err "Automatic install not supported on this system."
            echo "  Install manually:"
            echo "    Debian/Ubuntu:  sudo apt install python3"
            echo "    Fedora/RHEL:    sudo dnf install python3"
            echo "    Arch:           sudo pacman -S python"
            echo "    macOS:          brew install python3"
            exit 1
        fi
    else
        err "python3 is required. Aborting."
        exit 1
    fi
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

if [ "${PY_MAJOR}" -lt ${MIN_PYTHON_MAJOR} ] || { [ "${PY_MAJOR}" -eq ${MIN_PYTHON_MAJOR} ] && [ "${PY_MINOR}" -lt ${MIN_PYTHON_MINOR} ]; }; then
    err "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ required, found ${PY_VERSION}."
    echo ""
    echo "  Your system has Python ${PY_VERSION} which is too old."
    echo "  Please upgrade to Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+."
    exit 1
fi
PYTHON3_PATH=$(command -v python3)
info "Python ${PY_VERSION} found (${PYTHON3_PATH})"

# ── Check curl or wget ──
if command -v curl &>/dev/null; then
    DOWNLOADER="curl"
elif command -v wget &>/dev/null; then
    DOWNLOADER="wget"
else
    err "curl or wget is required but neither was found."
    echo "  Install: sudo apt install curl"
    exit 1
fi
info "Using ${DOWNLOADER} for download"

# ── Choose install directory ──
echo ""
echo -e "Install directory [${BOLD}${DEFAULT_INSTALL_DIR}${NC}]: \c"
read_input CUSTOM_DIR || true
INSTALL_DIR="${CUSTOM_DIR:-${DEFAULT_INSTALL_DIR}}"

# ── Create directory if needed ──
if [ ! -d "${INSTALL_DIR}" ]; then
    echo ""
    warn "Directory ${INSTALL_DIR} does not exist."
    echo -e "Create it? (y/N): \c"
    read_input CREATE || true
    if [[ "${CREATE:-n}" =~ ^[Yy]$ ]]; then
        if [ -w "$(dirname "${INSTALL_DIR}")" ]; then
            mkdir -p "${INSTALL_DIR}"
        else
            echo "  (requires sudo)"
            sudo mkdir -p "${INSTALL_DIR}"
            sudo chown "$(id -u):$(id -g)" "${INSTALL_DIR}"
        fi
        info "Created ${INSTALL_DIR}"
    else
        err "Aborted."
        exit 1
    fi
fi

# ── Check write permissions ──
if [ ! -w "${INSTALL_DIR}" ]; then
    err "No write permission to ${INSTALL_DIR}"
    echo "  Fix: sudo chown $(whoami) ${INSTALL_DIR}"
    echo "  Or choose a different directory."
    exit 1
fi

# ── Download script ──
echo ""
info "Downloading ${SCRIPT_NAME}..."
TARGET="${INSTALL_DIR}/${SCRIPT_NAME}"

if [ "${DOWNLOADER}" = "curl" ]; then
    HTTP_CODE=$(curl -fsSL -w "%{http_code}" "${RAW_URL}" -o "${TARGET}")
else
    wget -qO "${TARGET}" "${RAW_URL}"
    HTTP_CODE="200"
fi

# ── Verify download ──
if [ ! -f "${TARGET}" ] || [ ! -s "${TARGET}" ]; then
    err "Download failed — file is empty or missing."
    echo "  URL: ${RAW_URL}"
    exit 1
fi

# Check it's actually Python (not a 404 HTML page)
FIRST_LINE=$(head -1 "${TARGET}")
if [[ "${FIRST_LINE}" != "#!/usr/bin/env python3"* ]]; then
    err "Downloaded file does not look like a Python script."
    echo "  First line: ${FIRST_LINE}"
    echo "  URL may be incorrect: ${RAW_URL}"
    rm -f "${TARGET}"
    exit 1
fi

info "Downloaded successfully (HTTP ${HTTP_CODE})"

# ── Set permissions ──
chmod 700 "${TARGET}"
info "Permissions set to 700 (owner: read/write/execute only)"

# ── Summary ──
echo ""
echo "─────────────────────────────────────"
echo -e "${GREEN}${BOLD}Installation complete!${NC}"
echo ""
echo "  Next steps:"
echo ""
echo "  1) Run the interactive menu:"
echo -e "     ${BOLD}cd ${INSTALL_DIR} && python3 ${SCRIPT_NAME}${NC}"
echo ""
echo "  2) Add monitors (option 1 in the menu):"
echo "     - Select mounts to monitor"
echo "     - Enter your Kuma push URL"
echo "       (create a Push monitor in Kuma first)"
echo ""
echo "  3) Test the push (option 6):"
echo "     - Verifies connectivity to Kuma"
echo ""
echo "  4) Schedule automatic checks (option 5):"
echo "     - Set interval (1–120 minutes)"
echo "     - Cron job is added automatically"
echo ""
echo "  5) Or run a one-off check:"
echo -e "     ${BOLD}python3 ${TARGET} --run${NC}"
echo ""
echo "  Config is stored in:"
echo "    ${INSTALL_DIR}/mount-monitor.json"
echo "    (or ~/.config/mount-monitor.json)"
echo ""
echo "─────────────────────────────────────"
