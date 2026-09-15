#!/usr/bin/env bash
#
# install.sh - single-command installer for the SmartUI panel.
#
# Usage once hosted on GitHub:
#   bash <(curl -Ls https://raw.githubusercontent.com/<YOUR_ORG>/<YOUR_REPO>/main/install.sh)
#
# REPO_URL below is a placeholder - this script has no way to know where you
# actually host the finished panel, since nothing in this project has publish
# access to GitHub on your behalf. Set it to your real repository before this
# one-liner will work for anyone else.

set -euo pipefail

REPO_URL="https://github.com/Zico4real/Smartui.git"
INSTALL_DIR="/opt/smartui"
BIN_LINK="/usr/local/bin/smartui"
STATE_DIR="/etc/smartui"

C_RED='\033[91m'
C_GREEN='\033[92m'
C_YELLOW='\033[93m'
C_CYAN='\033[96m'
C_RESET='\033[0m'

log_info()  { echo -e "${C_CYAN}[i]${C_RESET} $1"; }
log_ok()    { echo -e "${C_GREEN}[OK]${C_RESET} $1"; }
log_warn()  { echo -e "${C_YELLOW}[!]${C_RESET} $1"; }
log_error() { echo -e "${C_RED}[X]${C_RESET} $1"; }

if [ "$(id -u)" -ne 0 ]; then
    log_error "Run this as root (sudo bash <(curl -Ls ...))."
    exit 1
fi

if [ ! -f /etc/os-release ]; then
    log_error "Couldn't detect the OS - this installer targets Ubuntu/Debian."
    exit 1
fi
. /etc/os-release
case "$ID" in
    ubuntu|debian) ;;
    *)
        log_warn "This has only been built and tested against Ubuntu/Debian - detected"
        log_warn "'$ID'. Continuing anyway, but expect some module-level apt-get calls"
        log_warn "inside the panel itself to fail on a different base distro."
        ;;
esac

log_info "Installing base dependencies (git, curl, python3, python3-pip)..."
apt-get update -qq
apt-get install -y -qq git curl python3 python3-pip >/dev/null

if [ "$REPO_URL" = "https://github.com/YOUR_ORG/YOUR_REPO.git" ]; then
    log_error "REPO_URL in this script is still the placeholder - edit it to point at"
    log_error "your actual repository before running this installer."
    exit 1
fi

if [ -d "$INSTALL_DIR/.git" ]; then
    log_info "Existing install found at $INSTALL_DIR - updating rather than re-cloning."
    git -C "$INSTALL_DIR" fetch --quiet
    git -C "$INSTALL_DIR" reset --hard origin/main --quiet
else
    log_info "Cloning into $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
    git clone --quiet "$REPO_URL" "$INSTALL_DIR"
fi

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

log_info "Verifying the panel actually imports cleanly before wiring up the command..."
if ! python3 -c "
import sys
sys.path.insert(0, '$INSTALL_DIR')
import smartui_main
" 2>/tmp/smartui_install_check.log; then
    log_error "smartui_main.py failed to import - not installing the 'smartui' command."
    log_error "Details:"
    cat /tmp/smartui_install_check.log
    exit 1
fi
log_ok "Panel imports cleanly."

cat > "$BIN_LINK" <<EOF
#!/usr/bin/env bash
cd "$INSTALL_DIR"
exec python3 "$INSTALL_DIR/smartui_main.py"
EOF
chmod +x "$BIN_LINK"

if [ ! -x "$BIN_LINK" ]; then
    log_error "Failed to install the 'smartui' command to $BIN_LINK."
    exit 1
fi

echo ""
log_ok "Installed. Run the panel with:"
echo ""
echo -e "    ${C_GREEN}smartui${C_RESET}"
echo ""
log_info "Individual protocols (SSH, OpenVPN, Xray, etc.) are installed on-demand"
log_info "from inside the panel itself, not by this installer - this script only"
log_info "sets up the panel program and its own dependencies."
