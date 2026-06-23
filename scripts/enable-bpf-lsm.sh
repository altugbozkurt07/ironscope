#!/usr/bin/env bash
# enable-bpf-lsm.sh — Enable BPF LSM on Ubuntu/Debian systems.
# Requires: sudo, GRUB bootloader, reboot after running.
#
# Usage: sudo ./scripts/enable-bpf-lsm.sh
#        # then reboot

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# --- Pre-checks ---

if [[ $EUID -ne 0 ]]; then
    error "Must run as root: sudo $0"
fi

CURRENT_LSMS=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "")
if echo "$CURRENT_LSMS" | grep -q "bpf"; then
    info "BPF LSM is already enabled: $CURRENT_LSMS"
    exit 0
fi

warn "Current LSMs: $CURRENT_LSMS"
warn "BPF LSM is not enabled. Configuring..."

KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
if [[ $KERNEL_MAJOR -lt 5 ]] || { [[ $KERNEL_MAJOR -eq 5 ]] && [[ $KERNEL_MINOR -lt 7 ]]; }; then
    error "Kernel $KERNEL_VERSION is too old. BPF LSM requires >= 5.7."
fi
info "Kernel $KERNEL_VERSION supports BPF LSM."

# --- Check BPF LSM compiled into kernel ---

KCONFIG="/boot/config-${KERNEL_VERSION}"
if [[ -f "$KCONFIG" ]]; then
    if grep -q "CONFIG_BPF_LSM=y" "$KCONFIG"; then
        info "CONFIG_BPF_LSM=y found in $KCONFIG"
    else
        error "CONFIG_BPF_LSM is not enabled in $KCONFIG. Need a kernel compiled with CONFIG_BPF_LSM=y."
    fi
else
    warn "No kernel config at $KCONFIG — skipping compile-time check."
fi

# --- Update GRUB ---

GRUB_FILE="/etc/default/grub"
if [[ ! -f "$GRUB_FILE" ]]; then
    error "$GRUB_FILE not found. Non-GRUB systems need manual boot param configuration."
fi

# Build the new LSM list: append bpf to whatever is currently active
NEW_LSMS="${CURRENT_LSMS},bpf"

# The param we need to inject
LSM_PARAM="lsm=${NEW_LSMS}"

CURRENT_CMDLINE=$(grep '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_FILE" | head -1)
info "Current GRUB_CMDLINE_LINUX_DEFAULT: $CURRENT_CMDLINE"

# Remove any existing lsm= param, then append ours
CLEANED=$(echo "$CURRENT_CMDLINE" | sed -E 's/lsm=[^ "]*//g' | sed 's/  */ /g')
# Insert our param before the closing quote
NEW_CMDLINE=$(echo "$CLEANED" | sed "s/\"$/ ${LSM_PARAM}\"/")

info "New GRUB_CMDLINE_LINUX_DEFAULT: $NEW_CMDLINE"

# Back up and write
cp "$GRUB_FILE" "${GRUB_FILE}.bak.$(date +%s)"
sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|${NEW_CMDLINE}|" "$GRUB_FILE"

info "Updated $GRUB_FILE"

# --- Regenerate GRUB config ---

if command -v update-grub &>/dev/null; then
    info "Running update-grub..."
    update-grub
elif command -v grub2-mkconfig &>/dev/null; then
    info "Running grub2-mkconfig..."
    grub2-mkconfig -o /boot/grub2/grub.cfg
elif command -v grub-mkconfig &>/dev/null; then
    info "Running grub-mkconfig..."
    grub-mkconfig -o /boot/grub/grub.cfg
else
    warn "No grub update command found. Run your distro's grub config regeneration manually."
fi

# --- Done ---

echo ""
info "BPF LSM configured. Reboot to activate:"
echo "    sudo reboot"
echo ""
echo "After reboot, verify with:"
echo "    cat /sys/kernel/security/lsm"
echo "    # Should include: ...bpf"
