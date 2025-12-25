#!/usr/bin/env bash
#===============================================================================
# CIS Ubuntu Server 24.04 LTS - Lynis Score Improvements
# Version: 1.0.0
# Date: 2025-12-25
# Author: xoelrdgz
# Description: Additional hardening measures to improve Lynis security score
#
# This script implements security measures recommended by Lynis that are
# beyond the core CIS benchmarks but improve overall security posture.
#===============================================================================

set -euo pipefail

#===============================================================================
# Configuration
#===============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
readonly LOG_FILE="/var/log/cis-hardening/lynis-improvements.log"
readonly BACKUP_DIR="/var/backups/cis-hardening/lynis-improvements"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Options
REMOVE_COMPILERS=false
HARDEN_KERNEL=true
HARDEN_NETWORK=true
SECURE_PERMISSIONS=true
DISABLE_SERVICES=true
DRY_RUN=false

#===============================================================================
# Logging Functions
#===============================================================================

setup_logging() {
    local log_dir="$(dirname "$LOG_FILE")"
    mkdir -p "$log_dir"
    mkdir -p "$BACKUP_DIR"
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo ""
    echo "=============================================="
    echo "Lynis Improvements - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=============================================="
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[DONE]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_section() {
    echo ""
    echo -e "${CYAN}[====]${NC} $*"
    echo ""
}

#===============================================================================
# Helper Functions
#===============================================================================

show_help() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Additional hardening measures to improve Lynis security score.
These are recommended security improvements beyond CIS benchmarks.

Options:
    --remove-compilers    Remove compilers (gcc, g++, make, etc.)
    --skip-kernel         Skip additional kernel hardening
    --skip-network        Skip additional network hardening
    --skip-permissions    Skip file permission hardening
    --skip-services       Skip unnecessary service removal
    --all                 Apply all improvements (includes --remove-compilers)
    --dry-run             Show what would be done without making changes
    --help                Show this help message
    --version             Show version information

WARNING: Removing compilers will prevent building software on this system.
         Only use on production servers that don't require compilation.

Examples:
    $SCRIPT_NAME                    # Standard improvements
    $SCRIPT_NAME --all              # All improvements including compiler removal
    $SCRIPT_NAME --remove-compilers # Remove compilers specifically
    $SCRIPT_NAME --dry-run --all    # Preview all changes

EOF
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup="$BACKUP_DIR/$(basename "$file").$(date +%Y%m%d_%H%M%S)"
        cp "$file" "$backup"
        log_info "Backed up: $file -> $backup"
    fi
}

#===============================================================================
# Compiler Removal
#===============================================================================

remove_compilers() {
    log_section "Removing Compilers and Build Tools"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would remove compilers and build tools"
        dpkg -l | grep -E "^ii.*(gcc|g\+\+|cpp|make|dpkg-dev|libc6-dev|build-essential)" || true
        return 0
    fi
    
    # List of compiler/build packages to remove
    local packages=(
        "gcc"
        "g++"
        "cpp"
        "make"
        "build-essential"
        "dpkg-dev"
        "libc6-dev"
        "libc-dev-bin"
        "libstdc++-*-dev"
        "linux-headers-*"
        "linux-libc-dev"
        "gcc-*"
        "g++-*"
        "gfortran"
        "gfortran-*"
    )
    
    local removed=0
    for pkg in "${packages[@]}"; do
        if dpkg -l | grep -qE "^ii.*$pkg"; then
            log_info "Removing: $pkg"
            apt-get remove -y --purge "$pkg" 2>/dev/null || true
            ((removed++)) || true
        fi
    done
    
    if [[ $removed -gt 0 ]]; then
        apt-get autoremove -y 2>/dev/null || true
        log_success "Removed $removed compiler/build packages"
    else
        log_info "No compiler packages found to remove"
    fi
    
    # Verify removal
    if command -v gcc &>/dev/null || command -v g++ &>/dev/null || command -v make &>/dev/null; then
        log_warning "Some compilers may still be present"
    else
        log_success "Compilers successfully removed"
    fi
}

#===============================================================================
# Additional Kernel Hardening
#===============================================================================

apply_kernel_hardening() {
    log_section "Applying Additional Kernel Hardening"
    
    local sysctl_file="/etc/sysctl.d/99-lynis-hardening.conf"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would create $sysctl_file with additional kernel parameters"
        return 0
    fi
    
    backup_file "$sysctl_file"
    
    cat > "$sysctl_file" << 'EOF'
# Lynis Recommended Kernel Hardening
# Applied by: CIS Hardening Scripts
# Date: Generated automatically

#===============================================================================
# Memory Protection
#===============================================================================

# Restrict dmesg access to root only
kernel.dmesg_restrict = 1

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict performance events to root
kernel.perf_event_paranoid = 3

# Disable magic SysRq key (emergency debugging)
# Set to 0 for production, 1 for some functions, 176 for safe functions
kernel.sysrq = 0

# Restrict BPF to root only
kernel.unprivileged_bpf_disabled = 1

# Restrict userfaultfd to root
vm.unprivileged_userfaultfd = 0

#===============================================================================
# Network Hardening (Additional)
#===============================================================================

# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# RFC 1337 protection
net.ipv4.tcp_rfc1337 = 1

# Protect against time-wait assassination
net.ipv4.tcp_max_tw_buckets = 1440000

# Limit local port range
net.ipv4.ip_local_port_range = 32768 65535

# TCP Hardening
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

#===============================================================================
# Filesystem Hardening
#===============================================================================

# Restrict hardlinks and symlinks
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Protect FIFOs and regular files in world-writable directories
fs.protected_fifos = 2
fs.protected_regular = 2

EOF

    chmod 644 "$sysctl_file"
    
    # Apply settings
    sysctl -p "$sysctl_file" 2>/dev/null || log_warning "Some sysctl settings may have failed"
    
    log_success "Additional kernel hardening applied"
}

#===============================================================================
# Additional Network Hardening
#===============================================================================

apply_network_hardening() {
    log_section "Applying Additional Network Hardening"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would apply additional network hardening"
        return 0
    fi
    
    # Disable DCCP protocol (rarely used, potential vulnerability)
    local dccp_conf="/etc/modprobe.d/dccp.conf"
    if [[ ! -f "$dccp_conf" ]]; then
        echo "install dccp /bin/true" > "$dccp_conf"
        echo "blacklist dccp" >> "$dccp_conf"
        log_success "Disabled DCCP protocol"
    fi
    
    # Disable SCTP protocol (rarely used)
    local sctp_conf="/etc/modprobe.d/sctp.conf"
    if [[ ! -f "$sctp_conf" ]]; then
        echo "install sctp /bin/true" > "$sctp_conf"
        echo "blacklist sctp" >> "$sctp_conf"
        log_success "Disabled SCTP protocol"
    fi
    
    # Disable RDS protocol
    local rds_conf="/etc/modprobe.d/rds.conf"
    if [[ ! -f "$rds_conf" ]]; then
        echo "install rds /bin/true" > "$rds_conf"
        echo "blacklist rds" >> "$rds_conf"
        log_success "Disabled RDS protocol"
    fi
    
    # Disable TIPC protocol
    local tipc_conf="/etc/modprobe.d/tipc.conf"
    if [[ ! -f "$tipc_conf" ]]; then
        echo "install tipc /bin/true" > "$tipc_conf"
        echo "blacklist tipc" >> "$tipc_conf"
        log_success "Disabled TIPC protocol"
    fi
    
    log_success "Additional network hardening complete"
}

#===============================================================================
# File Permission Hardening
#===============================================================================

apply_permission_hardening() {
    log_section "Applying File Permission Hardening"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would apply file permission hardening"
        return 0
    fi
    
    # Secure cron directories
    local cron_dirs=(
        "/etc/crontab"
        "/etc/cron.hourly"
        "/etc/cron.daily"
        "/etc/cron.weekly"
        "/etc/cron.monthly"
        "/etc/cron.d"
    )
    
    for item in "${cron_dirs[@]}"; do
        if [[ -e "$item" ]]; then
            chown root:root "$item"
            if [[ -d "$item" ]]; then
                chmod og-rwx "$item"
            else
                chmod og-rwx "$item"
            fi
            log_info "Secured: $item"
        fi
    done
    
    # Secure at.allow and at.deny
    if [[ -f /etc/at.deny ]]; then
        rm -f /etc/at.deny
    fi
    if [[ ! -f /etc/at.allow ]]; then
        touch /etc/at.allow
        chown root:root /etc/at.allow
        chmod 640 /etc/at.allow
        log_success "Created restrictive /etc/at.allow"
    fi
    
    # Secure cron.allow and cron.deny
    if [[ -f /etc/cron.deny ]]; then
        rm -f /etc/cron.deny
    fi
    if [[ ! -f /etc/cron.allow ]]; then
        touch /etc/cron.allow
        chown root:root /etc/cron.allow
        chmod 640 /etc/cron.allow
        log_success "Created restrictive /etc/cron.allow"
    fi
    
    # Set restrictive umask in login.defs
    if [[ -f /etc/login.defs ]]; then
        backup_file /etc/login.defs
        sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
        log_success "Set UMASK to 027 in login.defs"
    fi
    
    # Secure home directories
    log_info "Securing home directories..."
    for dir in /home/*; do
        if [[ -d "$dir" ]]; then
            chmod 750 "$dir" 2>/dev/null || true
        fi
    done
    
    log_success "File permission hardening complete"
}

#===============================================================================
# Disable Unnecessary Services
#===============================================================================

disable_unnecessary_services() {
    log_section "Disabling Unnecessary Services"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would disable unnecessary services"
        return 0
    fi
    
    # Services typically not needed on a hardened server
    local services=(
        "avahi-daemon"      # mDNS/DNS-SD
        "cups"              # Printing
        "cups-browsed"      # Printer browsing
        "isc-dhcp-server"   # DHCP server
        "isc-dhcp-server6"  # DHCPv6 server
        "slapd"             # LDAP server
        "nfs-server"        # NFS server
        "rpcbind"           # RPC
        "rsync"             # rsync daemon
        "smbd"              # Samba
        "snmpd"             # SNMP
        "squid"             # Proxy
        "vsftpd"            # FTP server
        "xinetd"            # Internet services
        "autofs"            # Automount
        "bluetooth"         # Bluetooth
    )
    
    local disabled=0
    for svc in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "^$svc"; then
            if systemctl is-enabled "$svc" &>/dev/null; then
                systemctl stop "$svc" 2>/dev/null || true
                systemctl disable "$svc" 2>/dev/null || true
                log_info "Disabled: $svc"
                ((disabled++)) || true
            fi
        fi
    done
    
    if [[ $disabled -gt 0 ]]; then
        log_success "Disabled $disabled unnecessary services"
    else
        log_info "No unnecessary services found to disable"
    fi
}

#===============================================================================
# Configure Secure Shell Banner
#===============================================================================

configure_banners() {
    log_section "Configuring Security Banners"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would configure security banners"
        return 0
    fi
    
    # Create issue files with warning banner
    local banner_text="
================================================================================
                          AUTHORIZED ACCESS ONLY
================================================================================

This system is the property of the organization. Unauthorized access is 
prohibited and may be subject to legal action.

All activities on this system are monitored and logged. By accessing this 
system, you consent to such monitoring and acknowledge that any evidence of
unauthorized access or criminal activity may be provided to law enforcement.

================================================================================
"

    echo "$banner_text" > /etc/issue
    echo "$banner_text" > /etc/issue.net
    
    # Remove OS information from motd
    if [[ -f /etc/update-motd.d/10-help-text ]]; then
        chmod -x /etc/update-motd.d/10-help-text 2>/dev/null || true
    fi
    if [[ -f /etc/update-motd.d/50-motd-news ]]; then
        chmod -x /etc/update-motd.d/50-motd-news 2>/dev/null || true
    fi
    
    log_success "Security banners configured"
}

#===============================================================================
# Configure Process Accounting
#===============================================================================

configure_accounting() {
    log_section "Configuring Process Accounting"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would configure process accounting"
        return 0
    fi
    
    # Enable process accounting if available
    if command -v accton &>/dev/null; then
        touch /var/log/pacct
        accton /var/log/pacct 2>/dev/null || true
        log_success "Process accounting enabled"
    else
        log_info "Process accounting tools not installed (install 'acct' package)"
    fi
}

#===============================================================================
# Harden Shell Timeout
#===============================================================================

configure_shell_timeout() {
    log_section "Configuring Shell Timeout"
    
    local profile_file="/etc/profile.d/timeout.sh"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would create $profile_file"
        return 0
    fi
    
    cat > "$profile_file" << 'EOF'
# Automatic logout after 15 minutes of inactivity
# Part of CIS Hardening
readonly TMOUT=900
export TMOUT
EOF

    chmod 644 "$profile_file"
    log_success "Shell timeout configured (900 seconds)"
}

#===============================================================================
# Main Execution
#===============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --remove-compilers)
                REMOVE_COMPILERS=true
                shift
                ;;
            --skip-kernel)
                HARDEN_KERNEL=false
                shift
                ;;
            --skip-network)
                HARDEN_NETWORK=false
                shift
                ;;
            --skip-permissions)
                SECURE_PERMISSIONS=false
                shift
                ;;
            --skip-services)
                DISABLE_SERVICES=false
                shift
                ;;
            --all)
                REMOVE_COMPILERS=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --version|-v)
                echo "$SCRIPT_NAME version $SCRIPT_VERSION"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Setup
    check_root
    setup_logging
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_warning "DRY RUN MODE - No changes will be made"
    fi
    
    # Apply improvements
    if [[ "$HARDEN_KERNEL" == "true" ]]; then
        apply_kernel_hardening
    fi
    
    if [[ "$HARDEN_NETWORK" == "true" ]]; then
        apply_network_hardening
    fi
    
    if [[ "$SECURE_PERMISSIONS" == "true" ]]; then
        apply_permission_hardening
    fi
    
    if [[ "$DISABLE_SERVICES" == "true" ]]; then
        disable_unnecessary_services
    fi
    
    configure_banners
    configure_shell_timeout
    configure_accounting
    
    if [[ "$REMOVE_COMPILERS" == "true" ]]; then
        log_warning "Compiler removal requested - this cannot be easily undone"
        remove_compilers
    fi
    
    # Summary
    echo ""
    echo "==============================================================================="
    log_success "Lynis improvements complete"
    echo "==============================================================================="
    echo ""
    echo "Applied improvements:"
    echo "  - Kernel hardening:    $(if $HARDEN_KERNEL; then echo 'Applied'; else echo 'Skipped'; fi)"
    echo "  - Network hardening:   $(if $HARDEN_NETWORK; then echo 'Applied'; else echo 'Skipped'; fi)"
    echo "  - Permission hardening:$(if $SECURE_PERMISSIONS; then echo 'Applied'; else echo 'Skipped'; fi)"
    echo "  - Service removal:     $(if $DISABLE_SERVICES; then echo 'Applied'; else echo 'Skipped'; fi)"
    echo "  - Compiler removal:    $(if $REMOVE_COMPILERS; then echo 'Applied'; else echo 'Skipped'; fi)"
    echo "  - Security banners:    Applied"
    echo "  - Shell timeout:       Applied"
    echo ""
    echo "Next Steps:"
    echo "  1. Reboot to apply all kernel module changes"
    echo "  2. Run: lynis audit system"
    echo "  3. Review Lynis report for remaining suggestions"
    echo ""
    echo "Log file: $LOG_FILE"
    echo ""
}

main "$@"

