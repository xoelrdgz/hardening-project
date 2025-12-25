#!/usr/bin/env bash
#===============================================================================
# CIS Ubuntu Server 24.04 LTS - Security Tools Installation
# Version: 1.0.0
# Date: 2025-12-25
# Author: xoelrdgz
# Description: Installs security tools to improve Lynis score and overall security
#
# CIS Controls Addressed:
#   - 6.3.1: AIDE filesystem integrity checking
#   - 6.2.x: Audit system (auditd)
#   - Multiple Lynis recommendations
#===============================================================================

set -euo pipefail

#===============================================================================
# Configuration
#===============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
readonly LOG_FILE="/var/log/cis-hardening/security-tools-install.log"

# Tool categories
declare -A TOOLS_ESSENTIAL=(
    ["lynis"]="Security auditing tool"
    ["auditd"]="Linux audit framework"
    ["audispd-plugins"]="Audit dispatcher plugins"
    ["aide"]="File integrity monitoring"
    ["rkhunter"]="Rootkit detection"
    ["chkrootkit"]="Rootkit checker"
)

declare -A TOOLS_RECOMMENDED=(
    ["fail2ban"]="Intrusion prevention"
    ["clamav"]="Antivirus engine"
    ["clamav-daemon"]="Antivirus daemon"
    ["clamav-freshclam"]="Virus database updater"
    ["debsums"]="Package verification"
    ["apt-show-versions"]="Show package versions"
    ["needrestart"]="Restart notification"
    ["libpam-tmpdir"]="Secure temp directories"
    ["apt-listchanges"]="Package changelog viewer"
    ["debsecan"]="CVE vulnerability scanner"
    ["apt-listbugs"]="Package bug tracker"
)

declare -A TOOLS_NETWORK_SECURITY=(
    ["nftables"]="Modern firewall framework"
    ["tcpdump"]="Network packet analyzer"
    ["net-tools"]="Network utilities"
    ["iptables-persistent"]="Persistent iptables rules"
)

declare -A TOOLS_OPTIONAL=(
    ["acct"]="Process accounting"
    ["sysstat"]="System statistics"
    ["logwatch"]="Log analyzer"
    ["psacct"]="Process accounting utilities"
)

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

#===============================================================================
# Logging Functions
#===============================================================================

setup_logging() {
    local log_dir="$(dirname "$LOG_FILE")"
    mkdir -p "$log_dir"
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo ""
    echo "=============================================="
    echo "Security Tools Installation - $(date '+%Y-%m-%d %H:%M:%S')"
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

Installs security tools required for comprehensive security auditing
and to improve Lynis hardening score.

Options:
    --essential-only    Install only essential tools
    --full              Install all tools (essential + recommended + optional)
    --skip-clamav       Skip ClamAV installation (saves disk space)
    --skip-configure    Skip post-installation configuration
    --dry-run           Show what would be installed without installing
    --help              Show this help message
    --version           Show version information

Tool Categories:
    Essential:          lynis, auditd, aide, rkhunter, chkrootkit
    Recommended:        fail2ban, clamav, debsums, needrestart, etc.
    Network Security:   nftables, tcpdump, net-tools
    Optional:           acct, sysstat, logwatch

EOF
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_network() {
    log_info "Checking network connectivity..."
    if ! ping -c 1 -W 5 archive.ubuntu.com &>/dev/null; then
        log_warning "Cannot reach Ubuntu archive. Checking alternative..."
        if ! ping -c 1 -W 5 8.8.8.8 &>/dev/null; then
            log_error "No network connectivity. Cannot install packages."
            exit 1
        fi
    fi
    log_success "Network connectivity verified"
}

update_package_cache() {
    log_info "Updating package cache..."
    apt-get update -qq
    log_success "Package cache updated"
}

#===============================================================================
# Installation Functions
#===============================================================================

install_package() {
    local package="$1"
    local description="${2:-}"
    
    if dpkg -l "$package" 2>/dev/null | grep -q "^ii"; then
        log_info "  $package: Already installed"
        return 0
    fi
    
    log_info "  Installing $package${description:+ ($description)}..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "    [DRY RUN] Would install: $package"
        return 0
    fi
    
    if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$package" 2>/dev/null; then
        log_success "  $package: Installed successfully"
        return 0
    else
        log_warning "  $package: Installation failed"
        return 1
    fi
}

install_tool_category() {
    local category_name="$1"
    shift
    local -n tools_ref=$1
    
    log_section "Installing $category_name"
    
    local installed=0
    local failed=0
    
    for tool in "${!tools_ref[@]}"; do
        if install_package "$tool" "${tools_ref[$tool]}"; then
            ((installed++)) || true
        else
            ((failed++)) || true
        fi
    done
    
    log_info "  $category_name: $installed installed, $failed failed"
}

#===============================================================================
# Configuration Functions
#===============================================================================

configure_aide() {
    log_section "Configuring AIDE"
    
    if ! command -v aide &>/dev/null; then
        log_warning "AIDE not installed, skipping configuration"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would configure AIDE"
        return 0
    fi
    
    # Initialize AIDE database if not exists
    if [[ ! -f /var/lib/aide/aide.db ]]; then
        log_info "Initializing AIDE database (this may take several minutes)..."
        
        # Update AIDE configuration for better performance
        if [[ -f /etc/aide/aide.conf ]]; then
            # Backup original config
            cp /etc/aide/aide.conf /etc/aide/aide.conf.backup
        fi
        
        # Initialize database
        aideinit 2>/dev/null || aide --init 2>/dev/null || {
            log_warning "AIDE initialization failed - may need manual setup"
            return 0
        }
        
        # Move new database to active
        if [[ -f /var/lib/aide/aide.db.new ]]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        fi
        
        log_success "AIDE database initialized"
    else
        log_info "AIDE database already exists"
    fi
    
    # Create daily cron job for AIDE
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
# Daily AIDE integrity check
/usr/bin/aide --check 2>&1 | /usr/bin/mail -s "AIDE Report for $(hostname)" root 2>/dev/null || \
    /usr/bin/aide --check >> /var/log/aide/aide-check.log 2>&1
EOF
    chmod 755 /etc/cron.daily/aide-check
    mkdir -p /var/log/aide
    
    log_success "AIDE configured with daily checks"
}

configure_rkhunter() {
    log_section "Configuring Rootkit Hunter"
    
    if ! command -v rkhunter &>/dev/null; then
        log_warning "rkhunter not installed, skipping configuration"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would configure rkhunter"
        return 0
    fi
    
    # Configure rkhunter
    if [[ -f /etc/rkhunter.conf ]]; then
        # Enable automatic updates
        sed -i 's/^#\?UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf 2>/dev/null || true
        sed -i 's/^#\?MIRRORS_MODE=.*/MIRRORS_MODE=0/' /etc/rkhunter.conf 2>/dev/null || true
        sed -i 's/^#\?WEB_CMD=.*/WEB_CMD=""/' /etc/rkhunter.conf 2>/dev/null || true
        
        # Allow script replacements (for package updates)
        sed -i 's/^#\?SCRIPTWHITELIST=.*/SCRIPTWHITELIST=\/usr\/bin\/egrep/' /etc/rkhunter.conf 2>/dev/null || true
        sed -i 's/^#\?SCRIPTWHITELIST=.*/SCRIPTWHITELIST=\/usr\/bin\/fgrep/' /etc/rkhunter.conf 2>/dev/null || true
        sed -i 's/^#\?SCRIPTWHITELIST=.*/SCRIPTWHITELIST=\/usr\/bin\/which/' /etc/rkhunter.conf 2>/dev/null || true
    fi
    
    # Update rkhunter database
    log_info "Updating rkhunter database..."
    rkhunter --update 2>/dev/null || log_warning "rkhunter database update failed"
    rkhunter --propupd 2>/dev/null || log_warning "rkhunter property update failed"
    
    # Configure default settings
    if [[ -f /etc/default/rkhunter ]]; then
        sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' /etc/default/rkhunter
        sed -i 's/^CRON_DB_UPDATE=.*/CRON_DB_UPDATE="true"/' /etc/default/rkhunter
        sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' /etc/default/rkhunter
    fi
    
    log_success "rkhunter configured with daily scans"
}

configure_chkrootkit() {
    log_section "Configuring chkrootkit"
    
    if ! command -v chkrootkit &>/dev/null; then
        log_warning "chkrootkit not installed, skipping configuration"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would configure chkrootkit"
        return 0
    fi
    
    # Enable daily runs
    if [[ -f /etc/chkrootkit.conf ]]; then
        sed -i 's/^RUN_DAILY=.*/RUN_DAILY="true"/' /etc/chkrootkit.conf 2>/dev/null || true
    fi
    
    # Create chkrootkit configuration if it doesn't exist
    if [[ ! -f /etc/chkrootkit.conf ]]; then
        cat > /etc/chkrootkit.conf << 'EOF'
RUN_DAILY="true"
RUN_DAILY_OPTS="-q"
DIFF_MODE="true"
EOF
    fi
    
    log_success "chkrootkit configured"
}

configure_fail2ban() {
    log_section "Configuring Fail2Ban"
    
    if ! command -v fail2ban-client &>/dev/null; then
        log_warning "Fail2Ban not installed, skipping configuration"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would configure Fail2Ban"
        return 0
    fi
    
    # Create local configuration
    cat > /etc/fail2ban/jail.local << 'EOF'
# Fail2Ban Local Configuration
# CIS Hardening Project

[DEFAULT]
# Ban duration (10 minutes by default, increase for production)
bantime = 600

# Time window for counting failures
findtime = 600

# Number of failures before ban
maxretry = 5

# Ignore local addresses
ignoreip = 127.0.0.1/8 ::1

# Default action (ban IP and log)
banaction = nftables-multiport
banaction_allports = nftables-allports

# Logging
logtarget = /var/log/fail2ban.log
loglevel = INFO

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 6
bantime = 600
EOF

    # Enable and start Fail2Ban
    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true
    
    log_success "Fail2Ban configured and enabled"
}

configure_clamav() {
    log_section "Configuring ClamAV"
    
    if ! command -v clamscan &>/dev/null; then
        log_warning "ClamAV not installed, skipping configuration"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would configure ClamAV"
        return 0
    fi
    
    # Stop freshclam to update configuration
    systemctl stop clamav-freshclam 2>/dev/null || true
    
    # Update virus database
    log_info "Updating ClamAV virus database (this may take a while)..."
    freshclam 2>/dev/null || log_warning "ClamAV database update failed - may need manual intervention"
    
    # Enable services
    systemctl enable clamav-freshclam 2>/dev/null || true
    systemctl start clamav-freshclam 2>/dev/null || true
    
    # Enable daemon if installed
    if systemctl list-unit-files | grep -q "clamav-daemon"; then
        systemctl enable clamav-daemon 2>/dev/null || true
        systemctl start clamav-daemon 2>/dev/null || true
    fi
    
    # Create weekly scan cron job
    cat > /etc/cron.weekly/clamav-scan << 'EOF'
#!/bin/bash
# Weekly ClamAV scan
LOGFILE="/var/log/clamav/weekly-scan.log"
mkdir -p /var/log/clamav

echo "ClamAV Weekly Scan - $(date)" > "$LOGFILE"
clamscan -r --infected --exclude-dir="^/sys" --exclude-dir="^/proc" \
    --exclude-dir="^/dev" --exclude-dir="^/run" / >> "$LOGFILE" 2>&1
EOF
    chmod 755 /etc/cron.weekly/clamav-scan
    
    log_success "ClamAV configured with weekly scans"
}

configure_auditd() {
    log_section "Configuring Audit Daemon"
    
    if ! command -v auditctl &>/dev/null; then
        log_warning "auditd not installed, skipping configuration"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would configure auditd"
        return 0
    fi
    
    # Enable and start auditd
    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true
    
    log_success "auditd enabled (detailed rules configured separately)"
}

configure_debsums() {
    log_section "Configuring debsums"
    
    if ! command -v debsums &>/dev/null; then
        log_warning "debsums not installed, skipping configuration"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would configure debsums"
        return 0
    fi
    
    # Create weekly verification cron job
    cat > /etc/cron.weekly/debsums-check << 'EOF'
#!/bin/bash
# Weekly package verification
LOGFILE="/var/log/debsums-weekly.log"

echo "Package Verification - $(date)" > "$LOGFILE"
debsums -s >> "$LOGFILE" 2>&1

# Alert if any changes detected
if [ -s "$LOGFILE" ] && grep -q "FAILED" "$LOGFILE"; then
    echo "ALERT: Package verification failures detected"
fi
EOF
    chmod 755 /etc/cron.weekly/debsums-check
    
    log_success "debsums configured with weekly verification"
}

#===============================================================================
# Main Execution
#===============================================================================

# Default options
INSTALL_MODE="recommended"
SKIP_CLAMAV=false
SKIP_CONFIGURE=false
DRY_RUN=false

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --essential-only)
                INSTALL_MODE="essential"
                shift
                ;;
            --full)
                INSTALL_MODE="full"
                shift
                ;;
            --skip-clamav)
                SKIP_CLAMAV=true
                shift
                ;;
            --skip-configure)
                SKIP_CONFIGURE=true
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
    
    check_network
    update_package_cache
    
    # Install packages based on mode
    install_tool_category "Essential Security Tools" TOOLS_ESSENTIAL
    install_tool_category "Network Security Tools" TOOLS_NETWORK_SECURITY
    
    if [[ "$INSTALL_MODE" == "recommended" ]] || [[ "$INSTALL_MODE" == "full" ]]; then
        if [[ "$SKIP_CLAMAV" == "true" ]]; then
            # Remove ClamAV from recommended
            unset 'TOOLS_RECOMMENDED[clamav]'
            unset 'TOOLS_RECOMMENDED[clamav-daemon]'
            unset 'TOOLS_RECOMMENDED[clamav-freshclam]'
            log_info "Skipping ClamAV installation as requested"
        fi
        install_tool_category "Recommended Security Tools" TOOLS_RECOMMENDED
    fi
    
    if [[ "$INSTALL_MODE" == "full" ]]; then
        install_tool_category "Optional Security Tools" TOOLS_OPTIONAL
    fi
    
    # Configure tools
    if [[ "$SKIP_CONFIGURE" != "true" ]]; then
        log_section "Post-Installation Configuration"
        
        configure_auditd
        configure_aide
        configure_rkhunter
        configure_chkrootkit
        configure_fail2ban
        configure_debsums
        
        if [[ "$SKIP_CLAMAV" != "true" ]]; then
            configure_clamav
        fi
    fi
    
    # Summary
    echo ""
    echo "==============================================================================="
    log_success "Security tools installation complete"
    echo "==============================================================================="
    echo ""
    echo "Installed Tools Summary:"
    echo "  - Lynis:      $(command -v lynis &>/dev/null && echo 'Installed' || echo 'Not installed')"
    echo "  - AIDE:       $(command -v aide &>/dev/null && echo 'Installed' || echo 'Not installed')"
    echo "  - rkhunter:   $(command -v rkhunter &>/dev/null && echo 'Installed' || echo 'Not installed')"
    echo "  - chkrootkit: $(command -v chkrootkit &>/dev/null && echo 'Installed' || echo 'Not installed')"
    echo "  - Fail2Ban:   $(command -v fail2ban-client &>/dev/null && echo 'Installed' || echo 'Not installed')"
    echo "  - ClamAV:     $(command -v clamscan &>/dev/null && echo 'Installed' || echo 'Not installed')"
    echo "  - nftables:   $(command -v nft &>/dev/null && echo 'Installed' || echo 'Not installed')"
    echo ""
    echo "Next Steps:"
    echo "  1. Review and customize /etc/fail2ban/jail.local"
    echo "  2. Run: lynis audit system"
    echo "  3. Run: rkhunter --check"
    echo "  4. Configure nftables firewall rules"
    echo ""
    echo "Log file: $LOG_FILE"
    echo ""
}

main "$@"

