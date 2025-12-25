#!/usr/bin/env bash
#===============================================================================
# CIS Ubuntu Server 24.04 LTS Hardening Scripts - Main Orchestrator
# Version: 2.0.0
# Date: 2025-12-25
# Author: xoelrdgz
# Description: Main script to orchestrate CIS benchmark hardening controls
#===============================================================================

#set -euo pipefail
set +e

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Script directory
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_DIR="/var/log/cis-hardening"
readonly LOG_FILE="${LOG_DIR}/hardening-$(date +%Y%m%d-%H%M%S).log"
readonly BACKUP_DIR="/var/backups/cis-hardening-$(date +%Y%m%d-%H%M%S)"

#===============================================================================
# Logging Functions
#===============================================================================
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

log_section() {
    echo ""
    echo -e "${CYAN}[====]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
    echo ""
}

#===============================================================================
# Pre-flight Checks
#===============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS version"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]] || [[ "${VERSION_ID}" != "24.04" ]]; then
        log_warning "This script is designed for Ubuntu 24.04 LTS. Current: $ID $VERSION_ID"
    fi
}

setup_directories() {
    mkdir -p "$LOG_DIR" "$BACKUP_DIR"
    chmod 700 "$LOG_DIR" "$BACKUP_DIR"
    log_info "Created logging directory: $LOG_DIR"
    log_info "Created backup directory: $BACKUP_DIR"
}

#===============================================================================
# Backup Function
#===============================================================================
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp -a "$file" "${BACKUP_DIR}/$(basename "$file").bak"
        log_info "Backed up: $file"
    fi
}

#===============================================================================
# Main Execution
#===============================================================================
print_banner() {
    echo ""
    echo -e "${CYAN}===============================================================================${NC}"
    echo -e "${CYAN}  CIS Ubuntu Server 24.04 LTS Hardening Scripts${NC}"
    echo -e "${CYAN}  Version: 2.0.0 | Compliance Level: Level 1 & Level 2 (Server)${NC}"
    echo -e "${CYAN}===============================================================================${NC}"
    echo ""
}

show_help() {
    cat << EOF
Usage: $(basename "$0") [COMMAND] [OPTIONS]

Commands:
    full            Complete hardening workflow (recommended)
    analyze         Run security analysis only (with Lynis)
    harden          Apply CIS hardening controls
    tools           Install security tools only
    lynis-improve   Apply Lynis score improvements
    firewall        Configure nftables firewall only
    report          Generate compliance report

Options:
    --phase PHASE   Analysis phase: initial or post (for analyze command)
    --control ID    Run specific control (e.g., 1.1.1.9)
    --level N       Run only Level N controls (1 or 2)
    --dry-run       Show what would be done without making changes
    --skip-lynis    Skip Lynis scan during analysis
    --remove-compilers  Remove compilers during Lynis improvements
    --ssh-port PORT     SSH port for firewall (default: 22)
    --tcp-ports PORTS   Additional TCP ports (comma-separated)
    --help          Show this help message

Workflow Example (Recommended Order):
    1. $(basename "$0") analyze --phase initial     # Collect initial state
    2. $(basename "$0") tools                       # Install security tools
    3. $(basename "$0") harden                      # Apply CIS controls
    4. $(basename "$0") lynis-improve               # Additional hardening
    5. $(basename "$0") firewall                    # Configure nftables
    6. $(basename "$0") analyze --phase post        # Collect post state
    7. $(basename "$0") report                      # Generate report

    OR use: $(basename "$0") full                   # All steps automatically

CIS Controls Implemented:
    Section 1 - Initial Setup
        1.1.1.9    - Disable USB Storage
        1.1.1.10   - Disable Unused Filesystems
        1.1.2.1.1  - /tmp Separate Partition
        1.1.2.1.4  - noexec on /tmp
        1.1.2.2.4  - noexec on /dev/shm
        1.3.1.2    - AppArmor Bootloader
        1.3.1.4    - AppArmor Profiles Enforcing
        1.4.1      - Bootloader Password
        1.4.2      - Bootloader Config Access
        1.5.1      - ASLR Enabled
        1.5.2      - ptrace_scope Restricted
        1.5.3      - Core Dumps Restricted
    
    Section 2 - Services
        2.1.1      - Disable autofs
        2.1.21     - MTA Local-Only Mode
        2.2.4      - Remove Telnet Client

    Section 3 - Network Configuration
        3.3.1      - IP Forwarding Disabled
        3.3.2      - Packet Redirect Sending Disabled
        3.3.3      - ICMP Redirects Not Accepted
        3.3.4      - Broadcast ICMP Requests Ignored
        3.3.5      - Secure ICMP Redirects Not Accepted
        3.3.9      - Suspicious Packets Logged
        3.3.10     - TCP SYN Cookies Enabled
        3.5.x      - nftables Firewall Configuration

    Section 5 - Access Control
        5.1.x      - SSH Server Hardening
        5.2.x      - Sudo Configuration
        5.3.x      - PAM Password Policies
        5.4.1.4    - SHA512 Password Hashing
        5.4.1.5    - Inactive Password Lock
        5.4.2.1    - Root Only UID 0

    Section 6 - Logging and Auditing
        6.1.3.4    - rsyslog File Permissions
        6.2.1.2    - auditd Service Enabled
        6.2.2.3    - System Disabled on Audit Log Full
        6.2.3.4    - Date/Time Modification Audit
        6.2.3.8    - User/Group Modification Audit
        6.2.3.10   - Mount Audit
        6.2.3.17   - chacl Command Audit
        6.2.3.20   - Audit Configuration Immutable
        6.3.1      - AIDE Installed

EOF
}

#===============================================================================
# Command Handlers
#===============================================================================

run_analysis() {
    local phase="${1:-initial}"
    local skip_lynis="${2:-false}"
    
    log_section "Running Security Analysis - Phase: $phase"
    
    local analyze_script="${SCRIPT_DIR}/cis-analyze.sh"
    if [[ ! -f "$analyze_script" ]]; then
        log_error "Analysis script not found: $analyze_script"
        return 1
    fi
    
    local opts="--phase $phase"
    [[ "$skip_lynis" == "true" ]] && opts+=" --skip-lynis"
    
    bash "$analyze_script" $opts
}

run_tools_install() {
    log_section "Installing Security Tools"
    
    local tools_script="${SCRIPT_DIR}/40-install-security-tools.sh"
    if [[ ! -f "$tools_script" ]]; then
        log_error "Tools script not found: $tools_script"
        return 1
    fi
    
    bash "$tools_script"
}

run_hardening() {
    local specific_control="$1"
    local level="$2"
    local dry_run="$3"
    
    log_section "Applying CIS Hardening Controls"
    
    # CIS Control Scripts
    local controls=(
        "01-disable-usb-storage.sh"
        "33-disable-unused-filesystems.sh"
        "02-tmp-partition.sh"
        "03-tmp-noexec.sh"
        "04-devshm-noexec.sh"
        "05-apparmor-bootloader.sh"
        "06-apparmor-enforce.sh"
        "07-bootloader-password.sh"
        "08-bootloader-access.sh"
        "09-aslr-enabled.sh"
        "10-ptrace-scope.sh"
        "11-core-dumps.sh"
        "12-sha512-passwords.sh"
        "13-inactive-password-lock.sh"
        "14-root-uid-zero.sh"
        "15-rsyslog-permissions.sh"
        "16-auditd-enabled.sh"
        "17-audit-log-full.sh"
        "18-audit-datetime.sh"
        "19-audit-identity.sh"
        "20-audit-mounts.sh"
        "21-audit-chacl.sh"
        "22-audit-immutable.sh"
        "23-aide-installed.sh"
        "24-disable-ip-forwarding.sh"
        "25-disable-packet-redirect.sh"
        "26-ignore-icmp-redirects.sh"
        "27-ignore-icmp-broadcast.sh"
        "28-tcp-syn-cookies.sh"
        "29-ssh-hardening.sh"
        "30-services-config.sh"
        "31-nftables-firewall.sh"
        "32-pam-sudo-config.sh"
    )

    local passed=0
    local failed=0
    local skipped=0

    for control_script in "${controls[@]}"; do
        local script_path="${SCRIPT_DIR}/${control_script}"
        
        if [[ -n "$specific_control" ]]; then
            if [[ "$control_script" != *"$specific_control"* ]]; then
                continue
            fi
        fi

        if [[ -f "$script_path" ]]; then
            log_info "Executing: $control_script"
            if [[ "$dry_run" == "true" ]]; then
                log_info "[DRY-RUN] Would execute: $script_path --remediate"
            else
                local exit_code=0
                bash "$script_path" "--remediate" || { exit_code=$?; true; }
                if [[ $exit_code -eq 0 ]]; then
                    ((passed++)) || true
                else
                    ((failed++)) || true
                fi
            fi
        else
            log_warning "Script not found: $script_path"
            ((skipped++)) || true
        fi
    done

    log_success "Hardening Complete: Passed=$passed, Failed=$failed, Skipped=$skipped"
    return $(( failed > 0 ? 1 : 0 ))
}

run_lynis_improvements() {
    local remove_compilers="$1"
    
    log_section "Applying Lynis Score Improvements"
    
    local lynis_script="${SCRIPT_DIR}/41-lynis-improvements.sh"
    if [[ ! -f "$lynis_script" ]]; then
        log_error "Lynis improvements script not found: $lynis_script"
        return 1
    fi
    
    local opts=""
    [[ "$remove_compilers" == "true" ]] && opts="--remove-compilers"
    
    bash "$lynis_script" $opts
}

run_firewall_config() {
    local ssh_port="$1"
    local tcp_ports="$2"
    
    log_section "Configuring nftables Firewall"
    
    local nft_script="${SCRIPT_DIR}/42-configure-nftables.sh"
    if [[ ! -f "$nft_script" ]]; then
        log_error "nftables script not found: $nft_script"
        return 1
    fi
    
    local opts=""
    [[ -n "$ssh_port" ]] && opts+=" --ssh-port $ssh_port"
    [[ -n "$tcp_ports" ]] && opts+=" --tcp-ports $tcp_ports"
    
    bash "$nft_script" $opts
}

generate_report() {
    log_section "Generating Compliance Report"
    
    local report_file="${LOG_DIR}/compliance-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
================================================================================
CIS Ubuntu Server 24.04 LTS - Compliance Report
Generated: $(date '+%Y-%m-%d %H:%M:%S')
Hostname: $(hostname)
================================================================================

SYSTEM INFORMATION
------------------
$(hostnamectl 2>/dev/null || echo "hostnamectl not available")

LYNIS HARDENING INDEX
---------------------
$(if command -v lynis &>/dev/null; then
    lynis audit system --quick --no-colors 2>/dev/null | grep -E "Hardening index|Lynis" | head -5
else
    echo "Lynis not installed"
fi)

SECURITY TOOLS STATUS
---------------------
- Lynis:      $(command -v lynis &>/dev/null && echo 'Installed' || echo 'Not installed')
- AIDE:       $(command -v aide &>/dev/null && echo 'Installed' || echo 'Not installed')
- rkhunter:   $(command -v rkhunter &>/dev/null && echo 'Installed' || echo 'Not installed')
- chkrootkit: $(command -v chkrootkit &>/dev/null && echo 'Installed' || echo 'Not installed')
- Fail2Ban:   $(command -v fail2ban-client &>/dev/null && echo 'Installed' || echo 'Not installed')
- ClamAV:     $(command -v clamscan &>/dev/null && echo 'Installed' || echo 'Not installed')
- nftables:   $(command -v nft &>/dev/null && echo 'Installed' || echo 'Not installed')
- auditd:     $(systemctl is-active auditd 2>/dev/null || echo 'Not running')

FIREWALL STATUS
---------------
$(nft list ruleset 2>/dev/null | head -50 || echo "nftables not configured")

APPARMOR STATUS
---------------
$(aa-status 2>/dev/null | head -20 || echo "AppArmor not running")

LISTENING SERVICES
------------------
$(ss -tlnp 2>/dev/null | head -20)

================================================================================
End of Report
================================================================================
EOF

    chmod 600 "$report_file"
    log_success "Report generated: $report_file"
    echo ""
    cat "$report_file"
}

run_full_workflow() {
    local ssh_port="$1"
    local tcp_ports="$2"
    local remove_compilers="$3"
    
    log_section "Starting Full Hardening Workflow"
    
    # Step 1: Initial Analysis
    log_info "Step 1/6: Initial Security Analysis"
    run_analysis "initial" "false" || log_warning "Initial analysis had issues"
    
    # Step 2: Install Security Tools
    log_info "Step 2/6: Installing Security Tools"
    run_tools_install || log_warning "Tools installation had issues"
    
    # Step 3: Apply CIS Hardening
    log_info "Step 3/6: Applying CIS Hardening Controls"
    run_hardening "" "" "false" || log_warning "Some hardening controls failed"
    
    # Step 4: Lynis Improvements
    log_info "Step 4/6: Applying Lynis Improvements"
    run_lynis_improvements "$remove_compilers" || log_warning "Lynis improvements had issues"
    
    # Step 5: Configure Firewall
    log_info "Step 5/6: Configuring nftables Firewall"
    run_firewall_config "$ssh_port" "$tcp_ports" || log_warning "Firewall configuration had issues"
    
    # Step 6: Post Analysis
    log_info "Step 6/6: Post-Hardening Security Analysis"
    run_analysis "post" "false" || log_warning "Post analysis had issues"
    
    # Generate Report
    generate_report
    
    log_success "Full hardening workflow completed!"
}

#===============================================================================
# Main
#===============================================================================

main() {
    local command=""
    local phase="initial"
    local specific_control=""
    local level=""
    local dry_run=false
    local skip_lynis=false
    local remove_compilers=false
    local ssh_port=""
    local tcp_ports=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            full|analyze|harden|tools|lynis-improve|firewall|report)
                command="$1"
                shift
                ;;
            --phase)
                phase="$2"
                shift 2
                ;;
            --control)
                specific_control="$2"
                shift 2
                ;;
            --level)
                level="$2"
                shift 2
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            --skip-lynis)
                skip_lynis=true
                shift
                ;;
            --remove-compilers)
                remove_compilers=true
                shift
                ;;
            --ssh-port)
                ssh_port="$2"
                shift 2
                ;;
            --tcp-ports)
                tcp_ports="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    print_banner
    check_root
    check_os
    setup_directories

    log_info "Log file: $LOG_FILE"
    log_info "Backup directory: $BACKUP_DIR"

    # Export variables for child scripts
    export LOG_FILE BACKUP_DIR SCRIPT_DIR
    export RED GREEN YELLOW BLUE CYAN NC
    export -f log_info log_success log_warning log_error log_section backup_file

    # Execute command
    case "$command" in
        full)
            run_full_workflow "$ssh_port" "$tcp_ports" "$remove_compilers"
            ;;
        analyze)
            run_analysis "$phase" "$skip_lynis"
            ;;
        harden)
            run_hardening "$specific_control" "$level" "$dry_run"
            ;;
        tools)
            run_tools_install
            ;;
        lynis-improve)
            run_lynis_improvements "$remove_compilers"
            ;;
        firewall)
            run_firewall_config "$ssh_port" "$tcp_ports"
            ;;
        report)
            generate_report
            ;;
        "")
            # Legacy mode: default to full hardening
            log_info "No command specified. Use --help for usage information."
            log_info "Running: harden (legacy mode)"
            run_hardening "$specific_control" "$level" "$dry_run"
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
