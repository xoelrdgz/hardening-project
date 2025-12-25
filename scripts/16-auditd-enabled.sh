#!/usr/bin/env bash
#===============================================================================
# CIS Control: 6.2.1.2 - Ensure auditd service is enabled and active
# Profile: Level 2 - Server, Level 2 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="6.2.1.2"
CONTROL_DESC="Ensure auditd service is enabled and active"

source_common() {
    if [[ -n "${LOG_FILE:-}" ]]; then
        return 0
    fi
    log_info() { echo "[INFO] $*"; }
    log_success() { echo "[PASS] $*"; }
    log_warning() { echo "[WARN] $*"; }
    log_error() { echo "[FAIL] $*"; }
    backup_file() { 
        if [[ -f "$1" ]]; then
            cp -a "$1" "$1.bak.$(date +%Y%m%d%H%M%S)"
        fi
    }
}

source_common

#===============================================================================
# Audit Function
#===============================================================================
audit() {
    log_info "[$CONTROL_ID] Auditing: $CONTROL_DESC"
    
    local result=0
    
    # Check if auditd is installed
    if ! command -v auditd &>/dev/null && ! command -v auditctl &>/dev/null; then
        log_error "[$CONTROL_ID] auditd is not installed"
        return 1
    fi
    
    # Check if auditd is enabled
    local enabled_status
    enabled_status=$(systemctl is-enabled auditd 2>/dev/null || echo "disabled")
    
    if [[ "$enabled_status" == "enabled" ]]; then
        log_success "[$CONTROL_ID] auditd is enabled"
    else
        log_error "[$CONTROL_ID] auditd is not enabled (status: $enabled_status)"
        result=1
    fi
    
    # Check if auditd is active
    local active_status
    active_status=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
    
    if [[ "$active_status" == "active" ]]; then
        log_success "[$CONTROL_ID] auditd is active"
    else
        log_error "[$CONTROL_ID] auditd is not active (status: $active_status)"
        result=1
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    # Check if auditd is installed
    if ! dpkg-query -s auditd &>/dev/null; then
        log_info "[$CONTROL_ID] Installing auditd"
        apt-get update -qq
        apt-get install -y -qq auditd audispd-plugins
    fi
    
    # Unmask auditd if masked
    systemctl unmask auditd 2>/dev/null || true
    
    # Enable auditd
    log_info "[$CONTROL_ID] Enabling auditd service"
    systemctl enable auditd
    
    # Start auditd
    log_info "[$CONTROL_ID] Starting auditd service"
    systemctl start auditd
    
    log_success "[$CONTROL_ID] Remediation complete"
    
    # Verify remediation
    audit
}

#===============================================================================
# Main
#===============================================================================
main() {
    case "${1:-}" in
        --audit)
            audit
            ;;
        --remediate)
            remediate
            ;;
        *)
            echo "Usage: $0 {--audit|--remediate}"
            exit 1
            ;;
    esac
}

main "$@"
