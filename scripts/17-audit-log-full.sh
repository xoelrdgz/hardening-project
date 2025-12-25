#!/usr/bin/env bash
#===============================================================================
# CIS Control: 6.2.2.3 - Ensure system is disabled when audit logs are full
# Profile: Level 2 - Server, Level 2 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="6.2.2.3"
CONTROL_DESC="Ensure system is disabled when audit logs are full"

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
    local auditd_conf="/etc/audit/auditd.conf"
    
    if [[ ! -f "$auditd_conf" ]]; then
        log_error "[$CONTROL_ID] auditd.conf not found"
        return 1
    fi
    
    # Check disk_full_action
    local disk_full_action
    disk_full_action=$(grep -Pi '^\s*disk_full_action\s*=' "$auditd_conf" | awk -F= '{print $2}' | tr -d ' ' || echo "")
    
    if [[ "$disk_full_action" =~ ^(halt|single)$ ]]; then
        log_success "[$CONTROL_ID] disk_full_action is set to $disk_full_action"
    else
        log_error "[$CONTROL_ID] disk_full_action is '$disk_full_action' (should be halt or single)"
        result=1
    fi
    
    # Check disk_error_action
    local disk_error_action
    disk_error_action=$(grep -Pi '^\s*disk_error_action\s*=' "$auditd_conf" | awk -F= '{print $2}' | tr -d ' ' || echo "")
    
    if [[ "$disk_error_action" =~ ^(syslog|single|halt)$ ]]; then
        log_success "[$CONTROL_ID] disk_error_action is set to $disk_error_action"
    else
        log_error "[$CONTROL_ID] disk_error_action is '$disk_error_action' (should be syslog, single, or halt)"
        result=1
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    local auditd_conf="/etc/audit/auditd.conf"
    
    if [[ ! -f "$auditd_conf" ]]; then
        log_error "[$CONTROL_ID] auditd.conf not found - install auditd first"
        return 1
    fi
    
    backup_file "$auditd_conf"
    
    # Update disk_full_action
    if grep -qPi '^\s*disk_full_action\s*=' "$auditd_conf"; then
        sed -i 's/^\s*disk_full_action\s*=.*/disk_full_action = halt/' "$auditd_conf"
    else
        echo "disk_full_action = halt" >> "$auditd_conf"
    fi
    log_info "[$CONTROL_ID] Set disk_full_action = halt"
    
    # Update disk_error_action
    if grep -qPi '^\s*disk_error_action\s*=' "$auditd_conf"; then
        sed -i 's/^\s*disk_error_action\s*=.*/disk_error_action = halt/' "$auditd_conf"
    else
        echo "disk_error_action = halt" >> "$auditd_conf"
    fi
    log_info "[$CONTROL_ID] Set disk_error_action = halt"
    
    # Restart auditd to apply changes
    log_info "[$CONTROL_ID] Restarting auditd service"
    systemctl restart auditd 2>/dev/null || service auditd restart
    
    log_success "[$CONTROL_ID] Remediation complete"
    log_warning "[$CONTROL_ID] System will halt when audit logs are full or disk error occurs"
    
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
