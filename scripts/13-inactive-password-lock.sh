#!/usr/bin/env bash
#===============================================================================
# CIS Control: 5.4.1.5 - Ensure inactive password lock is configured
# Profile: Level 1 - Server, Level 1 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="5.4.1.5"
CONTROL_DESC="Ensure inactive password lock is configured"
INACTIVE_DAYS="45"  # Maximum 45 days as per CIS

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
    
    # Check useradd default INACTIVE setting
    local default_inactive
    default_inactive=$(useradd -D | grep INACTIVE | cut -d= -f2 || echo "-1")
    
    if [[ "$default_inactive" -ge 1 ]] && [[ "$default_inactive" -le "$INACTIVE_DAYS" ]]; then
        log_success "[$CONTROL_ID] Default INACTIVE is set to $default_inactive days"
    else
        log_error "[$CONTROL_ID] Default INACTIVE is $default_inactive (should be 1-$INACTIVE_DAYS)"
        result=1
    fi
    
    # Check existing users with passwords
    log_info "[$CONTROL_ID] Checking existing user accounts..."
    
    local non_compliant_users=""
    while IFS=: read -r username _ _ _ _ _ inactive _; do
        if [[ -n "$inactive" ]]; then
            if [[ "$inactive" -gt "$INACTIVE_DAYS" ]] || [[ "$inactive" -lt 0 ]]; then
                non_compliant_users+="$username (INACTIVE: $inactive) "
            fi
        fi
    done < <(awk -F: '($2~/^\$.+\$/) {print $1":"$7}' /etc/shadow 2>/dev/null)
    
    if [[ -n "$non_compliant_users" ]]; then
        log_error "[$CONTROL_ID] Users with non-compliant INACTIVE: $non_compliant_users"
        result=1
    else
        log_success "[$CONTROL_ID] All users have compliant INACTIVE settings"
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    # Set default INACTIVE for new users
    log_info "[$CONTROL_ID] Setting default INACTIVE to $INACTIVE_DAYS days"
    useradd -D -f "$INACTIVE_DAYS"
    
    # Fix existing users with passwords that have non-compliant INACTIVE
    log_info "[$CONTROL_ID] Updating existing user accounts..."
    
    while IFS=: read -r username inactive; do
        if [[ -n "$inactive" ]]; then
            if [[ "$inactive" -gt "$INACTIVE_DAYS" ]] || [[ "$inactive" -lt 0 ]]; then
                log_info "[$CONTROL_ID] Setting INACTIVE to $INACTIVE_DAYS for user: $username"
                chage --inactive "$INACTIVE_DAYS" "$username"
            fi
        fi
    done < <(awk -F: '($2~/^\$.+\$/) {print $1":"$7}' /etc/shadow 2>/dev/null)
    
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
