#!/usr/bin/env bash
#===============================================================================
# CIS Control: 5.4.2.1 - Ensure root is the only UID 0 account
# Profile: Level 1 - Server, Level 1 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="5.4.2.1"
CONTROL_DESC="Ensure root is the only UID 0 account"

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
    
    # Find all accounts with UID 0
    local uid0_accounts
    uid0_accounts=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
    
    local count=0
    local non_root_uid0=""
    
    while IFS= read -r account; do
        ((count++))
        if [[ "$account" != "root" ]]; then
            non_root_uid0+="$account "
        fi
    done <<< "$uid0_accounts"
    
    if [[ "$count" -eq 1 ]] && [[ "$uid0_accounts" == "root" ]]; then
        log_success "[$CONTROL_ID] Only root has UID 0"
    else
        log_error "[$CONTROL_ID] Accounts with UID 0: $uid0_accounts"
        if [[ -n "$non_root_uid0" ]]; then
            log_error "[$CONTROL_ID] Non-root accounts with UID 0: $non_root_uid0"
        fi
        result=1
    fi
    
    # Check if root account exists and has UID 0
    local root_uid
    root_uid=$(awk -F: '($1 == "root") { print $3 }' /etc/passwd)
    
    if [[ "$root_uid" != "0" ]]; then
        log_error "[$CONTROL_ID] root account does not have UID 0 (has UID: $root_uid)"
        result=1
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    local passwd_file="/etc/passwd"
    backup_file "$passwd_file"
    
    # Ensure root has UID 0
    local root_uid
    root_uid=$(awk -F: '($1 == "root") { print $3 }' "$passwd_file")
    
    if [[ "$root_uid" != "0" ]]; then
        log_info "[$CONTROL_ID] Setting root UID to 0"
        usermod -u 0 root
    fi
    
    # Find other accounts with UID 0
    local non_root_uid0
    non_root_uid0=$(awk -F: '($3 == 0 && $1 != "root") { print $1 }' "$passwd_file")
    
    if [[ -n "$non_root_uid0" ]]; then
        log_warning "[$CONTROL_ID] The following non-root accounts have UID 0:"
        echo "$non_root_uid0"
        log_warning "[$CONTROL_ID] These accounts should be manually reviewed and modified"
        log_warning "[$CONTROL_ID] To change a user's UID, use: usermod -u <new_uid> <username>"
        log_warning "[$CONTROL_ID] WARNING: Changing UIDs may affect file ownership and permissions"
        
        # Find next available UID for potential remediation
        local next_uid
        next_uid=$(awk -F: '($3 >= 1000 && $3 < 65534) { uid[$3]=1 } END { for (i=1000; i<65534; i++) if (!uid[i]) { print i; exit } }' "$passwd_file")
        
        log_info "[$CONTROL_ID] Next available UID for reassignment: $next_uid"
        log_warning "[$CONTROL_ID] Manual intervention required for security reasons"
        
        return 1
    fi
    
    log_success "[$CONTROL_ID] Remediation complete - only root has UID 0"
    
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
