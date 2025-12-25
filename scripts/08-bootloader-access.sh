#!/usr/bin/env bash
#===============================================================================
# CIS Control: 1.4.2 - Ensure access to bootloader config is configured
# Profile: Level 1 - Server, Level 1 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="1.4.2"
CONTROL_DESC="Ensure access to bootloader config is configured"

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
    local grub_cfg="/boot/grub/grub.cfg"
    
    if [[ ! -f "$grub_cfg" ]]; then
        log_error "[$CONTROL_ID] GRUB config not found at $grub_cfg"
        return 1
    fi
    
    # Get file permissions
    local stat_output
    stat_output=$(stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' "$grub_cfg")
    log_info "[$CONTROL_ID] Current permissions: $stat_output"
    
    # Check UID (should be 0/root)
    local uid
    uid=$(stat -Lc '%u' "$grub_cfg")
    if [[ "$uid" -ne 0 ]]; then
        log_error "[$CONTROL_ID] Owner is not root (UID: $uid)"
        result=1
    else
        log_success "[$CONTROL_ID] Owner is root"
    fi
    
    # Check GID (should be 0/root)
    local gid
    gid=$(stat -Lc '%g' "$grub_cfg")
    if [[ "$gid" -ne 0 ]]; then
        log_error "[$CONTROL_ID] Group is not root (GID: $gid)"
        result=1
    else
        log_success "[$CONTROL_ID] Group is root"
    fi
    
    # Check permissions (should be 0600 or more restrictive)
    local perms
    perms=$(stat -Lc '%a' "$grub_cfg")
    
    # Check if group or others have any permissions
    local group_perms=$((perms / 10 % 10))
    local other_perms=$((perms % 10))
    
    if [[ "$group_perms" -gt 0 ]] || [[ "$other_perms" -gt 0 ]]; then
        log_error "[$CONTROL_ID] Permissions too permissive: $perms (should be 0600 or more restrictive)"
        result=1
    else
        log_success "[$CONTROL_ID] Permissions are properly restrictive: $perms"
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    local grub_cfg="/boot/grub/grub.cfg"
    
    if [[ ! -f "$grub_cfg" ]]; then
        log_error "[$CONTROL_ID] GRUB config not found at $grub_cfg"
        return 1
    fi
    
    # Set ownership to root:root
    log_info "[$CONTROL_ID] Setting ownership to root:root"
    chown root:root "$grub_cfg"
    
    # Set permissions to 0600 (remove execute, remove group/other read/write)
    log_info "[$CONTROL_ID] Setting permissions to 0600"
    chmod u-x,go-rwx "$grub_cfg"
    
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
