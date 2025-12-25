#!/usr/bin/env bash
#===============================================================================
# CIS Control: 1.1.2.2.4 - Ensure noexec option set on /dev/shm partition
# Profile: Level 1 - Server, Level 1 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="1.1.2.2.4"
CONTROL_DESC="Ensure noexec option set on /dev/shm partition"

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
    
    # Check if /dev/shm is mounted
    if ! findmnt -kn /dev/shm &>/dev/null; then
        log_error "[$CONTROL_ID] /dev/shm is not mounted"
        return 1
    fi
    
    # Check for noexec option
    if findmnt -kn /dev/shm | grep -q 'noexec'; then
        log_success "[$CONTROL_ID] noexec option is set on /dev/shm"
        return 0
    else
        log_error "[$CONTROL_ID] noexec option is NOT set on /dev/shm"
        return 1
    fi
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    local fstab="/etc/fstab"
    backup_file "$fstab"
    
    # Check if /dev/shm is in fstab
    if grep -q "^[^#].*[[:space:]]/dev/shm[[:space:]]" "$fstab"; then
        # Check if noexec is already present
        if grep "^[^#].*[[:space:]]/dev/shm[[:space:]]" "$fstab" | grep -q "noexec"; then
            log_info "[$CONTROL_ID] noexec already in fstab for /dev/shm"
        else
            log_info "[$CONTROL_ID] Adding noexec to /dev/shm mount options in fstab"
            
            # Add noexec to existing /dev/shm entry
            sed -i '/^[^#].*[[:space:]]\/dev\/shm[[:space:]]/ s/defaults/defaults,noexec/' "$fstab"
            
            # If defaults wasn't there, add noexec to the options field
            if ! grep "^[^#].*[[:space:]]/dev/shm[[:space:]]" "$fstab" | grep -q "noexec"; then
                sed -i '/^[^#].*[[:space:]]\/dev\/shm[[:space:]]/ s/\([[:space:]][^[:space:]]*[[:space:]][^[:space:]]*[[:space:]][^[:space:]]*\)/\1,noexec/' "$fstab"
            fi
        fi
    else
        log_info "[$CONTROL_ID] Adding /dev/shm entry to fstab"
        echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> "$fstab"
    fi
    
    # Remount /dev/shm with noexec
    log_info "[$CONTROL_ID] Remounting /dev/shm with noexec option"
    mount -o remount,noexec /dev/shm 2>/dev/null || mount -o remount /dev/shm
    
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
