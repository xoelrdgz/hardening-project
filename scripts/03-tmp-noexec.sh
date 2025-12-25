#!/usr/bin/env bash
#===============================================================================
# CIS Control: 1.1.2.1.4 - Ensure noexec option set on /tmp partition
# Profile: Level 1 - Server, Level 1 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="1.1.2.1.4"
CONTROL_DESC="Ensure noexec option set on /tmp partition"

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
    
    # Check if /tmp is mounted
    if ! findmnt -kn /tmp &>/dev/null; then
        log_warning "[$CONTROL_ID] /tmp is not mounted as a separate partition"
        return 1
    fi
    
    # Check for noexec option
    if findmnt -kn /tmp | grep -q 'noexec'; then
        log_success "[$CONTROL_ID] noexec option is set on /tmp"
        return 0
    else
        log_error "[$CONTROL_ID] noexec option is NOT set on /tmp"
        return 1
    fi
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    local fstab="/etc/fstab"
    
    # Check if /tmp is in fstab
    if grep -q "^[^#].*[[:space:]]/tmp[[:space:]]" "$fstab"; then
        backup_file "$fstab"
        
        # Check if noexec is already present
        if grep "^[^#].*[[:space:]]/tmp[[:space:]]" "$fstab" | grep -q "noexec"; then
            log_info "[$CONTROL_ID] noexec already in fstab for /tmp"
        else
            log_info "[$CONTROL_ID] Adding noexec to /tmp mount options in fstab"
            
            # Add noexec to existing /tmp entry
            sed -i '/^[^#].*[[:space:]]\/tmp[[:space:]]/ s/defaults/defaults,noexec/' "$fstab"
            
            # If defaults wasn't there, add noexec to the options field
            if ! grep "^[^#].*[[:space:]]/tmp[[:space:]]" "$fstab" | grep -q "noexec"; then
                sed -i '/^[^#].*[[:space:]]\/tmp[[:space:]]/ s/\([[:space:]][^[:space:]]*[[:space:]][^[:space:]]*[[:space:]][^[:space:]]*\)/\1,noexec/' "$fstab"
            fi
        fi
    else
        log_warning "[$CONTROL_ID] /tmp not found in fstab - run 02-tmp-partition.sh first"
    fi
    
    # Remount /tmp with noexec
    log_info "[$CONTROL_ID] Remounting /tmp with noexec option"
    mount -o remount,noexec /tmp 2>/dev/null || mount -o remount /tmp
    
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
