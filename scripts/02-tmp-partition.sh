#!/usr/bin/env bash
#===============================================================================
# CIS Control: 1.1.2.1.1 - Ensure /tmp is a separate partition
# Profile: Level 1 - Server, Level 1 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="1.1.2.1.1"
CONTROL_DESC="Ensure /tmp is a separate partition"

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
    
    # Check if /tmp is mounted
    if findmnt -kn /tmp &>/dev/null; then
        log_success "[$CONTROL_ID] /tmp is mounted as a separate partition"
        findmnt -kn /tmp | head -1
    else
        log_error "[$CONTROL_ID] /tmp is NOT mounted as a separate partition"
        result=1
    fi
    
    # Check systemd tmp.mount status
    local mount_status
    mount_status=$(systemctl is-enabled tmp.mount 2>/dev/null || echo "disabled")
    
    if [[ "$mount_status" == "masked" ]] || [[ "$mount_status" == "disabled" ]]; then
        log_error "[$CONTROL_ID] tmp.mount is $mount_status"
        result=1
    else
        log_success "[$CONTROL_ID] tmp.mount is $mount_status"
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    # Unmask tmp.mount if masked
    local mount_status
    mount_status=$(systemctl is-enabled tmp.mount 2>/dev/null || echo "disabled")
    
    if [[ "$mount_status" == "masked" ]]; then
        log_info "[$CONTROL_ID] Unmasking tmp.mount"
        systemctl unmask tmp.mount
    fi
    
    # Check if /tmp entry exists in /etc/fstab
    if ! grep -q "^[^#].*[[:space:]]/tmp[[:space:]]" /etc/fstab; then
        log_info "[$CONTROL_ID] Adding /tmp entry to /etc/fstab"
        backup_file /etc/fstab
        
        # Add tmpfs mount for /tmp with secure options
        echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /etc/fstab
        
        log_info "[$CONTROL_ID] Mounting /tmp with new configuration"
        mount -o remount /tmp 2>/dev/null || mount /tmp
    else
        log_info "[$CONTROL_ID] /tmp entry already exists in /etc/fstab"
        # Remount to apply any changes
        mount -o remount /tmp 2>/dev/null || true
    fi
    
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
