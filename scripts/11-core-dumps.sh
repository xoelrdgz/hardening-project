#!/usr/bin/env bash
#===============================================================================
# CIS Control: 1.5.3 - Ensure core dumps are restricted
# Profile: Level 1 - Server, Level 1 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="1.5.3"
CONTROL_DESC="Ensure core dumps are restricted"

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
    
    # Check limits.conf for hard core 0
    if grep -Pqs '^\h*\*\h+hard\h+core\h+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
        log_success "[$CONTROL_ID] Hard core limit is set to 0 in limits.conf"
    else
        log_error "[$CONTROL_ID] Hard core limit is NOT set to 0 in limits.conf"
        result=1
    fi
    
    # Check sysctl for fs.suid_dumpable
    local suid_dumpable
    suid_dumpable=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "2")
    
    if [[ "$suid_dumpable" == "0" ]]; then
        log_success "[$CONTROL_ID] fs.suid_dumpable is correctly set to 0"
    else
        log_error "[$CONTROL_ID] fs.suid_dumpable is set to $suid_dumpable (should be 0)"
        result=1
    fi
    
    # Check if systemd-coredump is configured (if present)
    if [[ -f /etc/systemd/coredump.conf ]]; then
        if grep -qE '^\s*Storage\s*=\s*none' /etc/systemd/coredump.conf; then
            log_success "[$CONTROL_ID] systemd-coredump Storage is set to none"
        else
            log_warning "[$CONTROL_ID] systemd-coredump may allow core dumps"
        fi
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    # Set hard core limit in limits.conf (idempotent)
    local limits_file="/etc/security/limits.d/99-cis-core.conf"
    
    if ! grep -Pqs '^\h*\*\h+hard\h+core\h+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
        log_info "[$CONTROL_ID] Setting hard core limit to 0"
        echo "* hard core 0" > "$limits_file"
    fi
    
    # Set fs.suid_dumpable
    local sysctl_file="/etc/sysctl.d/60-cis-kernel.conf"
    mkdir -p /etc/sysctl.d
    
    # Create or update the sysctl file
    if [[ ! -f "$sysctl_file" ]]; then
        echo "# CIS Kernel Hardening Configuration" > "$sysctl_file"
        echo "# Managed by CIS hardening scripts" >> "$sysctl_file"
    fi
    
    # Remove from other config files (not our managed file)
    for file in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
        if [[ -f "$file" ]] && [[ "$file" != "$sysctl_file" ]]; then
            if grep -qE "^\s*fs\.suid_dumpable\s*=" "$file" 2>/dev/null; then
                backup_file "$file"
                sed -i '/^\s*fs\.suid_dumpable\s*=/d' "$file"
                log_info "[$CONTROL_ID] Removed fs.suid_dumpable from $file"
            fi
        fi
    done
    
    # Update or add in our managed file (idempotent)
    if grep -qE "^\s*fs\.suid_dumpable\s*=" "$sysctl_file" 2>/dev/null; then
        sed -i 's|^\s*fs\.suid_dumpable\s*=.*|fs.suid_dumpable = 0|' "$sysctl_file"
    else
        echo "fs.suid_dumpable = 0" >> "$sysctl_file"
    fi
    
    # Apply immediately
    sysctl -w fs.suid_dumpable=0 >/dev/null
    
    # Configure systemd-coredump if present (idempotent)
    if [[ -f /etc/systemd/coredump.conf ]]; then
        if ! grep -qE '^\s*Storage\s*=\s*none' /etc/systemd/coredump.conf; then
            backup_file /etc/systemd/coredump.conf
            log_info "[$CONTROL_ID] Configuring systemd-coredump"
            
            # Remove existing Storage and ProcessSizeMax lines
            sed -i '/^\s*Storage\s*=/d; /^\s*ProcessSizeMax\s*=/d' /etc/systemd/coredump.conf
            
            # Add settings under [Coredump] section
            if grep -q '^\s*\[Coredump\]' /etc/systemd/coredump.conf; then
                sed -i '/^\[Coredump\]/a Storage=none\nProcessSizeMax=0' /etc/systemd/coredump.conf
            else
                echo -e "\n[Coredump]\nStorage=none\nProcessSizeMax=0" >> /etc/systemd/coredump.conf
            fi
            
            systemctl daemon-reload 2>/dev/null || true
        fi
    fi
    
    log_success "[$CONTROL_ID] Remediation complete"
    
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
