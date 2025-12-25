#!/usr/bin/env bash
#===============================================================================
# CIS Control: 1.5.2 - Ensure ptrace_scope is restricted
# Profile: Level 1 - Server, Level 1 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="1.5.2"
CONTROL_DESC="Ensure ptrace_scope is restricted"
PARAM_NAME="kernel.yama.ptrace_scope"
PARAM_VALUE="1"  # 1 = restricted, 2 = admin-only, 3 = no attach

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
    
    # Check running configuration
    local running_value
    running_value=$(sysctl -n "$PARAM_NAME" 2>/dev/null || echo "0")
    
    # Valid values are 1, 2, or 3
    if [[ "$running_value" =~ ^[123]$ ]]; then
        log_success "[$CONTROL_ID] $PARAM_NAME is correctly set to $running_value in running config"
    else
        log_error "[$CONTROL_ID] $PARAM_NAME is set to $running_value (should be 1, 2, or 3)"
        result=1
    fi
    
    # Check persistent configuration
    local config_files=("/etc/sysctl.conf" "/etc/sysctl.d/*.conf")
    local found_config=false
    
    for pattern in "${config_files[@]}"; do
        for file in $pattern; do
            if [[ -f "$file" ]]; then
                if grep -qE "^\s*${PARAM_NAME}\s*=\s*[123]" "$file" 2>/dev/null; then
                    log_success "[$CONTROL_ID] $PARAM_NAME correctly configured in $file"
                    found_config=true
                    break 2
                fi
            fi
        done
    done
    
    if ! $found_config; then
        log_warning "[$CONTROL_ID] $PARAM_NAME not found in persistent configuration files"
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
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
            if grep -qE "^\s*${PARAM_NAME}\s*=" "$file" 2>/dev/null; then
                backup_file "$file"
                sed -i "/^\s*${PARAM_NAME}\s*=/d" "$file"
                log_info "[$CONTROL_ID] Removed $PARAM_NAME from $file"
            fi
        fi
    done
    
    # Update or add in our managed file (idempotent)
    if grep -qE "^\s*${PARAM_NAME}\s*=" "$sysctl_file" 2>/dev/null; then
        sed -i "s|^\s*${PARAM_NAME}\s*=.*|${PARAM_NAME} = ${PARAM_VALUE}|" "$sysctl_file"
    else
        echo "${PARAM_NAME} = ${PARAM_VALUE}" >> "$sysctl_file"
    fi
    
    # Apply the setting immediately
    sysctl -w "${PARAM_NAME}=${PARAM_VALUE}" >/dev/null
    
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
