#!/usr/bin/env bash
#===============================================================================
# CIS Control: 3.3.4 - Ensure ICMP echo requests to broadcast are ignored
# Profile: Level 1 - Server
# Automated: Yes
# Description: Prevents smurf attacks (ICMP amplification)
#===============================================================================

set -euo pipefail

CONTROL_ID="3.3.4"
CONTROL_DESC="Ensure broadcast ICMP requests are ignored"
SYSCTL_FILE="/etc/sysctl.d/60-cis-network.conf"

PARAM_NAME="net.ipv4.icmp_echo_ignore_broadcasts"
PARAM_VALUE="1"

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
    local running_value
    running_value=$(sysctl -n "$PARAM_NAME" 2>/dev/null || echo "")
    
    if [[ "$running_value" == "$PARAM_VALUE" ]]; then
        log_success "[$CONTROL_ID] $PARAM_NAME = $running_value"
    else
        log_error "[$CONTROL_ID] $PARAM_NAME = '$running_value' (expected: $PARAM_VALUE)"
        result=1
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    mkdir -p /etc/sysctl.d
    
    # Create or update the sysctl file
    if [[ ! -f "$SYSCTL_FILE" ]]; then
        echo "# CIS Network Hardening Configuration" > "$SYSCTL_FILE"
        echo "# Managed by CIS hardening scripts" >> "$SYSCTL_FILE"
    fi
    
    # Remove from other config files (not our managed file)
    for file in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
        if [[ -f "$file" ]] && [[ "$file" != "$SYSCTL_FILE" ]]; then
            if grep -qE "^\s*${PARAM_NAME}\s*=" "$file" 2>/dev/null; then
                backup_file "$file"
                sed -i "/^\s*${PARAM_NAME}\s*=/d" "$file"
                log_info "[$CONTROL_ID] Removed $PARAM_NAME from $file"
            fi
        fi
    done
    
    # Update or add in our managed file (idempotent)
    if grep -qE "^\s*${PARAM_NAME}\s*=" "$SYSCTL_FILE" 2>/dev/null; then
        sed -i "s|^\s*${PARAM_NAME}\s*=.*|${PARAM_NAME} = ${PARAM_VALUE}|" "$SYSCTL_FILE"
    else
        echo "${PARAM_NAME} = ${PARAM_VALUE}" >> "$SYSCTL_FILE"
    fi
    
    # Apply immediately
    sysctl -w "${PARAM_NAME}=${PARAM_VALUE}" >/dev/null 2>&1 || true
    
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
