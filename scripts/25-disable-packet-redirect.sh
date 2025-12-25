#!/usr/bin/env bash
#===============================================================================
# CIS Control: 3.3.2 - Ensure packet redirect sending is disabled
# Profile: Level 1 - Server
# Automated: Yes
# Description: Prevents MITM attacks by disabling ICMP redirect sending
#===============================================================================

set -euo pipefail

CONTROL_ID="3.3.2"
CONTROL_DESC="Ensure packet redirect sending is disabled"
SYSCTL_FILE="/etc/sysctl.d/60-cis-network.conf"

declare -A PARAMS
PARAMS["net.ipv4.conf.all.send_redirects"]="0"
PARAMS["net.ipv4.conf.default.send_redirects"]="0"

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
    
    for param in "${!PARAMS[@]}"; do
        local expected="${PARAMS[$param]}"
        local running_value
        running_value=$(sysctl -n "$param" 2>/dev/null || echo "")
        
        if [[ "$running_value" == "$expected" ]]; then
            log_success "[$CONTROL_ID] $param = $running_value"
        else
            log_error "[$CONTROL_ID] $param = '$running_value' (expected: $expected)"
            result=1
        fi
    done
    
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
    
    for param in "${!PARAMS[@]}"; do
        local value="${PARAMS[$param]}"
        
        # Remove from other config files (not our managed file)
        for file in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
            if [[ -f "$file" ]] && [[ "$file" != "$SYSCTL_FILE" ]]; then
                if grep -qE "^\s*${param}\s*=" "$file" 2>/dev/null; then
                    backup_file "$file"
                    sed -i "/^\s*${param}\s*=/d" "$file"
                    log_info "[$CONTROL_ID] Removed $param from $file"
                fi
            fi
        done
        
        # Update or add in our managed file (idempotent)
        if grep -qE "^\s*${param}\s*=" "$SYSCTL_FILE" 2>/dev/null; then
            sed -i "s|^\s*${param}\s*=.*|${param} = ${value}|" "$SYSCTL_FILE"
        else
            echo "${param} = ${value}" >> "$SYSCTL_FILE"
        fi
        
        # Apply immediately
        sysctl -w "${param}=${value}" >/dev/null 2>&1 || true
    done
    
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
