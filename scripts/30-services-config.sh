#!/usr/bin/env bash
#===============================================================================
# CIS Control: 2.1 - Services Configuration
# Profile: Level 1 - Server
# Automated: Yes
# Description: Disables unnecessary services and configures MTA
#===============================================================================

set -euo pipefail

CONTROL_ID="2.1"
CONTROL_DESC="Services Configuration"

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

SERVICES_TO_DISABLE=(
    "autofs"
    "avahi-daemon"
    "cups"
    "bluetooth"
)

#===============================================================================
# Audit Function
#===============================================================================
audit() {
    log_info "[$CONTROL_ID] Auditing: $CONTROL_DESC"
    
    local result=0
    
    # 2.1.1 - Check autofs and other services
    for svc in "${SERVICES_TO_DISABLE[@]}"; do
        local status
        status=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
        
        if [[ "$status" == "not-found" ]]; then
            log_success "[$CONTROL_ID] $svc is not installed"
        elif [[ "$status" == "disabled" ]] || [[ "$status" == "masked" ]]; then
            log_success "[$CONTROL_ID] $svc is disabled/masked"
        else
            log_error "[$CONTROL_ID] $svc is enabled ($status)"
            result=1
        fi
    done
    
    # 2.1.21 - Check MTA local-only mode
    if command -v postconf &>/dev/null; then
        local inet_interfaces
        inet_interfaces=$(postconf -h inet_interfaces 2>/dev/null || echo "")
        if [[ "$inet_interfaces" == "loopback-only" ]] || [[ "$inet_interfaces" == "localhost" ]]; then
            log_success "[$CONTROL_ID] Postfix configured for local-only mode"
        else
            log_warning "[$CONTROL_ID] Postfix inet_interfaces = $inet_interfaces"
        fi
    fi
    
    # Check for external MTA listeners
    if ss -tlnp | grep -q ':25 ' | grep -v '127.0.0.1\|::1'; then
        log_warning "[$CONTROL_ID] MTA listening on external interfaces"
    fi
    
    # 2.2.4 - Check telnet
    if dpkg-query -s telnet &>/dev/null; then
        log_error "[$CONTROL_ID] telnet client is installed"
        result=1
    else
        log_success "[$CONTROL_ID] telnet client is not installed"
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    # Disable unnecessary services
    for svc in "${SERVICES_TO_DISABLE[@]}"; do
        if systemctl list-unit-files | grep -q "^$svc"; then
            log_info "[$CONTROL_ID] Disabling $svc"
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            systemctl mask "$svc" 2>/dev/null || true
        fi
    done
    
    # Configure postfix for local-only mode
    if command -v postconf &>/dev/null; then
        log_info "[$CONTROL_ID] Configuring Postfix for local-only mode"
        postconf -e "inet_interfaces = loopback-only"
        systemctl restart postfix 2>/dev/null || true
    fi
    
    # Remove telnet client
    if dpkg-query -s telnet &>/dev/null; then
        log_info "[$CONTROL_ID] Removing telnet client"
        apt-get purge -y telnet
    fi
    
    # Remove other insecure packages
    for pkg in nis rsh-client; do
        if dpkg-query -s "$pkg" &>/dev/null; then
            log_info "[$CONTROL_ID] Removing $pkg"
            apt-get purge -y "$pkg"
        fi
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
