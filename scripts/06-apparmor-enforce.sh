#!/usr/bin/env bash
#===============================================================================
# CIS Control: 1.3.1.4 - Ensure all AppArmor Profiles are enforcing
# Profile: Level 2 - Server, Level 2 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="1.3.1.4"
CONTROL_DESC="Ensure all AppArmor Profiles are enforcing"

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
    
    # Check if AppArmor is installed
    if ! command -v apparmor_status &>/dev/null; then
        log_error "[$CONTROL_ID] AppArmor is not installed"
        return 1
    fi
    
    # Get AppArmor status
    local status_output
    status_output=$(apparmor_status 2>/dev/null || true)
    
    # Check profiles loaded
    local profiles_loaded
    profiles_loaded=$(echo "$status_output" | grep "profiles are loaded" | awk '{print $1}' || echo "0")
    log_info "[$CONTROL_ID] $profiles_loaded profiles are loaded"
    
    # Check profiles in enforce mode
    local profiles_enforce
    profiles_enforce=$(echo "$status_output" | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")
    log_info "[$CONTROL_ID] $profiles_enforce profiles are in enforce mode"
    
    # Check profiles in complain mode
    local profiles_complain
    profiles_complain=$(echo "$status_output" | grep "profiles are in complain mode" | awk '{print $1}' || echo "0")
    
    if [[ "$profiles_complain" -gt 0 ]]; then
        log_error "[$CONTROL_ID] $profiles_complain profiles are in complain mode"
        result=1
    else
        log_success "[$CONTROL_ID] No profiles in complain mode"
    fi
    
    # Check for unconfined processes
    local unconfined
    unconfined=$(echo "$status_output" | grep "processes are unconfined" | awk '{print $1}' || echo "0")
    
    if [[ "$unconfined" -gt 0 ]]; then
        log_warning "[$CONTROL_ID] $unconfined processes are unconfined"
        result=1
    else
        log_success "[$CONTROL_ID] No unconfined processes"
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    # Check if AppArmor is installed
    if ! command -v apparmor_status &>/dev/null; then
        log_info "[$CONTROL_ID] Installing AppArmor"
        apt-get update -qq
        apt-get install -y -qq apparmor apparmor-utils
    fi
    
    # Ensure AppArmor service is enabled and started
    systemctl enable apparmor 2>/dev/null || true
    systemctl start apparmor 2>/dev/null || true
    
    # Set all profiles to enforce mode
    if command -v aa-enforce &>/dev/null; then
        log_info "[$CONTROL_ID] Setting all profiles to enforce mode"
        
        # Get list of profiles in complain mode and enforce them
        local profiles_dir="/etc/apparmor.d"
        
        if [[ -d "$profiles_dir" ]]; then
            for profile in "$profiles_dir"/*; do
                if [[ -f "$profile" ]] && [[ ! "$profile" =~ (abstractions|disable|force-complain|local|tunables|lxc) ]]; then
                    aa-enforce "$profile" 2>/dev/null || true
                fi
            done
        fi
    else
        log_warning "[$CONTROL_ID] aa-enforce not available, installing apparmor-utils"
        apt-get install -y -qq apparmor-utils
        
        # Retry enforcement
        for profile in /etc/apparmor.d/*; do
            if [[ -f "$profile" ]] && [[ ! "$profile" =~ (abstractions|disable|force-complain|local|tunables|lxc) ]]; then
                aa-enforce "$profile" 2>/dev/null || true
            fi
        done
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
