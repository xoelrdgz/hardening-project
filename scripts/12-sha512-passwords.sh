#!/usr/bin/env bash
#===============================================================================
# CIS Control: 5.4.1.4 - Ensure strong password hashing algorithm is configured
# Profile: Level 1 - Server, Level 1 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="5.4.1.4"
CONTROL_DESC="Ensure strong password hashing algorithm is configured"
REQUIRED_ALGO="SHA512"  # or yescrypt for newer systems

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
    local login_defs="/etc/login.defs"
    
    if [[ ! -f "$login_defs" ]]; then
        log_error "[$CONTROL_ID] $login_defs not found"
        return 1
    fi
    
    # Check ENCRYPT_METHOD in login.defs
    local encrypt_method
    encrypt_method=$(grep -E "^\s*ENCRYPT_METHOD" "$login_defs" | awk '{print $2}' || echo "")
    
    if [[ -z "$encrypt_method" ]]; then
        log_error "[$CONTROL_ID] ENCRYPT_METHOD not configured in $login_defs"
        result=1
    elif [[ "$encrypt_method" == "SHA512" ]] || [[ "$encrypt_method" == "yescrypt" ]]; then
        log_success "[$CONTROL_ID] ENCRYPT_METHOD is set to $encrypt_method"
    else
        log_error "[$CONTROL_ID] ENCRYPT_METHOD is set to $encrypt_method (should be SHA512 or yescrypt)"
        result=1
    fi
    
    # Check PAM configuration for password hashing
    local pam_password_file="/etc/pam.d/common-password"
    
    if [[ -f "$pam_password_file" ]]; then
        if grep -qE '(sha512|yescrypt)' "$pam_password_file"; then
            log_success "[$CONTROL_ID] PAM is configured with strong password hashing"
        else
            log_warning "[$CONTROL_ID] PAM may not be using strong password hashing"
        fi
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    local login_defs="/etc/login.defs"
    
    if [[ ! -f "$login_defs" ]]; then
        log_error "[$CONTROL_ID] $login_defs not found"
        return 1
    fi
    
    backup_file "$login_defs"
    
    # Set or update ENCRYPT_METHOD
    if grep -qE "^\s*ENCRYPT_METHOD" "$login_defs"; then
        log_info "[$CONTROL_ID] Updating ENCRYPT_METHOD to $REQUIRED_ALGO"
        sed -i "s/^\s*ENCRYPT_METHOD.*/ENCRYPT_METHOD $REQUIRED_ALGO/" "$login_defs"
    else
        log_info "[$CONTROL_ID] Adding ENCRYPT_METHOD $REQUIRED_ALGO"
        echo "ENCRYPT_METHOD $REQUIRED_ALGO" >> "$login_defs"
    fi
    
    # Update PAM configuration if needed
    local pam_password_file="/etc/pam.d/common-password"
    
    if [[ -f "$pam_password_file" ]]; then
        backup_file "$pam_password_file"
        
        # Ensure sha512 is used in PAM
        if grep -qE 'pam_unix\.so.*sha512' "$pam_password_file"; then
            log_info "[$CONTROL_ID] PAM already configured with sha512"
        elif grep -qE 'pam_unix\.so' "$pam_password_file"; then
            log_info "[$CONTROL_ID] Adding sha512 to pam_unix.so configuration"
            sed -i 's/\(pam_unix\.so[^#]*\)/\1 sha512/' "$pam_password_file"
        fi
    fi
    
    log_success "[$CONTROL_ID] Remediation complete"
    log_warning "[$CONTROL_ID] Existing user passwords will use new algorithm on next change"
    
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
