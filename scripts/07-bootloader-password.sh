#!/usr/bin/env bash
#===============================================================================
# CIS Control: 1.4.1 - Ensure bootloader password is set
# Profile: Level 1 - Server, Level 1 - Workstation
# Automated: Yes
#
# AUTOMATION SUPPORT:
# This script supports CI/CD and automated deployments via environment variables
# or pre-generated password hashes. Set one of the following:
#
#   GRUB_PASSWORD_HASH - Pre-generated PBKDF2 hash (recommended for automation)
#   GRUB_PASSWORD      - Plain text password (will be hashed - less secure)
#   GRUB_USERNAME      - Custom superuser name (default: grubadmin)
#
# To generate a hash manually:
#   grub-mkpasswd-pbkdf2 --iteration-count=600000
#
# Example CI/CD usage:
#   export GRUB_PASSWORD_HASH="grub.pbkdf2.sha512.600000.XXXX..."
#   ./07-bootloader-password.sh --remediate
#===============================================================================

set -euo pipefail

CONTROL_ID="1.4.1"
CONTROL_DESC="Ensure bootloader password is set"

# Default values - can be overridden by environment variables
GRUB_USERNAME="${GRUB_USERNAME:-grubadmin}"
GRUB_PASSWORD_HASH="${GRUB_PASSWORD_HASH:-}"
GRUB_PASSWORD="${GRUB_PASSWORD:-}"

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
# Generate password hash from plain text (for automation with GRUB_PASSWORD)
#===============================================================================
generate_password_hash() {
    local password="$1"
    local hash
    
    # Use expect or echo to automate grub-mkpasswd-pbkdf2
    hash=$(echo -e "${password}\n${password}" | grub-mkpasswd-pbkdf2 --iteration-count=600000 2>/dev/null | grep "PBKDF2" | awk '{print $NF}' || echo "")
    
    if [[ -z "$hash" ]]; then
        return 1
    fi
    
    echo "$hash"
}

#===============================================================================
# Audit Function
#===============================================================================
audit() {
    log_info "[$CONTROL_ID] Auditing: $CONTROL_DESC"
    
    local result=0
    local grub_cfg="/boot/grub/grub.cfg"
    
    if [[ ! -f "$grub_cfg" ]]; then
        log_error "[$CONTROL_ID] GRUB config not found at $grub_cfg"
        return 1
    fi
    
    # Check for superusers setting
    if grep -q "^set superusers" "$grub_cfg"; then
        log_success "[$CONTROL_ID] GRUB superuser is configured"
        grep "^set superusers" "$grub_cfg" | head -1
    else
        log_error "[$CONTROL_ID] GRUB superuser is NOT configured"
        result=1
    fi
    
    # Check for password_pbkdf2 setting
    if grep -q "^password_pbkdf2" "$grub_cfg" || grep -q "password_pbkdf2" "$grub_cfg"; then
        log_success "[$CONTROL_ID] GRUB password is configured"
    else
        log_error "[$CONTROL_ID] GRUB password is NOT configured"
        result=1
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    local grub_custom="/etc/grub.d/40_custom"
    local encrypted_password=""
    
    # Check if password is already set
    if grep -q "^password_pbkdf2" /boot/grub/grub.cfg 2>/dev/null; then
        log_info "[$CONTROL_ID] GRUB password already configured"
        audit
        return 0
    fi
    
    #---------------------------------------------------------------------------
    # Priority 1: Use pre-generated hash from environment (CI/CD recommended)
    #---------------------------------------------------------------------------
    if [[ -n "$GRUB_PASSWORD_HASH" ]]; then
        log_info "[$CONTROL_ID] Using pre-generated password hash from GRUB_PASSWORD_HASH"
        encrypted_password="$GRUB_PASSWORD_HASH"
        
        # Validate hash format
        if ! [[ "$encrypted_password" =~ ^grub\.pbkdf2\. ]]; then
            log_error "[$CONTROL_ID] Invalid hash format. Must start with 'grub.pbkdf2.'"
            log_error "[$CONTROL_ID] Generate with: grub-mkpasswd-pbkdf2 --iteration-count=600000"
            return 1
        fi
    
    #---------------------------------------------------------------------------
    # Priority 2: Generate hash from plain password (automation fallback)
    #---------------------------------------------------------------------------
    elif [[ -n "$GRUB_PASSWORD" ]]; then
        log_info "[$CONTROL_ID] Generating hash from GRUB_PASSWORD environment variable"
        log_warning "[$CONTROL_ID] Consider using GRUB_PASSWORD_HASH for better security"
        
        encrypted_password=$(generate_password_hash "$GRUB_PASSWORD")
        
        if [[ -z "$encrypted_password" ]]; then
            log_error "[$CONTROL_ID] Failed to generate password hash"
            return 1
        fi
        
        # Clear password from environment for security
        unset GRUB_PASSWORD
    
    #---------------------------------------------------------------------------
    # Priority 3: Interactive mode (manual execution)
    #---------------------------------------------------------------------------
    elif [[ -t 0 ]]; then
        log_info "[$CONTROL_ID] Interactive mode - requesting password input"
        echo ""
        echo "Please enter the GRUB bootloader password:"
        encrypted_password=$(grub-mkpasswd-pbkdf2 --iteration-count=600000 2>&1 | grep "PBKDF2" | awk '{print $NF}' || echo "")
        
        if [[ -z "$encrypted_password" ]]; then
            log_error "[$CONTROL_ID] Failed to generate encrypted password"
            return 1
        fi
    
    #---------------------------------------------------------------------------
    # No password source available
    #---------------------------------------------------------------------------
    else
        log_error "[$CONTROL_ID] No password source available for non-interactive mode"
        log_error "[$CONTROL_ID] "
        log_error "[$CONTROL_ID] For CI/CD automation, set one of these environment variables:"
        log_error "[$CONTROL_ID]   GRUB_PASSWORD_HASH - Pre-generated PBKDF2 hash (recommended)"
        log_error "[$CONTROL_ID]   GRUB_PASSWORD      - Plain text password (will be hashed)"
        log_error "[$CONTROL_ID] "
        log_error "[$CONTROL_ID] To generate a hash:"
        log_error "[$CONTROL_ID]   grub-mkpasswd-pbkdf2 --iteration-count=600000"
        log_error "[$CONTROL_ID] "
        log_error "[$CONTROL_ID] Example:"
        log_error "[$CONTROL_ID]   export GRUB_PASSWORD_HASH='grub.pbkdf2.sha512.600000.XXX...'"
        log_error "[$CONTROL_ID]   ./07-bootloader-password.sh --remediate"
        return 1
    fi
    
    # Backup existing config
    backup_file "$grub_custom"
    
    # Create grub custom file with password
    log_info "[$CONTROL_ID] Configuring GRUB with superuser: $GRUB_USERNAME"
    cat > "$grub_custom" << EOF
#!/bin/sh
exec tail -n +3 \$0
# GRUB bootloader password - CIS Control $CONTROL_ID
# Configured: $(date -Iseconds)
# WARNING: Do not edit manually - managed by hardening scripts
set superusers="$GRUB_USERNAME"
password_pbkdf2 $GRUB_USERNAME $encrypted_password
EOF
    
    chmod 755 "$grub_custom"
    
    # Update grub
    log_info "[$CONTROL_ID] Updating GRUB configuration"
    update-grub 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg
    
    log_success "[$CONTROL_ID] GRUB password configured successfully"
    log_info "[$CONTROL_ID] Superuser: $GRUB_USERNAME"
    log_warning "[$CONTROL_ID] Store credentials securely - required to edit boot parameters"
    
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
