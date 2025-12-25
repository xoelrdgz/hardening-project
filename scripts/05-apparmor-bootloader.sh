#!/usr/bin/env bash
#===============================================================================
# CIS Control: 1.3.1.2 - Ensure AppArmor is enabled in bootloader configuration
# Profile: Level 1 - Server, Level 1 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="1.3.1.2"
CONTROL_DESC="Ensure AppArmor is enabled in the bootloader configuration"

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
    local grub_cfg="/boot/grub/grub.cfg"
    
    if [[ ! -f "$grub_cfg" ]]; then
        log_error "[$CONTROL_ID] GRUB config not found at $grub_cfg"
        return 1
    fi
    
    # Check for apparmor=1
    if grep "^\s*linux" "$grub_cfg" | grep -v "apparmor=1" | grep -q "linux"; then
        log_error "[$CONTROL_ID] Some linux lines missing apparmor=1 parameter"
        result=1
    else
        log_success "[$CONTROL_ID] All linux lines have apparmor=1 parameter"
    fi
    
    # Check for security=apparmor
    if grep "^\s*linux" "$grub_cfg" | grep -v "security=apparmor" | grep -q "linux"; then
        log_error "[$CONTROL_ID] Some linux lines missing security=apparmor parameter"
        result=1
    else
        log_success "[$CONTROL_ID] All linux lines have security=apparmor parameter"
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    local grub_default="/etc/default/grub"
    
    if [[ ! -f "$grub_default" ]]; then
        log_error "[$CONTROL_ID] GRUB default config not found at $grub_default"
        return 1
    fi
    
    backup_file "$grub_default"
    
    # Get current GRUB_CMDLINE_LINUX value
    local current_cmdline
    current_cmdline=$(grep "^GRUB_CMDLINE_LINUX=" "$grub_default" | cut -d'"' -f2 || echo "")
    
    local new_cmdline="$current_cmdline"
    
    # Add apparmor=1 if not present
    if ! echo "$current_cmdline" | grep -q "apparmor=1"; then
        log_info "[$CONTROL_ID] Adding apparmor=1 to GRUB_CMDLINE_LINUX"
        new_cmdline="$new_cmdline apparmor=1"
    fi
    
    # Add security=apparmor if not present
    if ! echo "$current_cmdline" | grep -q "security=apparmor"; then
        log_info "[$CONTROL_ID] Adding security=apparmor to GRUB_CMDLINE_LINUX"
        new_cmdline="$new_cmdline security=apparmor"
    fi
    
    # Clean up extra spaces
    new_cmdline=$(echo "$new_cmdline" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr -s ' ')
    
    # Update grub config
    if [[ "$current_cmdline" != "$new_cmdline" ]]; then
        sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"$new_cmdline\"|" "$grub_default"
        
        # Update grub
        log_info "[$CONTROL_ID] Updating GRUB configuration"
        update-grub 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg
    else
        log_info "[$CONTROL_ID] AppArmor parameters already present in GRUB config"
    fi
    
    log_success "[$CONTROL_ID] Remediation complete"
    log_warning "[$CONTROL_ID] System reboot required for changes to take effect"
    
    # Verify (will show current state, not yet applied)
    audit || true
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
