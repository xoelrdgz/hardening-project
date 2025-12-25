#!/usr/bin/env bash
#===============================================================================
# CIS Control: 1.1.1.9 - Ensure usb-storage kernel module is not available
# Profile: Level 1 - Server, Level 2 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="1.1.1.9"
CONTROL_DESC="Ensure usb-storage kernel module is not available"
MOD_NAME="usb-storage"
MOD_TYPE="drivers"

source_common() {
    if [[ -n "${LOG_FILE:-}" ]]; then
        return 0
    fi
    # Standalone execution
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
    local mod_path
    mod_path="$(readlink -f /lib/modules/**/kernel/$MOD_TYPE 2>/dev/null | sort -u || true)"
    
    # Check if module exists
    local module_exists=false
    for base_dir in $mod_path; do
        if [[ -d "$base_dir/${MOD_NAME/-/\/}" ]] && [[ -n "$(ls -A "$base_dir/${MOD_NAME/-/\/}" 2>/dev/null)" ]]; then
            module_exists=true
            break
        fi
    done
    
    if ! $module_exists; then
        log_success "[$CONTROL_ID] Kernel module '$MOD_NAME' does not exist on system"
        return 0
    fi
    
    # Check if module is loaded
    if lsmod | grep -q "$MOD_NAME"; then
        log_error "[$CONTROL_ID] Kernel module '$MOD_NAME' is loaded"
        result=1
    else
        log_success "[$CONTROL_ID] Kernel module '$MOD_NAME' is not loaded"
    fi
    
    # Check if module is disabled
    local showconfig
    showconfig=$(modprobe --showconfig 2>/dev/null | grep -P '\b(install|blacklist)\h+'"${MOD_NAME//-/_}"'\b' || true)
    
    if echo "$showconfig" | grep -Pq '\binstall\h+'"${MOD_NAME//-/_}"'\h+(\/usr)?\/bin\/(true|false)\b'; then
        log_success "[$CONTROL_ID] Kernel module '$MOD_NAME' is not loadable"
    else
        log_error "[$CONTROL_ID] Kernel module '$MOD_NAME' is loadable"
        result=1
    fi
    
    if echo "$showconfig" | grep -Pq '\bblacklist\h+'"${MOD_NAME//-/_}"'\b'; then
        log_success "[$CONTROL_ID] Kernel module '$MOD_NAME' is deny listed"
    else
        log_error "[$CONTROL_ID] Kernel module '$MOD_NAME' is not deny listed"
        result=1
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    local mod_path
    mod_path="$(readlink -f /lib/modules/**/kernel/$MOD_TYPE 2>/dev/null | sort -u || true)"
    
    # Check if module exists
    local module_exists=false
    for base_dir in $mod_path; do
        if [[ -d "$base_dir/${MOD_NAME/-/\/}" ]] && [[ -n "$(ls -A "$base_dir/${MOD_NAME/-/\/}" 2>/dev/null)" ]]; then
            module_exists=true
            break
        fi
    done
    
    if ! $module_exists; then
        log_info "[$CONTROL_ID] Kernel module '$MOD_NAME' does not exist - no remediation needed"
        return 0
    fi
    
    local conf_file="/etc/modprobe.d/${MOD_NAME}.conf"
    
    # Backup existing config if present
    backup_file "$conf_file"
    
    # Unload module if loaded
    if lsmod | grep -q "$MOD_NAME"; then
        log_info "[$CONTROL_ID] Unloading kernel module '$MOD_NAME'"
        modprobe -r "$MOD_NAME" 2>/dev/null || rmmod "$MOD_NAME" 2>/dev/null || true
    fi
    
    # Create modprobe config to disable module
    local showconfig
    showconfig=$(modprobe --showconfig 2>/dev/null | grep -P '\b(install|blacklist)\h+'"${MOD_NAME//-/_}"'\b' || true)
    
    if ! echo "$showconfig" | grep -Pq '\binstall\h+'"${MOD_NAME//-/_}"'\h+(\/usr)?\/bin\/(true|false)\b'; then
        log_info "[$CONTROL_ID] Setting kernel module '$MOD_NAME' to not loadable"
        echo "install ${MOD_NAME//-/_} $(readlink -f /bin/false)" >> "$conf_file"
    fi
    
    if ! echo "$showconfig" | grep -Pq '\bblacklist\h+'"${MOD_NAME//-/_}"'\b'; then
        log_info "[$CONTROL_ID] Deny listing kernel module '$MOD_NAME'"
        echo "blacklist ${MOD_NAME//-/_}" >> "$conf_file"
    fi
    
    log_success "[$CONTROL_ID] Remediation complete for '$MOD_NAME'"
    
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
