#!/usr/bin/env bash
#===============================================================================
# CIS Control: 6.2.3.10 - Ensure successful file system mounts are collected
# Profile: Level 2 - Server, Level 2 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="6.2.3.10"
CONTROL_DESC="Ensure successful file system mounts are collected"

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
    local rules_dir="/etc/audit/rules.d"
    
    # Get UID_MIN
    local uid_min
    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || echo "1000")
    
    # Check disk rules
    if [[ -d "$rules_dir" ]]; then
        if grep -rh -- "mount" "$rules_dir"/*.rules 2>/dev/null | grep -q "mounts\|mount"; then
            # Check for both architectures
            if grep -rh -- "arch=b64" "$rules_dir"/*.rules 2>/dev/null | grep -q "mount" && \
               grep -rh -- "arch=b32" "$rules_dir"/*.rules 2>/dev/null | grep -q "mount"; then
                log_success "[$CONTROL_ID] Mount audit rules found for both architectures"
            else
                log_warning "[$CONTROL_ID] Mount audit rules may be missing for one architecture"
            fi
        else
            log_error "[$CONTROL_ID] Mount audit rules not found in disk config"
            result=1
        fi
    else
        log_error "[$CONTROL_ID] Audit rules directory not found: $rules_dir"
        result=1
    fi
    
    # Check running configuration
    if command -v auditctl &>/dev/null; then
        local running_rules
        running_rules=$(auditctl -l 2>/dev/null || true)
        
        if echo "$running_rules" | grep -q "mount"; then
            log_success "[$CONTROL_ID] Mount audit rules loaded in running config"
        else
            log_warning "[$CONTROL_ID] Mount audit rules may not be loaded in running config"
        fi
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    local rules_dir="/etc/audit/rules.d"
    local rules_file="$rules_dir/50-mounts.rules"
    
    # Get UID_MIN
    local uid_min
    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || echo "1000")
    
    if [[ -z "$uid_min" ]]; then
        log_error "[$CONTROL_ID] Could not determine UID_MIN from /etc/login.defs"
        uid_min="1000"
    fi
    
    # Create rules directory if needed
    mkdir -p "$rules_dir"
    
    # Backup existing rules file
    backup_file "$rules_file"
    
    # Create audit rules for mount events
    log_info "[$CONTROL_ID] Creating mount audit rules (UID_MIN: $uid_min)"
    cat > "$rules_file" << EOF
## CIS Control 6.2.3.10 - Audit successful file system mounts

# Monitor mount syscall - 32-bit
-a always,exit -F arch=b32 -S mount -F auid>=$uid_min -F auid!=unset -k mounts

# Monitor mount syscall - 64-bit
-a always,exit -F arch=b64 -S mount -F auid>=$uid_min -F auid!=unset -k mounts
EOF
    
    # Set proper permissions
    chmod 640 "$rules_file"
    
    # Load the rules
    log_info "[$CONTROL_ID] Loading audit rules"
    if command -v augenrules &>/dev/null; then
        augenrules --load 2>/dev/null || true
    fi
    
    # Check if reboot is required
    if command -v auditctl &>/dev/null; then
        if auditctl -s 2>/dev/null | grep -q "enabled.*2"; then
            log_warning "[$CONTROL_ID] Audit rules are locked - reboot required to load new rules"
        fi
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
