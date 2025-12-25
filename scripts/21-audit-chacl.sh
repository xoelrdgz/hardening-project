#!/usr/bin/env bash
#===============================================================================
# CIS Control: 6.2.3.17 - Ensure successful/unsuccessful attempts to use chacl are collected
# Profile: Level 2 - Server, Level 2 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="6.2.3.17"
CONTROL_DESC="Ensure successful and unsuccessful attempts to use the chacl command are collected"

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
    
    # Check if chacl exists
    if ! command -v chacl &>/dev/null && [[ ! -f /usr/bin/chacl ]]; then
        log_info "[$CONTROL_ID] chacl command not found - audit rule may not be required"
        return 0
    fi
    
    # Check disk rules
    if [[ -d "$rules_dir" ]]; then
        if grep -rh -- "/usr/bin/chacl" "$rules_dir"/*.rules 2>/dev/null | grep -q "perm_chng\|priv_cmd"; then
            log_success "[$CONTROL_ID] chacl audit rule found in disk config"
        else
            log_error "[$CONTROL_ID] chacl audit rule not found in disk config"
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
        
        if echo "$running_rules" | grep -q "chacl"; then
            log_success "[$CONTROL_ID] chacl audit rule loaded in running config"
        else
            log_warning "[$CONTROL_ID] chacl audit rule may not be loaded in running config"
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
    local rules_file="$rules_dir/50-perm_chng.rules"
    
    # Get UID_MIN
    local uid_min
    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || echo "1000")
    
    if [[ -z "$uid_min" ]]; then
        log_error "[$CONTROL_ID] Could not determine UID_MIN from /etc/login.defs"
        uid_min="1000"
    fi
    
    # Create rules directory if needed
    mkdir -p "$rules_dir"
    
    # Backup existing rules file if it exists
    backup_file "$rules_file"
    
    # Check if file exists and append, otherwise create
    if [[ -f "$rules_file" ]]; then
        # Check if chacl rule already exists
        if ! grep -q "/usr/bin/chacl" "$rules_file"; then
            log_info "[$CONTROL_ID] Adding chacl audit rule"
            cat >> "$rules_file" << EOF

# CIS Control 6.2.3.17 - Audit chacl command usage
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=$uid_min -F auid!=unset -k perm_chng
EOF
        fi
    else
        log_info "[$CONTROL_ID] Creating permission change audit rules"
        cat > "$rules_file" << EOF
## CIS Control 6.2.3.17 - Audit chacl command usage

# Monitor chacl command execution
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=$uid_min -F auid!=unset -k perm_chng
EOF
    fi
    
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
