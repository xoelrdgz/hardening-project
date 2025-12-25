#!/usr/bin/env bash
#===============================================================================
# CIS Control: 6.2.3.4 - Ensure events that modify date and time are collected
# Profile: Level 2 - Server, Level 2 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="6.2.3.4"
CONTROL_DESC="Ensure events that modify date and time information are collected"

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
    
    # Check on-disk configuration
    local required_rules=(
        "-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change"
        "-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change"
        "-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change"
        "-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change"
        "-w /etc/localtime -p wa -k time-change"
    )
    
    # Check disk rules
    if [[ -d "$rules_dir" ]]; then
        for rule in "${required_rules[@]}"; do
            # Simplify pattern for grep
            local pattern
            pattern=$(echo "$rule" | sed 's/-F a0=0x0//' | sed 's/  */ /g')
            
            if grep -rh -- "time-change" "$rules_dir"/*.rules 2>/dev/null | grep -q "adjtimex\|settimeofday\|clock_settime\|localtime"; then
                :  # Rule pattern found
            else
                log_error "[$CONTROL_ID] Missing rule pattern in disk config: $rule"
                result=1
                break
            fi
        done
        
        if [[ $result -eq 0 ]]; then
            log_success "[$CONTROL_ID] Time change audit rules found in disk config"
        fi
    else
        log_error "[$CONTROL_ID] Audit rules directory not found: $rules_dir"
        result=1
    fi
    
    # Check running configuration
    if command -v auditctl &>/dev/null; then
        local running_rules
        running_rules=$(auditctl -l 2>/dev/null || true)
        
        if echo "$running_rules" | grep -q "time-change"; then
            log_success "[$CONTROL_ID] Time change audit rules loaded in running config"
        else
            log_warning "[$CONTROL_ID] Time change audit rules may not be loaded in running config"
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
    local rules_file="$rules_dir/50-time-change.rules"
    
    # Create rules directory if needed
    mkdir -p "$rules_dir"
    
    # Backup existing rules file
    backup_file "$rules_file"
    
    # Create audit rules for time change events
    log_info "[$CONTROL_ID] Creating time change audit rules"
    cat > "$rules_file" << 'EOF'
## CIS Control 6.2.3.4 - Audit date and time modification events

# adjtimex and settimeofday syscalls - 64-bit
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change

# adjtimex and settimeofday syscalls - 32-bit
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change

# clock_settime syscall - 64-bit (CLOCK_REALTIME = 0x0)
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change

# clock_settime syscall - 32-bit (CLOCK_REALTIME = 0x0)
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change

# Watch for changes to /etc/localtime
-w /etc/localtime -p wa -k time-change
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
