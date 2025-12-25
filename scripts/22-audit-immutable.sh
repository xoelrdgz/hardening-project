#!/usr/bin/env bash
#===============================================================================
# CIS Control: 6.2.3.20 - Ensure the audit configuration is immutable
# Profile: Level 2 - Server, Level 2 - Workstation
# Automated: Yes
#
# CRITICAL OPERATIONAL WARNING:
# ============================================================================
# Setting audit to immutable mode (-e 2) means:
#   1. NO audit rule changes possible without a REBOOT
#   2. If rules generate excessive noise, you CANNOT fix it hot
#   3. Disk saturation from audit logs could become unrecoverable
#
# PREREQUISITES BEFORE ENABLING IMMUTABLE MODE:
#   1. Test ALL audit rules in a staging environment for at least 24-48 hours
#   2. Monitor disk space usage under realistic workloads
#   3. Ensure log rotation is properly configured
#   4. Verify max_log_file and num_logs in /etc/audit/auditd.conf
#   5. Have a tested recovery procedure ready
#
# SAFE MODE:
#   Set AUDIT_IMMUTABLE_SAFE_MODE=1 to only audit (never remediate)
#   Set AUDIT_IMMUTABLE_FORCE=1 to bypass safety checks (dangerous!)
#
# ROLLBACK:
#   Immutable mode can only be disabled via system reboot
#   Remove -e 2 from /etc/audit/rules.d/99-finalize.rules, then reboot
#===============================================================================

set -euo pipefail

CONTROL_ID="6.2.3.20"
CONTROL_DESC="Ensure the audit configuration is immutable"

# Safety controls
AUDIT_IMMUTABLE_SAFE_MODE="${AUDIT_IMMUTABLE_SAFE_MODE:-0}"
AUDIT_IMMUTABLE_FORCE="${AUDIT_IMMUTABLE_FORCE:-0}"

# Minimum free disk percentage required before enabling immutable mode
MIN_DISK_FREE_PERCENT="${MIN_DISK_FREE_PERCENT:-20}"

# Minimum uptime in hours to consider rules "tested"
MIN_UPTIME_HOURS="${MIN_UPTIME_HOURS:-24}"

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
# Safety Check Functions
#===============================================================================
check_disk_space() {
    local audit_log_dir="/var/log/audit"
    local partition
    local free_percent
    
    if [[ -d "$audit_log_dir" ]]; then
        partition=$(df "$audit_log_dir" | tail -1 | awk '{print $6}')
        free_percent=$(df "$audit_log_dir" | tail -1 | awk '{print 100 - $5}' | tr -d '%')
    else
        partition="/"
        free_percent=$(df "/" | tail -1 | awk '{print 100 - $5}' | tr -d '%')
    fi
    
    if [[ "$free_percent" -lt "$MIN_DISK_FREE_PERCENT" ]]; then
        log_error "[$CONTROL_ID] Insufficient disk space on $partition"
        log_error "[$CONTROL_ID] Free: ${free_percent}% | Required: ${MIN_DISK_FREE_PERCENT}%"
        log_error "[$CONTROL_ID] Risk: Audit logs could fill disk with no way to modify rules"
        return 1
    fi
    
    log_info "[$CONTROL_ID] Disk space check passed: ${free_percent}% free on $partition"
    return 0
}

check_log_rotation() {
    local auditd_conf="/etc/audit/auditd.conf"
    
    if [[ ! -f "$auditd_conf" ]]; then
        log_warning "[$CONTROL_ID] auditd.conf not found - cannot verify log rotation"
        return 1
    fi
    
    local max_log_file
    local num_logs
    local max_log_file_action
    
    max_log_file=$(grep -Pi '^\s*max_log_file\s*=' "$auditd_conf" | awk -F= '{print $2}' | tr -d ' ' || echo "0")
    num_logs=$(grep -Pi '^\s*num_logs\s*=' "$auditd_conf" | awk -F= '{print $2}' | tr -d ' ' || echo "0")
    max_log_file_action=$(grep -Pi '^\s*max_log_file_action\s*=' "$auditd_conf" | awk -F= '{print $2}' | tr -d ' ' || echo "")
    
    if [[ "$max_log_file_action" != "rotate" ]] && [[ "$max_log_file_action" != "ROTATE" ]]; then
        log_warning "[$CONTROL_ID] max_log_file_action is '$max_log_file_action' (should be 'rotate')"
        log_warning "[$CONTROL_ID] Risk: Logs may not rotate properly, causing disk exhaustion"
        return 1
    fi
    
    log_info "[$CONTROL_ID] Log rotation check passed: max_log_file=$max_log_file, num_logs=$num_logs"
    return 0
}

check_uptime() {
    local uptime_seconds
    local uptime_hours
    
    uptime_seconds=$(awk '{print int($1)}' /proc/uptime)
    uptime_hours=$((uptime_seconds / 3600))
    
    if [[ "$uptime_hours" -lt "$MIN_UPTIME_HOURS" ]]; then
        log_warning "[$CONTROL_ID] System uptime: ${uptime_hours}h (recommended: ${MIN_UPTIME_HOURS}h+)"
        log_warning "[$CONTROL_ID] Audit rules should be tested before enabling immutable mode"
        return 1
    fi
    
    log_info "[$CONTROL_ID] Uptime check passed: ${uptime_hours} hours"
    return 0
}

check_audit_rules_loaded() {
    if ! command -v auditctl &>/dev/null; then
        log_error "[$CONTROL_ID] auditctl not found - auditd may not be installed"
        return 1
    fi
    
    local rule_count
    rule_count=$(auditctl -l 2>/dev/null | grep -v "^No rules" | wc -l || echo "0")
    
    if [[ "$rule_count" -lt 5 ]]; then
        log_warning "[$CONTROL_ID] Only $rule_count audit rules loaded"
        log_warning "[$CONTROL_ID] Ensure all required rules are configured before enabling immutable mode"
        return 1
    fi
    
    log_info "[$CONTROL_ID] Audit rules check passed: $rule_count rules loaded"
    return 0
}

run_safety_checks() {
    local failed=0
    
    log_info "[$CONTROL_ID] Running pre-immutable safety checks..."
    log_info "[$CONTROL_ID] ================================================"
    
    check_disk_space || failed=$((failed + 1))
    check_log_rotation || failed=$((failed + 1))
    check_uptime || failed=$((failed + 1))
    check_audit_rules_loaded || failed=$((failed + 1))
    
    log_info "[$CONTROL_ID] ================================================"
    
    if [[ "$failed" -gt 0 ]]; then
        log_error "[$CONTROL_ID] $failed safety check(s) failed"
        return 1
    fi
    
    log_success "[$CONTROL_ID] All safety checks passed"
    return 0
}

#===============================================================================
# Audit Function
#===============================================================================
audit() {
    log_info "[$CONTROL_ID] Auditing: $CONTROL_DESC"
    
    local result=0
    local rules_dir="/etc/audit/rules.d"
    
    # Check disk rules for -e 2
    if [[ -d "$rules_dir" ]]; then
        local immutable_rule
        immutable_rule=$(grep -Ph -- '^\h*-e\h+2\b' "$rules_dir"/*.rules 2>/dev/null | tail -1 || echo "")
        
        if [[ -n "$immutable_rule" ]]; then
            log_success "[$CONTROL_ID] Audit immutable flag (-e 2) found in disk config"
        else
            log_error "[$CONTROL_ID] Audit immutable flag (-e 2) not found in disk config"
            result=1
        fi
    else
        log_error "[$CONTROL_ID] Audit rules directory not found: $rules_dir"
        result=1
    fi
    
    # Check running configuration
    if command -v auditctl &>/dev/null; then
        local audit_status
        audit_status=$(auditctl -s 2>/dev/null | grep "enabled" || echo "")
        
        if echo "$audit_status" | grep -q "enabled.*2"; then
            log_success "[$CONTROL_ID] Audit is running in immutable mode"
        elif echo "$audit_status" | grep -q "enabled.*1"; then
            log_warning "[$CONTROL_ID] Audit is enabled but not in immutable mode (reboot may be required)"
        else
            log_warning "[$CONTROL_ID] Could not determine audit status"
        fi
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    #---------------------------------------------------------------------------
    # Safe Mode Check
    #---------------------------------------------------------------------------
    if [[ "$AUDIT_IMMUTABLE_SAFE_MODE" == "1" ]]; then
        log_warning "[$CONTROL_ID] SAFE MODE ENABLED - audit only, no changes will be made"
        log_warning "[$CONTROL_ID] Set AUDIT_IMMUTABLE_SAFE_MODE=0 to allow remediation"
        audit
        return 0
    fi
    
    #---------------------------------------------------------------------------
    # Safety Checks (unless forced)
    #---------------------------------------------------------------------------
    if [[ "$AUDIT_IMMUTABLE_FORCE" != "1" ]]; then
        if ! run_safety_checks; then
            log_error "[$CONTROL_ID] "
            log_error "[$CONTROL_ID] =========================================="
            log_error "[$CONTROL_ID] REMEDIATION BLOCKED - SAFETY CHECKS FAILED"
            log_error "[$CONTROL_ID] =========================================="
            log_error "[$CONTROL_ID] "
            log_error "[$CONTROL_ID] Enabling immutable mode with failed safety checks"
            log_error "[$CONTROL_ID] could result in an unrecoverable system state."
            log_error "[$CONTROL_ID] "
            log_error "[$CONTROL_ID] Options:"
            log_error "[$CONTROL_ID]   1. Fix the issues identified above"
            log_error "[$CONTROL_ID]   2. Set AUDIT_IMMUTABLE_FORCE=1 to bypass (DANGEROUS)"
            log_error "[$CONTROL_ID] "
            log_error "[$CONTROL_ID] If disk fills with audit logs in immutable mode,"
            log_error "[$CONTROL_ID] the only recovery is a reboot (potentially from rescue media)."
            return 1
        fi
    else
        log_warning "[$CONTROL_ID] AUDIT_IMMUTABLE_FORCE=1 - Bypassing safety checks"
        log_warning "[$CONTROL_ID] You have been warned!"
    fi
    
    #---------------------------------------------------------------------------
    # Check if already in immutable mode
    #---------------------------------------------------------------------------
    if command -v auditctl &>/dev/null; then
        if auditctl -s 2>/dev/null | grep -q "enabled.*2"; then
            log_info "[$CONTROL_ID] Audit is already in immutable mode"
            return 0
        fi
    fi
    
    #---------------------------------------------------------------------------
    # Apply immutable configuration
    #---------------------------------------------------------------------------
    local rules_dir="/etc/audit/rules.d"
    local rules_file="$rules_dir/99-finalize.rules"
    
    # Create rules directory if needed
    mkdir -p "$rules_dir"
    
    # Backup existing rules file
    backup_file "$rules_file"
    
    # Create finalize rules file
    log_info "[$CONTROL_ID] Setting audit configuration to immutable"
    cat > "$rules_file" << 'EOF'
## CIS Control 6.2.3.20 - Make audit configuration immutable
## This MUST be the last rule in the audit configuration
## ========================================================================
## WARNING: Once enabled, audit rules CANNOT be modified without a reboot!
## ========================================================================
##
## To disable immutable mode:
##   1. Remove or comment out the -e 2 line below
##   2. Reboot the system
##
## Configured: $(date -Iseconds)

# Lock down audit configuration
-e 2
EOF
    
    # Set proper permissions
    chmod 640 "$rules_file"
    
    # Load the rules
    log_info "[$CONTROL_ID] Loading audit rules"
    if command -v augenrules &>/dev/null; then
        augenrules --load 2>/dev/null || true
    fi
    
    log_success "[$CONTROL_ID] Remediation complete"
    log_warning "[$CONTROL_ID] "
    log_warning "[$CONTROL_ID] =============================================="
    log_warning "[$CONTROL_ID] IMPORTANT: IMMUTABLE MODE CONFIGURATION ADDED"
    log_warning "[$CONTROL_ID] =============================================="
    log_warning "[$CONTROL_ID] "
    log_warning "[$CONTROL_ID] A system REBOOT is required to activate immutable mode."
    log_warning "[$CONTROL_ID] Once active, audit rules CANNOT be changed without rebooting."
    log_warning "[$CONTROL_ID] "
    log_warning "[$CONTROL_ID] To abort before reboot:"
    log_warning "[$CONTROL_ID]   rm $rules_file"
    log_warning "[$CONTROL_ID]   augenrules --load"
    
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
        --check-safety)
            run_safety_checks
            ;;
        *)
            echo "Usage: $0 {--audit|--remediate|--check-safety}"
            echo ""
            echo "Environment variables:"
            echo "  AUDIT_IMMUTABLE_SAFE_MODE=1  Audit only, never apply changes"
            echo "  AUDIT_IMMUTABLE_FORCE=1      Bypass safety checks (dangerous!)"
            echo "  MIN_DISK_FREE_PERCENT=N      Minimum free disk % (default: 20)"
            echo "  MIN_UPTIME_HOURS=N           Minimum uptime hours (default: 24)"
            exit 1
            ;;
    esac
}

main "$@"
