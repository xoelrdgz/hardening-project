#!/usr/bin/env bash
#===============================================================================
# CIS Control: 6.1.3.4 - Ensure rsyslog log file creation mode is configured
# Profile: Level 1 - Server, Level 1 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="6.1.3.4"
CONTROL_DESC="Ensure rsyslog log file creation mode is configured"
REQUIRED_MODE="0640"

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
    
    # Check if rsyslog is installed
    if ! command -v rsyslogd &>/dev/null; then
        log_warning "[$CONTROL_ID] rsyslog is not installed"
        return 0
    fi
    
    # Check $FileCreateMode in rsyslog configuration
    local rsyslog_conf="/etc/rsyslog.conf"
    local rsyslog_d="/etc/rsyslog.d"
    local file_create_mode=""
    
    # Check main config file
    if [[ -f "$rsyslog_conf" ]]; then
        file_create_mode=$(grep -E '^\s*\$FileCreateMode' "$rsyslog_conf" | awk '{print $2}' | tail -1 || echo "")
    fi
    
    # Check rsyslog.d directory
    if [[ -d "$rsyslog_d" ]] && [[ -z "$file_create_mode" ]]; then
        for conf_file in "$rsyslog_d"/*.conf; do
            if [[ -f "$conf_file" ]]; then
                local mode
                mode=$(grep -E '^\s*\$FileCreateMode' "$conf_file" | awk '{print $2}' | tail -1 || echo "")
                if [[ -n "$mode" ]]; then
                    file_create_mode="$mode"
                    break
                fi
            fi
        done
    fi
    
    if [[ -z "$file_create_mode" ]]; then
        log_error "[$CONTROL_ID] \$FileCreateMode is not configured"
        result=1
    else
        # Check if mode is 0640 or more restrictive
        local perm_mask=0137
        local mode_decimal=$((8#${file_create_mode}))
        
        if (( (mode_decimal & perm_mask) > 0 )); then
            log_error "[$CONTROL_ID] \$FileCreateMode is set to $file_create_mode (too permissive)"
            result=1
        else
            log_success "[$CONTROL_ID] \$FileCreateMode is correctly set to $file_create_mode"
        fi
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    # Check if rsyslog is installed
    if ! command -v rsyslogd &>/dev/null; then
        log_warning "[$CONTROL_ID] rsyslog is not installed - skipping"
        return 0
    fi
    
    local rsyslog_conf="/etc/rsyslog.d/60-rsyslog.conf"
    
    # Create rsyslog.d directory if it doesn't exist
    mkdir -p /etc/rsyslog.d
    
    # Remove existing $FileCreateMode from all config files
    for conf_file in /etc/rsyslog.conf /etc/rsyslog.d/*.conf; do
        if [[ -f "$conf_file" ]]; then
            if grep -qE '^\s*\$FileCreateMode' "$conf_file"; then
                backup_file "$conf_file"
                sed -i '/^\s*\$FileCreateMode/d' "$conf_file"
                log_info "[$CONTROL_ID] Removed existing \$FileCreateMode from $conf_file"
            fi
        fi
    done
    
    # Add correct $FileCreateMode setting
    log_info "[$CONTROL_ID] Setting \$FileCreateMode to $REQUIRED_MODE"
    echo "" >> "$rsyslog_conf"
    echo "\$FileCreateMode $REQUIRED_MODE" >> "$rsyslog_conf"
    
    # Restart rsyslog to apply changes
    log_info "[$CONTROL_ID] Restarting rsyslog service"
    systemctl reload-or-restart rsyslog 2>/dev/null || true
    
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
