#!/usr/bin/env bash
#===============================================================================
# CIS Control: 6.3.1 - Ensure AIDE is installed
# Profile: Level 1 - Server, Level 1 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="6.3.1"
CONTROL_DESC="Ensure AIDE is installed"

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
    
    # Check if aide is installed
    if dpkg-query -s aide &>/dev/null; then
        log_success "[$CONTROL_ID] aide is installed"
    else
        log_error "[$CONTROL_ID] aide is NOT installed"
        result=1
    fi
    
    # Check if aide-common is installed
    if dpkg-query -s aide-common &>/dev/null; then
        log_success "[$CONTROL_ID] aide-common is installed"
    else
        log_error "[$CONTROL_ID] aide-common is NOT installed"
        result=1
    fi
    
    # Check if AIDE database exists
    if [[ -f /var/lib/aide/aide.db ]] || [[ -f /var/lib/aide/aide.db.gz ]]; then
        log_success "[$CONTROL_ID] AIDE database exists"
    else
        log_warning "[$CONTROL_ID] AIDE database not found - initialization may be required"
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    # Install AIDE
    if ! dpkg-query -s aide &>/dev/null || ! dpkg-query -s aide-common &>/dev/null; then
        log_info "[$CONTROL_ID] Installing AIDE"
        apt-get update -qq
        apt-get install -y -qq aide aide-common
    fi
    
    # Check if AIDE database needs initialization
    if [[ ! -f /var/lib/aide/aide.db ]] && [[ ! -f /var/lib/aide/aide.db.gz ]]; then
        log_info "[$CONTROL_ID] Initializing AIDE database (this may take several minutes)..."
        
        # Initialize AIDE
        if command -v aideinit &>/dev/null; then
            aideinit --yes --force 2>/dev/null || aideinit 2>/dev/null || true
        else
            aide --init 2>/dev/null || true
        fi
        
        # Move new database to active database
        if [[ -f /var/lib/aide/aide.db.new ]]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            log_success "[$CONTROL_ID] AIDE database initialized"
        elif [[ -f /var/lib/aide/aide.db.new.gz ]]; then
            mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
            log_success "[$CONTROL_ID] AIDE database initialized (compressed)"
        else
            log_warning "[$CONTROL_ID] AIDE database may need manual initialization"
            log_warning "[$CONTROL_ID] Run: aideinit && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
        fi
    else
        log_info "[$CONTROL_ID] AIDE database already exists"
    fi
    
    # Set up daily AIDE check via cron (if not already configured)
    local cron_daily="/etc/cron.daily/aide"
    if [[ ! -f "$cron_daily" ]]; then
        log_info "[$CONTROL_ID] Setting up daily AIDE check"
        cat > "$cron_daily" << 'EOF'
#!/bin/bash
# Daily AIDE integrity check
/usr/bin/aide --check --config /etc/aide/aide.conf 2>&1 | /usr/bin/mail -s "AIDE Integrity Check Report - $(hostname)" root
EOF
        chmod 755 "$cron_daily"
        log_success "[$CONTROL_ID] Daily AIDE check configured"
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
