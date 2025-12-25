#!/usr/bin/env bash
#===============================================================================
# CIS Control: 6.2.3.8 - Ensure events that modify user/group information are collected
# Profile: Level 2 - Server, Level 2 - Workstation
# Automated: Yes
#===============================================================================

set -euo pipefail

CONTROL_ID="6.2.3.8"
CONTROL_DESC="Ensure events that modify user/group information are collected"

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
    
    # Files to monitor
    local identity_files=(
        "/etc/group"
        "/etc/passwd"
        "/etc/gshadow"
        "/etc/shadow"
        "/etc/security/opasswd"
        "/etc/nsswitch.conf"
        "/etc/pam.conf"
        "/etc/pam.d"
    )
    
    # Check disk rules
    if [[ -d "$rules_dir" ]]; then
        local missing_files=""
        
        for identity_file in "${identity_files[@]}"; do
            if ! grep -rh -- "$identity_file" "$rules_dir"/*.rules 2>/dev/null | grep -q "identity"; then
                missing_files+="$identity_file "
            fi
        done
        
        if [[ -z "$missing_files" ]]; then
            log_success "[$CONTROL_ID] All identity file audit rules found in disk config"
        else
            log_error "[$CONTROL_ID] Missing audit rules for: $missing_files"
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
        
        if echo "$running_rules" | grep -q "identity"; then
            log_success "[$CONTROL_ID] Identity audit rules loaded in running config"
        else
            log_warning "[$CONTROL_ID] Identity audit rules may not be loaded in running config"
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
    local rules_file="$rules_dir/50-identity.rules"
    
    # Create rules directory if needed
    mkdir -p "$rules_dir"
    
    # Backup existing rules file
    backup_file "$rules_file"
    
    # Create audit rules for identity files
    log_info "[$CONTROL_ID] Creating identity audit rules"
    cat > "$rules_file" << 'EOF'
## CIS Control 6.2.3.8 - Audit user/group modification events

# Monitor system group file
-w /etc/group -p wa -k identity

# Monitor system user file
-w /etc/passwd -p wa -k identity

# Monitor encrypted group passwords
-w /etc/gshadow -p wa -k identity

# Monitor encrypted user passwords
-w /etc/shadow -p wa -k identity

# Monitor old password storage (PAM)
-w /etc/security/opasswd -p wa -k identity

# Monitor NSS configuration
-w /etc/nsswitch.conf -p wa -k identity

# Monitor PAM configuration file
-w /etc/pam.conf -p wa -k identity

# Monitor PAM configuration directory
-w /etc/pam.d -p wa -k identity
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
