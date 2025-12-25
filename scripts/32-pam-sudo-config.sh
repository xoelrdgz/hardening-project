#!/usr/bin/env bash
#===============================================================================
# CIS Control: 5.2/5.3 - PAM and Sudo Configuration
# Profile: Level 1 - Server
# Automated: Yes
# Description: Configures PAM password policies and sudo hardening
#===============================================================================

set -euo pipefail

CONTROL_ID="5.2/5.3"
CONTROL_DESC="PAM and Sudo Configuration"

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

# Configurable values
MIN_PASSWORD_LENGTH="${MIN_PASSWORD_LENGTH:-14}"
PASSWORD_REMEMBER="${PASSWORD_REMEMBER:-5}"
FAILLOCK_DENY="${FAILLOCK_DENY:-5}"
FAILLOCK_UNLOCK_TIME="${FAILLOCK_UNLOCK_TIME:-900}"

#===============================================================================
# Audit Function
#===============================================================================
audit() {
    log_info "[$CONTROL_ID] Auditing: $CONTROL_DESC"
    
    local result=0
    
    # 5.2.2 - Check sudo pty
    if grep -rq "Defaults.*use_pty" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        log_success "[5.2.2] Sudo commands use pty"
    else
        log_error "[5.2.2] Sudo commands do not use pty"
        result=1
    fi
    
    # 5.2.4 - Check for NOPASSWD
    if grep -rE "^\s*[^#].*NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        log_warning "[5.2.4] NOPASSWD entries found in sudoers"
    else
        log_success "[5.2.4] No NOPASSWD entries in sudoers"
    fi
    
    # 5.3.3.2.2 - Check minimum password length
    if [[ -f /etc/security/pwquality.conf ]]; then
        local minlen
        minlen=$(grep "^minlen" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
        if [[ -n "$minlen" ]] && [[ "$minlen" -ge 14 ]]; then
            log_success "[5.3.3.2.2] Minimum password length = $minlen"
        else
            log_error "[5.3.3.2.2] Minimum password length = ${minlen:-not set} (should be >= 14)"
            result=1
        fi
    else
        log_error "[5.3.3.2.2] pwquality.conf not found"
        result=1
    fi
    
    # 5.3.3.3.1 - Check password history
    if grep -q "pam_pwhistory.so" /etc/pam.d/common-password 2>/dev/null; then
        log_success "[5.3.3.3.1] Password history is configured"
    else
        log_error "[5.3.3.3.1] Password history is not configured"
        result=1
    fi
    
    # 5.4.1.1 - Check password expiration
    local pass_max
    pass_max=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [[ -n "$pass_max" ]] && [[ "$pass_max" -le 365 ]]; then
        log_success "[5.4.1.1] PASS_MAX_DAYS = $pass_max"
    else
        log_warning "[5.4.1.1] PASS_MAX_DAYS = ${pass_max:-not set}"
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    # Install required packages
    apt-get install -y -qq libpam-pwquality
    
    # 5.2.2 - Configure sudo to use pty
    log_info "[5.2.2] Configuring sudo to use pty"
    mkdir -p /etc/sudoers.d
    echo 'Defaults use_pty' > /etc/sudoers.d/cis-hardening
    echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers.d/cis-hardening
    chmod 440 /etc/sudoers.d/cis-hardening
    
    # Validate sudoers
    if ! visudo -cf /etc/sudoers.d/cis-hardening; then
        log_error "[5.2.2] Invalid sudoers configuration"
        rm -f /etc/sudoers.d/cis-hardening
        return 1
    fi
    
    # 5.3.3.2.2/5.3.3.2.3 - Configure password quality
    log_info "[5.3.3.2.x] Configuring password quality"
    backup_file /etc/security/pwquality.conf
    
    cat > /etc/security/pwquality.conf << EOF
# CIS Password Quality Configuration
minlen = ${MIN_PASSWORD_LENGTH}
minclass = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
retry = 3
EOF
    
    # 5.3.3.3.1 - Configure password history
    log_info "[5.3.3.3.1] Configuring password history"
    backup_file /etc/pam.d/common-password
    
    if ! grep -q "pam_pwhistory.so" /etc/pam.d/common-password; then
        sed -i "/pam_unix.so/i password required pam_pwhistory.so remember=${PASSWORD_REMEMBER} use_authtok" /etc/pam.d/common-password
    fi
    
    # 5.4.1.1 - Configure password expiration in login.defs
    log_info "[5.4.1.1] Configuring password expiration"
    backup_file /etc/login.defs
    
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
    
    log_success "[$CONTROL_ID] Remediation complete"
    
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
