#!/usr/bin/env bash
#===============================================================================
# CIS Control: 5.1 - SSH Server Hardening
# Profile: Level 1 - Server
# Automated: Yes
# Description: Configures SSH server according to CIS benchmarks
#===============================================================================

set -euo pipefail

CONTROL_ID="5.1"
CONTROL_DESC="SSH Server Hardening"
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CIS_CONFIG="/etc/ssh/sshd_config.d/50-cis-hardening.conf"

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

# CIS recommended values
declare -A SSH_SETTINGS=(
    ["MaxAuthTries"]="3"
    ["ClientAliveInterval"]="300"
    ["ClientAliveCountMax"]="3"
    ["PermitRootLogin"]="no"
    ["PermitEmptyPasswords"]="no"
    ["X11Forwarding"]="no"
    ["HostbasedAuthentication"]="no"
    ["IgnoreRhosts"]="yes"
    ["LoginGraceTime"]="60"
    ["MaxSessions"]="10"
    ["LogLevel"]="VERBOSE"
    ["AllowTcpForwarding"]="no"
)

#===============================================================================
# Audit Function
#===============================================================================
audit() {
    log_info "[$CONTROL_ID] Auditing: $CONTROL_DESC"
    
    local result=0
    
    if [[ ! -f "$SSHD_CONFIG" ]]; then
        log_error "[$CONTROL_ID] SSH server not installed"
        return 1
    fi
    
    for setting in "${!SSH_SETTINGS[@]}"; do
        local expected="${SSH_SETTINGS[$setting]}"
        local current
        current=$(sshd -T 2>/dev/null | grep -i "^$setting " | awk '{print $2}' || echo "")
        
        if [[ "${current,,}" == "${expected,,}" ]]; then
            log_success "[$CONTROL_ID] $setting = $current"
        else
            log_error "[$CONTROL_ID] $setting = '$current' (expected: $expected)"
            result=1
        fi
    done
    
    # Check ciphers (5.1.12)
    local ciphers
    ciphers=$(sshd -T 2>/dev/null | grep "^ciphers " | cut -d' ' -f2- || echo "")
    if echo "$ciphers" | grep -qE "3des|arcfour|blowfish|cast128|des"; then
        log_error "[$CONTROL_ID] Weak ciphers detected: $ciphers"
        result=1
    else
        log_success "[$CONTROL_ID] Ciphers are strong"
    fi
    
    # Check MACs (5.1.15)
    local macs
    macs=$(sshd -T 2>/dev/null | grep "^macs " | cut -d' ' -f2- || echo "")
    if echo "$macs" | grep -qE "md5|96"; then
        log_error "[$CONTROL_ID] Weak MACs detected: $macs"
        result=1
    else
        log_success "[$CONTROL_ID] MACs are strong"
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    if [[ ! -f "$SSHD_CONFIG" ]]; then
        log_error "[$CONTROL_ID] SSH server not installed"
        return 1
    fi
    
    mkdir -p /etc/ssh/sshd_config.d
    
    backup_file "$SSHD_CIS_CONFIG"
    
    cat > "$SSHD_CIS_CONFIG" << 'EOF'
# =============================================================================
# CIS SSH Server Hardening Configuration
# =============================================================================
# Managed by: CIS hardening scripts
# Controls: 5.1.6, 5.1.7, 5.1.12, 5.1.15, 5.1.20
# =============================================================================

# 5.1.6 - Maximum authentication attempts
MaxAuthTries 3

# 5.1.7 - Session timeout
ClientAliveInterval 300
ClientAliveCountMax 3

# 5.1.12 - Strong ciphers only
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# 5.1.15 - Strong MACs only
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Key exchange algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

# 5.1.20 - Root login
PermitRootLogin no

# Additional hardening
X11Forwarding no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
LoginGraceTime 60
MaxSessions 10
LogLevel VERBOSE
AllowTcpForwarding no
AllowAgentForwarding no
Banner /etc/issue.net
EOF
    
    chmod 600 "$SSHD_CIS_CONFIG"
    
    # Validate configuration
    if sshd -t 2>/dev/null; then
        log_success "[$CONTROL_ID] SSH configuration validated"
    else
        log_error "[$CONTROL_ID] SSH configuration validation failed"
        return 1
    fi
    
    # Restart SSH
    log_info "[$CONTROL_ID] Restarting SSH service"
    systemctl restart ssh 2>/dev/null || systemctl restart sshd
    
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
