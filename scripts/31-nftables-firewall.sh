#!/usr/bin/env bash
#===============================================================================
# CIS Control: 4.3 - nftables Firewall Configuration
# Profile: Level 1 - Server
# Automated: Yes
# Description: Configures nftables firewall with default deny policy
#===============================================================================

set -euo pipefail

CONTROL_ID="4.3"
CONTROL_DESC="nftables Firewall Configuration"
NFTABLES_CONF="/etc/nftables.conf"

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

# Configurable allowed ports (override with environment variables)
ALLOWED_TCP_PORTS="${ALLOWED_TCP_PORTS:-22}"

#===============================================================================
# Audit Function
#===============================================================================
audit() {
    log_info "[$CONTROL_ID] Auditing: $CONTROL_DESC"
    
    local result=0
    
    # 4.3.1 - Check if nftables is installed
    if ! command -v nft &>/dev/null; then
        log_error "[$CONTROL_ID.1] nftables is not installed"
        return 1
    fi
    log_success "[$CONTROL_ID.1] nftables is installed"
    
    # 4.3.4 - Check if table exists
    if nft list tables 2>/dev/null | grep -q "inet filter"; then
        log_success "[$CONTROL_ID.4] inet filter table exists"
    else
        log_error "[$CONTROL_ID.4] inet filter table does not exist"
        result=1
    fi
    
    # 4.3.5 - Check base chains
    local chains
    chains=$(nft list table inet filter 2>/dev/null || echo "")
    if echo "$chains" | grep -q "chain input"; then
        log_success "[$CONTROL_ID.5] Input chain exists"
    else
        log_error "[$CONTROL_ID.5] Input chain does not exist"
        result=1
    fi
    
    # 4.3.6 - Check loopback configuration
    if echo "$chains" | grep -q 'iif "lo" accept'; then
        log_success "[$CONTROL_ID.6] Loopback traffic is configured"
    else
        log_warning "[$CONTROL_ID.6] Loopback traffic configuration not found"
    fi
    
    # 4.3.8 - Check default policy
    if echo "$chains" | grep -q "policy drop"; then
        log_success "[$CONTROL_ID.8] Default deny policy is set"
    else
        log_error "[$CONTROL_ID.8] Default deny policy is not set"
        result=1
    fi
    
    # 4.3.9 - Check if service is enabled
    local enabled
    enabled=$(systemctl is-enabled nftables 2>/dev/null || echo "disabled")
    if [[ "$enabled" == "enabled" ]]; then
        log_success "[$CONTROL_ID.9] nftables service is enabled"
    else
        log_error "[$CONTROL_ID.9] nftables service is not enabled"
        result=1
    fi
    
    # 4.3.10 - Check if rules are persistent
    if [[ -f "$NFTABLES_CONF" ]]; then
        log_success "[$CONTROL_ID.10] nftables rules are persistent"
    else
        log_error "[$CONTROL_ID.10] nftables rules are not persistent"
        result=1
    fi
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    # 4.3.1 - Install nftables
    if ! command -v nft &>/dev/null; then
        log_info "[$CONTROL_ID] Installing nftables"
        apt-get update -qq
        apt-get install -y -qq nftables
    fi
    
    backup_file "$NFTABLES_CONF"
    
    # Build allowed ports configuration
    local tcp_port_rules=""
    IFS=',' read -ra PORTS <<< "$ALLOWED_TCP_PORTS"
    for port in "${PORTS[@]}"; do
        tcp_port_rules="${tcp_port_rules}        tcp dport ${port} ct state new accept
"
    done
    
    # Create nftables configuration
    cat > "$NFTABLES_CONF" << EOF
#!/usr/sbin/nft -f
# =============================================================================
# CIS nftables Firewall Configuration
# =============================================================================
# Managed by: CIS hardening scripts
# Generated: $(date -Iseconds)
# =============================================================================

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Accept loopback traffic (4.3.6)
        iif "lo" accept
        
        # Drop traffic to localhost not from localhost
        iif != "lo" ip saddr 127.0.0.0/8 drop
        iif != "lo" ip6 saddr ::1 drop
        
        # Accept established connections
        ct state established,related accept
        
        # Drop invalid packets
        ct state invalid drop
        
        # Accept essential ICMP
        ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
        
        # Allowed TCP ports
${tcp_port_rules}
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
    
    chmod 600 "$NFTABLES_CONF"
    
    # Validate configuration
    if nft -c -f "$NFTABLES_CONF"; then
        log_success "[$CONTROL_ID] nftables configuration validated"
    else
        log_error "[$CONTROL_ID] nftables configuration validation failed"
        return 1
    fi
    
    # Apply rules
    nft -f "$NFTABLES_CONF"
    
    # 4.3.9 - Enable service
    systemctl enable nftables
    systemctl start nftables
    
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
            echo ""
            echo "Environment variables:"
            echo "  ALLOWED_TCP_PORTS  Comma-separated list of allowed TCP ports (default: 22)"
            echo ""
            echo "Example:"
            echo "  ALLOWED_TCP_PORTS=22,80,443 $0 --remediate"
            exit 1
            ;;
    esac
}

main "$@"
