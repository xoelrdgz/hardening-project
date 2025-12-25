#!/usr/bin/env bash
#===============================================================================
# CIS Ubuntu Server 24.04 LTS - nftables Firewall Configuration
# Version: 1.0.0
# Date: 2025-12-25
# Author: xoelrdgz
# Description: Configures nftables firewall for a hardened server
#
# CIS Controls Addressed:
#   - 3.5.1.1: Ensure nftables is installed
#   - 3.5.1.2: Ensure a single firewall configuration utility is in use
#   - 3.5.2.x: nftables specific controls
#===============================================================================

set -euo pipefail

#===============================================================================
# Configuration
#===============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
readonly LOG_FILE="/var/log/cis-hardening/nftables-config.log"
readonly BACKUP_DIR="/var/backups/cis-hardening/nftables"
readonly NFTABLES_CONF="/etc/nftables.conf"

# Default ports (can be customized)
SSH_PORT="${SSH_PORT:-22}"
ALLOWED_TCP_PORTS="${ALLOWED_TCP_PORTS:-$SSH_PORT}"  # Comma-separated
ALLOWED_UDP_PORTS="${ALLOWED_UDP_PORTS:-}"           # Comma-separated

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Options
DRY_RUN=false
ALLOW_ICMP=true
RATE_LIMIT_SSH=true
LOG_DROPPED=true
ENABLE_IPV6=false

#===============================================================================
# Logging Functions
#===============================================================================

setup_logging() {
    local log_dir="$(dirname "$LOG_FILE")"
    mkdir -p "$log_dir"
    mkdir -p "$BACKUP_DIR"
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo ""
    echo "=============================================="
    echo "nftables Configuration - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=============================================="
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[DONE]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_section() {
    echo ""
    echo -e "${CYAN}[====]${NC} $*"
    echo ""
}

#===============================================================================
# Helper Functions
#===============================================================================

show_help() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Configures nftables firewall for a hardened server following CIS benchmarks.

Options:
    --ssh-port PORT       SSH port (default: 22)
    --tcp-ports PORTS     Allowed TCP ports (comma-separated, default: SSH port only)
    --udp-ports PORTS     Allowed UDP ports (comma-separated, default: none)
    --no-icmp             Block all ICMP (default: allow basic ICMP)
    --no-rate-limit       Disable SSH rate limiting
    --no-log              Disable logging of dropped packets
    --enable-ipv6         Enable IPv6 rules (default: IPv6 blocked)
    --dry-run             Show configuration without applying
    --help                Show this help message
    --version             Show version information

Examples:
    $SCRIPT_NAME                                    # Default: SSH only
    $SCRIPT_NAME --ssh-port 2222                    # Custom SSH port
    $SCRIPT_NAME --tcp-ports 22,80,443              # SSH + HTTP + HTTPS
    $SCRIPT_NAME --tcp-ports 22,443 --udp-ports 53  # SSH + HTTPS + DNS

The generated configuration:
    - Drops all incoming traffic by default
    - Allows established/related connections
    - Allows loopback traffic
    - Rate-limits SSH connections (anti-brute-force)
    - Logs dropped packets (optional)
    - Blocks IPv6 by default (can be enabled)

EOF
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_nftables() {
    if ! command -v nft &>/dev/null; then
        log_error "nftables is not installed. Installing..."
        apt-get update -qq
        apt-get install -y nftables
    fi
    log_success "nftables is available"
}

backup_current_config() {
    if [[ -f "$NFTABLES_CONF" ]]; then
        local backup="$BACKUP_DIR/nftables.conf.$(date +%Y%m%d_%H%M%S)"
        cp "$NFTABLES_CONF" "$backup"
        log_info "Backed up current config to: $backup"
    fi
}

disable_ufw() {
    # CIS 3.5.1.2 - Only one firewall should be active
    if command -v ufw &>/dev/null; then
        if ufw status | grep -q "Status: active"; then
            log_info "Disabling UFW (switching to nftables)..."
            ufw disable
            systemctl disable ufw 2>/dev/null || true
            log_success "UFW disabled"
        fi
    fi
}

disable_iptables_services() {
    # Disable iptables services if they exist
    for svc in iptables ip6tables; do
        if systemctl list-unit-files | grep -q "^$svc"; then
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
        fi
    done
}

#===============================================================================
# Configuration Generation
#===============================================================================

generate_nftables_conf() {
    log_section "Generating nftables Configuration"
    
    local conf_content=""
    
    # Header
    conf_content+="#!/usr/sbin/nft -f
#===============================================================================
# nftables Firewall Configuration - Hardened Server
# Generated by: CIS Hardening Scripts
# Date: $(date '+%Y-%m-%d %H:%M:%S')
#
# CIS Ubuntu Server 24.04 LTS Compliant
# Controls: 3.5.1.1, 3.5.2.1-3.5.2.10
#===============================================================================

# Flush existing rules
flush ruleset

"

    # IPv4 Table
    conf_content+="#===============================================================================
# IPv4 Firewall Rules
#===============================================================================
table inet filter {
    
    #---------------------------------------------------------------------------
    # Rate limiting sets
    #---------------------------------------------------------------------------
"

    if [[ "$RATE_LIMIT_SSH" == "true" ]]; then
        conf_content+="    set ssh_limit {
        type ipv4_addr
        size 65535
        flags dynamic,timeout
        timeout 1m
    }
    
"
    fi

    conf_content+="    #---------------------------------------------------------------------------
    # Input Chain - Default DROP
    #---------------------------------------------------------------------------
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow established/related connections (stateful)
        ct state established,related accept
        
        # Drop invalid packets
        ct state invalid drop
        
        # Allow loopback traffic
        iif \"lo\" accept
        
        # Drop traffic to loopback not from loopback
        iif != \"lo\" ip daddr 127.0.0.0/8 drop
"

    if [[ "$ENABLE_IPV6" == "true" ]]; then
        conf_content+="        iif != \"lo\" ip6 daddr ::1 drop
"
    fi

    # ICMP rules
    if [[ "$ALLOW_ICMP" == "true" ]]; then
        conf_content+="
        # Allow essential ICMP (ping, etc.)
        ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded, parameter-problem } accept
"
        if [[ "$ENABLE_IPV6" == "true" ]]; then
            conf_content+="        ip6 nexthdr icmpv6 icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
"
        fi
    fi

    # SSH with rate limiting
    if [[ "$RATE_LIMIT_SSH" == "true" ]]; then
        conf_content+="
        # SSH with rate limiting (anti-brute-force)
        # Limit: 4 new connections per minute per source IP
        tcp dport $SSH_PORT ct state new add @ssh_limit { ip saddr limit rate 4/minute burst 8 packets } accept
        tcp dport $SSH_PORT ct state new drop
"
    else
        conf_content+="
        # SSH access
        tcp dport $SSH_PORT accept
"
    fi

    # Additional TCP ports
    if [[ -n "$ALLOWED_TCP_PORTS" ]]; then
        local tcp_ports="${ALLOWED_TCP_PORTS//,/ }"
        # Remove SSH port from additional ports (already handled)
        local other_tcp=""
        for port in $tcp_ports; do
            if [[ "$port" != "$SSH_PORT" ]]; then
                other_tcp+="$port, "
            fi
        done
        if [[ -n "$other_tcp" ]]; then
            other_tcp="${other_tcp%, }"  # Remove trailing comma
            conf_content+="
        # Additional allowed TCP ports
        tcp dport { $other_tcp } accept
"
        fi
    fi

    # UDP ports
    if [[ -n "$ALLOWED_UDP_PORTS" ]]; then
        local udp_ports="${ALLOWED_UDP_PORTS//,/, }"
        conf_content+="
        # Allowed UDP ports
        udp dport { $udp_ports } accept
"
    fi

    # Logging
    if [[ "$LOG_DROPPED" == "true" ]]; then
        conf_content+="
        # Log dropped packets (rate limited)
        limit rate 5/minute burst 10 packets log prefix \"nftables-dropped-input: \" level info
"
    fi

    conf_content+="
        # Default: drop everything else
        counter drop
    }
    
    #---------------------------------------------------------------------------
    # Forward Chain - Default DROP (not a router)
    #---------------------------------------------------------------------------
    chain forward {
        type filter hook forward priority 0; policy drop;
        
        # Log forwarded packets (should be none on a server)
"
    if [[ "$LOG_DROPPED" == "true" ]]; then
        conf_content+="        limit rate 1/minute log prefix \"nftables-forward: \" level warn
"
    fi
    conf_content+="        counter drop
    }
    
    #---------------------------------------------------------------------------
    # Output Chain - Default ACCEPT (restrict if needed)
    #---------------------------------------------------------------------------
    chain output {
        type filter hook output priority 0; policy accept;
        
        # Allow all outbound traffic from this server
        # For stricter security, change policy to drop and whitelist
        counter accept
    }
}

"

    # IPv6 handling
    if [[ "$ENABLE_IPV6" != "true" ]]; then
        conf_content+="#===============================================================================
# IPv6 Firewall Rules - DROP ALL
# IPv6 is disabled for security. Enable with --enable-ipv6 if needed.
#===============================================================================
table ip6 filter {
    chain input {
        type filter hook input priority 0; policy drop;
        counter drop
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
        counter drop
    }
    
    chain output {
        type filter hook output priority 0; policy drop;
        counter drop
    }
}
"
    fi

    echo "$conf_content"
}

#===============================================================================
# Application
#===============================================================================

apply_configuration() {
    log_section "Applying nftables Configuration"
    
    # Generate configuration
    local config
    config=$(generate_nftables_conf)
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would write the following configuration to $NFTABLES_CONF:"
        echo ""
        echo "$config"
        echo ""
        return 0
    fi
    
    # Backup current config
    backup_current_config
    
    # Disable other firewalls
    disable_ufw
    disable_iptables_services
    
    # Write new configuration
    echo "$config" > "$NFTABLES_CONF"
    chmod 600 "$NFTABLES_CONF"
    log_success "Configuration written to $NFTABLES_CONF"
    
    # Validate configuration
    log_info "Validating configuration..."
    if nft -c -f "$NFTABLES_CONF"; then
        log_success "Configuration syntax is valid"
    else
        log_error "Configuration validation failed!"
        exit 1
    fi
    
    # Apply configuration
    log_info "Applying firewall rules..."
    nft -f "$NFTABLES_CONF"
    log_success "Firewall rules applied"
    
    # Enable nftables service
    systemctl enable nftables
    systemctl restart nftables
    log_success "nftables service enabled and started"
}

show_status() {
    log_section "Current nftables Status"
    
    echo "Active ruleset:"
    echo ""
    nft list ruleset
    echo ""
    
    echo "Service status:"
    systemctl status nftables --no-pager || true
}

#===============================================================================
# Main Execution
#===============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ssh-port)
                SSH_PORT="$2"
                if [[ ! "$SSH_PORT" =~ ^[0-9]+$ ]]; then
                    log_error "Invalid SSH port: $SSH_PORT"
                    exit 1
                fi
                shift 2
                ;;
            --tcp-ports)
                ALLOWED_TCP_PORTS="$2"
                shift 2
                ;;
            --udp-ports)
                ALLOWED_UDP_PORTS="$2"
                shift 2
                ;;
            --no-icmp)
                ALLOW_ICMP=false
                shift
                ;;
            --no-rate-limit)
                RATE_LIMIT_SSH=false
                shift
                ;;
            --no-log)
                LOG_DROPPED=false
                shift
                ;;
            --enable-ipv6)
                ENABLE_IPV6=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --version|-v)
                echo "$SCRIPT_NAME version $SCRIPT_VERSION"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Setup
    check_root
    setup_logging
    
    log_info "Configuration Summary:"
    log_info "  SSH Port:         $SSH_PORT"
    log_info "  TCP Ports:        ${ALLOWED_TCP_PORTS:-none}"
    log_info "  UDP Ports:        ${ALLOWED_UDP_PORTS:-none}"
    log_info "  ICMP:             $(if $ALLOW_ICMP; then echo 'Allowed'; else echo 'Blocked'; fi)"
    log_info "  SSH Rate Limit:   $(if $RATE_LIMIT_SSH; then echo 'Enabled'; else echo 'Disabled'; fi)"
    log_info "  Log Dropped:      $(if $LOG_DROPPED; then echo 'Yes'; else echo 'No'; fi)"
    log_info "  IPv6:             $(if $ENABLE_IPV6; then echo 'Enabled'; else echo 'Blocked'; fi)"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_warning "DRY RUN MODE - No changes will be made"
    fi
    
    # Check and apply
    check_nftables
    apply_configuration
    
    if [[ "$DRY_RUN" != "true" ]]; then
        show_status
    fi
    
    # Summary
    echo ""
    echo "==============================================================================="
    log_success "nftables firewall configured successfully"
    echo "==============================================================================="
    echo ""
    echo "Allowed Inbound:"
    echo "  - Established/related connections"
    echo "  - Loopback traffic"
    [[ "$ALLOW_ICMP" == "true" ]] && echo "  - ICMP ping and network diagnostics"
    echo "  - SSH on port $SSH_PORT$(if $RATE_LIMIT_SSH; then echo ' (rate limited)'; fi)"
    if [[ -n "$ALLOWED_TCP_PORTS" ]] && [[ "$ALLOWED_TCP_PORTS" != "$SSH_PORT" ]]; then
        echo "  - Additional TCP: ${ALLOWED_TCP_PORTS//,/, }"
    fi
    [[ -n "$ALLOWED_UDP_PORTS" ]] && echo "  - UDP: ${ALLOWED_UDP_PORTS//,/, }"
    echo ""
    echo "Blocked:"
    echo "  - All other inbound traffic"
    echo "  - All forwarding traffic"
    [[ "$ENABLE_IPV6" != "true" ]] && echo "  - All IPv6 traffic"
    echo ""
    echo "Log file: $LOG_FILE"
    echo "Config file: $NFTABLES_CONF"
    echo ""
}

main "$@"

