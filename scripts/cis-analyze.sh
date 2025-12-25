#!/usr/bin/env bash
#===============================================================================
# CIS Ubuntu Server 24.04 LTS - System Security Analysis Script
# Version: 2.0.0
# Date: 2025-12-25
# Author: xoelrdgz
# Description: Comprehensive security analysis including CIS controls and Lynis
#===============================================================================

set -euo pipefail

#===============================================================================
# Configuration
#===============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="2.0.0"

# Default output directory (can be overridden with --output)
OUTPUT_DIR=""
PHASE=""
RUN_LYNIS=true
LYNIS_AUDIT_ONLY=false

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

#===============================================================================
# Logging Functions
#===============================================================================

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
    echo -e "${CYAN}[====]${NC} $*"
}

#===============================================================================
# Helper Functions
#===============================================================================

show_help() {
    cat << EOF
Usage: $SCRIPT_NAME --phase <initial|post> [OPTIONS]

Comprehensive security analysis for CIS hardening with Lynis integration.

Required:
    --phase <initial|post>    Analysis phase (initial = pre-hardening, post = post-hardening)

Options:
    --output <directory>      Output directory (default: initial_logs or hardening_logs)
    --skip-lynis              Skip Lynis audit (faster, less comprehensive)
    --lynis-quick             Run Lynis in quick mode
    --help                    Show this help message
    --version                 Show version information

Examples:
    $SCRIPT_NAME --phase initial
    $SCRIPT_NAME --phase post
    $SCRIPT_NAME --phase initial --output /tmp/my_logs
    $SCRIPT_NAME --phase post --skip-lynis

Output Files:
    01_system_info.txt        System identification and resources
    02_network_config.txt     Network interfaces and routing
    03_open_ports.txt         Listening ports and services
    04_firewall_status.txt    UFW/nftables configuration
    05_kernel_params.txt      Security-relevant sysctl parameters
    06_kernel_modules.txt     Loaded and blacklisted modules
    07_filesystem_mounts.txt  Mount options and partitions
    08_apparmor_status.txt    AppArmor profiles and status
    09_users_groups.txt       User accounts and groups
    10_password_policy.txt    Password and authentication settings
    11_ssh_config.txt         SSH server configuration
    12_services.txt           Systemd services status
    13_auditd_status.txt      Audit daemon configuration
    14_logging_config.txt     Rsyslog and journal settings
    15_file_permissions.txt   Critical file permissions
    16_cis_controls.txt       CIS control compliance status
    17_lynis_report.txt       Lynis security audit results
    18_security_tools.txt     Security tools status

EOF
}

show_version() {
    echo "$SCRIPT_NAME version $SCRIPT_VERSION"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

create_output_dir() {
    mkdir -p "$OUTPUT_DIR"
    chmod 700 "$OUTPUT_DIR"
    log_info "Output directory: $OUTPUT_DIR"
}

write_header() {
    local file="$1"
    local title="$2"
    cat > "$file" << EOF
================================================================================
$title
================================================================================
Generated: $(date '+%Y-%m-%d %H:%M:%S')
Phase: $PHASE
Hostname: $(hostname)
================================================================================

EOF
}

append_section() {
    local file="$1"
    local section="$2"
    echo "" >> "$file"
    echo "=== $section ===" >> "$file"
}

#===============================================================================
# Collection Functions
#===============================================================================

collect_system_info() {
    local file="$OUTPUT_DIR/01_system_info.txt"
    log_info "Collecting system information..."
    
    write_header "$file" "SYSTEM INFORMATION"
    
    append_section "$file" "HOST IDENTIFICATION"
    hostnamectl >> "$file" 2>/dev/null || echo "hostnamectl not available" >> "$file"
    
    append_section "$file" "OPERATING SYSTEM"
    cat /etc/os-release >> "$file" 2>/dev/null || true
    
    append_section "$file" "KERNEL VERSION"
    uname -a >> "$file"
    
    append_section "$file" "UPTIME AND LOAD"
    uptime >> "$file"
    
    append_section "$file" "MEMORY"
    free -h >> "$file"
    
    append_section "$file" "DISK USAGE"
    df -h >> "$file"
    
    append_section "$file" "CPU INFO"
    lscpu | grep -E "^(Architecture|CPU\(s\)|Model name|Vendor)" >> "$file" 2>/dev/null || true
    
    log_success "System information collected"
}

collect_network_config() {
    local file="$OUTPUT_DIR/02_network_config.txt"
    log_info "Collecting network configuration..."
    
    write_header "$file" "NETWORK CONFIGURATION"
    
    append_section "$file" "NETWORK INTERFACES"
    ip -4 addr show >> "$file" 2>/dev/null || ifconfig >> "$file" 2>/dev/null || true
    
    append_section "$file" "IPV6 INTERFACES"
    ip -6 addr show >> "$file" 2>/dev/null || true
    
    append_section "$file" "ROUTING TABLE"
    ip route show >> "$file" 2>/dev/null || route -n >> "$file" 2>/dev/null || true
    
    append_section "$file" "DNS CONFIGURATION"
    cat /etc/resolv.conf >> "$file" 2>/dev/null || true
    
    append_section "$file" "HOSTS FILE"
    cat /etc/hosts >> "$file" 2>/dev/null || true
    
    log_success "Network configuration collected"
}

collect_open_ports() {
    local file="$OUTPUT_DIR/03_open_ports.txt"
    log_info "Collecting open ports..."
    
    write_header "$file" "OPEN PORTS AND LISTENING SERVICES"
    
    append_section "$file" "LISTENING TCP PORTS"
    ss -tlnp >> "$file" 2>/dev/null || netstat -tlnp >> "$file" 2>/dev/null || true
    
    append_section "$file" "LISTENING UDP PORTS"
    ss -ulnp >> "$file" 2>/dev/null || netstat -ulnp >> "$file" 2>/dev/null || true
    
    append_section "$file" "ALL ESTABLISHED CONNECTIONS"
    ss -tnp state established >> "$file" 2>/dev/null || true
    
    log_success "Open ports collected"
}

collect_firewall_status() {
    local file="$OUTPUT_DIR/04_firewall_status.txt"
    log_info "Collecting firewall status..."
    
    write_header "$file" "FIREWALL CONFIGURATION"
    
    append_section "$file" "UFW STATUS"
    if command -v ufw &>/dev/null; then
        ufw status verbose >> "$file" 2>/dev/null || echo "UFW not active" >> "$file"
    else
        echo "UFW not installed" >> "$file"
    fi
    
    append_section "$file" "IPTABLES RULES (IPv4)"
    iptables -L -n -v >> "$file" 2>/dev/null || echo "iptables not available" >> "$file"
    
    append_section "$file" "IPTABLES RULES (IPv6)"
    ip6tables -L -n -v >> "$file" 2>/dev/null || echo "ip6tables not available" >> "$file"
    
    append_section "$file" "NFTABLES RULES"
    if command -v nft &>/dev/null; then
        nft list ruleset >> "$file" 2>/dev/null || echo "nftables not configured" >> "$file"
    else
        echo "nftables not installed" >> "$file"
    fi
    
    append_section "$file" "NFTABLES SERVICE STATUS"
    systemctl is-enabled nftables 2>/dev/null >> "$file" || echo "nftables service not found" >> "$file"
    systemctl is-active nftables 2>/dev/null >> "$file" || true
    
    log_success "Firewall status collected"
}

collect_kernel_params() {
    local file="$OUTPUT_DIR/05_kernel_params.txt"
    log_info "Collecting kernel parameters..."
    
    write_header "$file" "KERNEL SECURITY PARAMETERS"
    
    append_section "$file" "CIS HARDENING PARAMETERS"
    {
        echo "# Section 1.5 - Kernel Hardening"
        sysctl kernel.randomize_va_space 2>/dev/null || true
        sysctl kernel.yama.ptrace_scope 2>/dev/null || true
        sysctl fs.suid_dumpable 2>/dev/null || true
        
        echo ""
        echo "# Section 3.3 - Network Parameters"
        sysctl net.ipv4.ip_forward 2>/dev/null || true
        sysctl net.ipv6.conf.all.forwarding 2>/dev/null || true
        sysctl net.ipv4.conf.all.send_redirects 2>/dev/null || true
        sysctl net.ipv4.conf.default.send_redirects 2>/dev/null || true
        sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null || true
        sysctl net.ipv4.conf.default.accept_redirects 2>/dev/null || true
        sysctl net.ipv6.conf.all.accept_redirects 2>/dev/null || true
        sysctl net.ipv6.conf.default.accept_redirects 2>/dev/null || true
        sysctl net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null || true
        sysctl net.ipv4.tcp_syncookies 2>/dev/null || true
    } >> "$file"
    
    append_section "$file" "ALL NETWORK PARAMETERS"
    sysctl -a 2>/dev/null | grep -E "^net\." | sort >> "$file" || true
    
    append_section "$file" "ALL KERNEL PARAMETERS"
    sysctl -a 2>/dev/null | grep -E "^kernel\." | sort >> "$file" || true
    
    append_section "$file" "FILESYSTEM PARAMETERS"
    sysctl -a 2>/dev/null | grep -E "^fs\." | sort >> "$file" || true
    
    log_success "Kernel parameters collected"
}

collect_kernel_modules() {
    local file="$OUTPUT_DIR/06_kernel_modules.txt"
    log_info "Collecting kernel modules..."
    
    write_header "$file" "KERNEL MODULES"
    
    append_section "$file" "LOADED MODULES"
    lsmod | sort >> "$file"
    
    append_section "$file" "BLACKLISTED MODULES"
    if [[ -d /etc/modprobe.d ]]; then
        grep -rh "^blacklist\|^install.*\/bin\/(true\|false)" /etc/modprobe.d/ 2>/dev/null | sort -u >> "$file" || echo "No blacklisted modules found" >> "$file"
    fi
    
    append_section "$file" "USB-STORAGE STATUS"
    if lsmod | grep -q usb_storage; then
        echo "usb-storage module is LOADED" >> "$file"
    else
        echo "usb-storage module is NOT loaded" >> "$file"
    fi
    if grep -rq "install usb-storage /bin/true\|blacklist usb-storage" /etc/modprobe.d/ 2>/dev/null; then
        echo "usb-storage is DISABLED in modprobe.d" >> "$file"
    else
        echo "usb-storage is NOT disabled in modprobe.d" >> "$file"
    fi
    
    log_success "Kernel modules collected"
}

collect_filesystem_mounts() {
    local file="$OUTPUT_DIR/07_filesystem_mounts.txt"
    log_info "Collecting filesystem mounts..."
    
    write_header "$file" "FILESYSTEM MOUNTS AND OPTIONS"
    
    append_section "$file" "CURRENT MOUNTS"
    mount | column -t >> "$file" 2>/dev/null || mount >> "$file"
    
    append_section "$file" "FSTAB CONFIGURATION"
    cat /etc/fstab >> "$file" 2>/dev/null || true
    
    append_section "$file" "TMP MOUNT OPTIONS"
    findmnt /tmp -o TARGET,SOURCE,FSTYPE,OPTIONS >> "$file" 2>/dev/null || echo "/tmp not separately mounted" >> "$file"
    
    append_section "$file" "DEV/SHM MOUNT OPTIONS"
    findmnt /dev/shm -o TARGET,SOURCE,FSTYPE,OPTIONS >> "$file" 2>/dev/null || echo "/dev/shm mount info not available" >> "$file"
    
    append_section "$file" "PARTITION TABLE"
    lsblk -f >> "$file" 2>/dev/null || true
    
    log_success "Filesystem mounts collected"
}

collect_apparmor_status() {
    local file="$OUTPUT_DIR/08_apparmor_status.txt"
    log_info "Collecting AppArmor status..."
    
    write_header "$file" "APPARMOR STATUS"
    
    append_section "$file" "APPARMOR STATUS"
    if command -v aa-status &>/dev/null; then
        aa-status >> "$file" 2>/dev/null || echo "AppArmor not running" >> "$file"
    else
        echo "AppArmor tools not installed" >> "$file"
    fi
    
    append_section "$file" "APPARMOR SERVICE"
    systemctl status apparmor --no-pager >> "$file" 2>/dev/null || true
    
    append_section "$file" "GRUB APPARMOR CONFIGURATION"
    grep -E "GRUB_CMDLINE_LINUX.*apparmor" /etc/default/grub >> "$file" 2>/dev/null || echo "AppArmor not configured in GRUB" >> "$file"
    
    log_success "AppArmor status collected"
}

collect_users_groups() {
    local file="$OUTPUT_DIR/09_users_groups.txt"
    log_info "Collecting users and groups..."
    
    write_header "$file" "USERS AND GROUPS"
    
    append_section "$file" "SYSTEM USERS (UID < 1000)"
    awk -F: '$3 < 1000 {print $1":"$3":"$7}' /etc/passwd >> "$file"
    
    append_section "$file" "REGULAR USERS (UID >= 1000)"
    awk -F: '$3 >= 1000 {print $1":"$3":"$7}' /etc/passwd >> "$file"
    
    append_section "$file" "USERS WITH UID 0"
    awk -F: '$3 == 0 {print $1}' /etc/passwd >> "$file"
    
    append_section "$file" "USERS WITH LOGIN SHELL"
    grep -vE "nologin|false|sync|shutdown|halt" /etc/passwd | awk -F: '{print $1":"$7}' >> "$file"
    
    append_section "$file" "SUDO GROUP MEMBERS"
    grep -E "^sudo:|^wheel:" /etc/group >> "$file" 2>/dev/null || echo "No sudo/wheel group found" >> "$file"
    
    append_section "$file" "SUDOERS CONFIGURATION"
    cat /etc/sudoers 2>/dev/null | grep -v "^#" | grep -v "^$" >> "$file" || true
    if [[ -d /etc/sudoers.d ]]; then
        echo "--- Files in /etc/sudoers.d ---" >> "$file"
        ls -la /etc/sudoers.d/ >> "$file" 2>/dev/null || true
    fi
    
    log_success "Users and groups collected"
}

collect_password_policy() {
    local file="$OUTPUT_DIR/10_password_policy.txt"
    log_info "Collecting password policy..."
    
    write_header "$file" "PASSWORD AND AUTHENTICATION POLICY"
    
    append_section "$file" "LOGIN.DEFS SETTINGS"
    grep -E "^PASS_|^ENCRYPT_METHOD|^SHA_CRYPT|^LOGIN_RETRIES|^LOGIN_TIMEOUT|^UMASK|^INACTIVE" /etc/login.defs 2>/dev/null | grep -v "^#" >> "$file" || true
    
    append_section "$file" "USERADD DEFAULTS"
    cat /etc/default/useradd 2>/dev/null | grep -v "^#" | grep -v "^$" >> "$file" || true
    
    append_section "$file" "PAM PASSWORD CONFIGURATION"
    grep -E "pam_unix|pam_pwquality|pam_cracklib|pam_faillock" /etc/pam.d/common-password /etc/pam.d/common-auth 2>/dev/null >> "$file" || true
    
    append_section "$file" "PWQUALITY CONFIGURATION"
    if [[ -f /etc/security/pwquality.conf ]]; then
        grep -v "^#" /etc/security/pwquality.conf | grep -v "^$" >> "$file" || echo "Default configuration" >> "$file"
    else
        echo "pwquality.conf not found" >> "$file"
    fi
    
    append_section "$file" "PASSWORD AGING (USERS WITH PASSWORD)"
    for user in $(awk -F: '$2~/^\$.+\$/ {print $1}' /etc/shadow 2>/dev/null); do
        chage -l "$user" 2>/dev/null | head -5 | sed "s/^/$user: /" >> "$file"
        echo "" >> "$file"
    done
    
    append_section "$file" "INACTIVE PASSWORD LOCK SETTING"
    useradd -D 2>/dev/null | grep INACTIVE >> "$file" || true
    
    log_success "Password policy collected"
}

collect_ssh_config() {
    local file="$OUTPUT_DIR/11_ssh_config.txt"
    log_info "Collecting SSH configuration..."
    
    write_header "$file" "SSH SERVER CONFIGURATION"
    
    append_section "$file" "SSHD SERVICE STATUS"
    systemctl status sshd --no-pager >> "$file" 2>/dev/null || systemctl status ssh --no-pager >> "$file" 2>/dev/null || true
    
    append_section "$file" "SSHD_CONFIG (NON-DEFAULT SETTINGS)"
    if [[ -f /etc/ssh/sshd_config ]]; then
        grep -vE "^#|^$" /etc/ssh/sshd_config >> "$file"
    fi
    
    append_section "$file" "SSHD_CONFIG.D DIRECTORY"
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        for conf in /etc/ssh/sshd_config.d/*.conf; do
            if [[ -f "$conf" ]]; then
                echo "--- $conf ---" >> "$file"
                grep -vE "^#|^$" "$conf" >> "$file"
            fi
        done
    else
        echo "No sshd_config.d directory" >> "$file"
    fi
    
    append_section "$file" "SSH HOST KEYS"
    ls -la /etc/ssh/ssh_host_* 2>/dev/null >> "$file" || true
    
    append_section "$file" "AUTHORIZED KEYS LOCATIONS"
    for home in /root /home/*; do
        if [[ -f "$home/.ssh/authorized_keys" ]]; then
            echo "$home/.ssh/authorized_keys exists ($(wc -l < "$home/.ssh/authorized_keys") keys)" >> "$file"
        fi
    done
    
    log_success "SSH configuration collected"
}

collect_services() {
    local file="$OUTPUT_DIR/12_services.txt"
    log_info "Collecting services status..."
    
    write_header "$file" "SYSTEMD SERVICES"
    
    append_section "$file" "ENABLED SERVICES"
    systemctl list-unit-files --type=service --state=enabled --no-pager >> "$file" 2>/dev/null || true
    
    append_section "$file" "RUNNING SERVICES"
    systemctl list-units --type=service --state=running --no-pager >> "$file" 2>/dev/null || true
    
    append_section "$file" "FAILED SERVICES"
    systemctl list-units --type=service --state=failed --no-pager >> "$file" 2>/dev/null || true
    
    append_section "$file" "SECURITY-RELEVANT SERVICES"
    for svc in auditd apparmor ufw nftables ssh sshd rsyslog systemd-journald fail2ban clamav-daemon rkhunter; do
        echo "--- $svc ---" >> "$file"
        systemctl is-enabled "$svc" 2>/dev/null >> "$file" || echo "not found" >> "$file"
        systemctl is-active "$svc" 2>/dev/null >> "$file" || echo "not active" >> "$file"
    done
    
    log_success "Services status collected"
}

collect_auditd_status() {
    local file="$OUTPUT_DIR/13_auditd_status.txt"
    log_info "Collecting auditd status..."
    
    write_header "$file" "AUDIT DAEMON CONFIGURATION"
    
    append_section "$file" "AUDITD SERVICE STATUS"
    systemctl status auditd --no-pager >> "$file" 2>/dev/null || echo "auditd not installed or not running" >> "$file"
    
    append_section "$file" "AUDITD CONFIGURATION"
    if [[ -f /etc/audit/auditd.conf ]]; then
        grep -vE "^#|^$" /etc/audit/auditd.conf >> "$file"
    else
        echo "auditd.conf not found" >> "$file"
    fi
    
    append_section "$file" "AUDIT RULES"
    auditctl -l >> "$file" 2>/dev/null || echo "No audit rules loaded" >> "$file"
    
    append_section "$file" "AUDIT RULES FILES"
    if [[ -d /etc/audit/rules.d ]]; then
        ls -la /etc/audit/rules.d/ >> "$file"
        for rulefile in /etc/audit/rules.d/*.rules; do
            if [[ -f "$rulefile" ]]; then
                echo "--- $rulefile ---" >> "$file"
                cat "$rulefile" >> "$file"
            fi
        done
    fi
    
    append_section "$file" "AUDIT STATUS"
    auditctl -s >> "$file" 2>/dev/null || true
    
    log_success "Auditd status collected"
}

collect_logging_config() {
    local file="$OUTPUT_DIR/14_logging_config.txt"
    log_info "Collecting logging configuration..."
    
    write_header "$file" "LOGGING CONFIGURATION"
    
    append_section "$file" "RSYSLOG STATUS"
    systemctl status rsyslog --no-pager >> "$file" 2>/dev/null || echo "rsyslog not running" >> "$file"
    
    append_section "$file" "RSYSLOG CONFIGURATION"
    if [[ -f /etc/rsyslog.conf ]]; then
        grep -vE "^#|^$" /etc/rsyslog.conf | head -50 >> "$file"
    fi
    
    append_section "$file" "RSYSLOG FILE PERMISSIONS SETTING"
    grep -E "FileCreateMode|DirCreateMode" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null >> "$file" || echo "Default permissions" >> "$file"
    
    append_section "$file" "JOURNALD CONFIGURATION"
    if [[ -f /etc/systemd/journald.conf ]]; then
        grep -vE "^#|^$" /etc/systemd/journald.conf >> "$file" || echo "Default configuration" >> "$file"
    fi
    
    append_section "$file" "LOG DIRECTORY PERMISSIONS"
    ls -la /var/log/ | head -30 >> "$file"
    
    log_success "Logging configuration collected"
}

collect_file_permissions() {
    local file="$OUTPUT_DIR/15_file_permissions.txt"
    log_info "Collecting file permissions..."
    
    write_header "$file" "CRITICAL FILE PERMISSIONS"
    
    append_section "$file" "PASSWD AND SHADOW FILES"
    ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null >> "$file" || true
    
    append_section "$file" "GRUB CONFIGURATION"
    ls -la /boot/grub/grub.cfg 2>/dev/null >> "$file" || echo "grub.cfg not found" >> "$file"
    ls -la /etc/grub.d/ 2>/dev/null >> "$file" || true
    
    append_section "$file" "SSH CONFIGURATION FILES"
    ls -la /etc/ssh/sshd_config 2>/dev/null >> "$file" || true
    ls -la /etc/ssh/sshd_config.d/ 2>/dev/null >> "$file" || true
    
    append_section "$file" "CRON DIRECTORIES"
    ls -la /etc/cron* 2>/dev/null >> "$file" || true
    
    append_section "$file" "SUID/SGID FILES"
    echo "SUID files:" >> "$file"
    find / -perm -4000 -type f 2>/dev/null | head -50 >> "$file" || true
    echo "" >> "$file"
    echo "SGID files:" >> "$file"
    find / -perm -2000 -type f 2>/dev/null | head -50 >> "$file" || true
    
    append_section "$file" "WORLD-WRITABLE DIRECTORIES"
    find / -type d -perm -0002 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -30 >> "$file" || true
    
    log_success "File permissions collected"
}

collect_cis_controls() {
    local file="$OUTPUT_DIR/16_cis_controls.txt"
    log_info "Collecting CIS control status..."
    
    write_header "$file" "CIS CONTROL COMPLIANCE STATUS"
    
    append_section "$file" "SECTION 1.1 - FILESYSTEM"
    
    echo "1.1.1.9 - USB Storage:" >> "$file"
    if grep -rq "install usb-storage /bin/true\|blacklist usb-storage" /etc/modprobe.d/ 2>/dev/null; then
        echo "  COMPLIANT - USB storage disabled" >> "$file"
    else
        echo "  NON-COMPLIANT - USB storage not disabled" >> "$file"
    fi
    
    echo "1.1.2.1.1 - /tmp partition:" >> "$file"
    if findmnt /tmp &>/dev/null; then
        echo "  COMPLIANT - /tmp is separately mounted" >> "$file"
    else
        echo "  NON-COMPLIANT - /tmp is not separately mounted" >> "$file"
    fi
    
    echo "1.1.2.1.4 - noexec on /tmp:" >> "$file"
    if findmnt /tmp -o OPTIONS 2>/dev/null | grep -q noexec; then
        echo "  COMPLIANT - noexec set on /tmp" >> "$file"
    else
        echo "  NON-COMPLIANT - noexec not set on /tmp" >> "$file"
    fi
    
    append_section "$file" "SECTION 1.3 - APPARMOR"
    
    echo "1.3.1.2 - AppArmor in bootloader:" >> "$file"
    if grep -q "apparmor=1" /proc/cmdline 2>/dev/null; then
        echo "  COMPLIANT - AppArmor enabled in bootloader" >> "$file"
    else
        echo "  NON-COMPLIANT - AppArmor not in bootloader" >> "$file"
    fi
    
    echo "1.3.1.4 - AppArmor enforce mode:" >> "$file"
    local profiles_enforce=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")
    local profiles_complain=$(aa-status 2>/dev/null | grep "profiles are in complain mode" | awk '{print $1}' || echo "0")
    echo "  Profiles in enforce mode: ${profiles_enforce:-0}" >> "$file"
    echo "  Profiles in complain mode: ${profiles_complain:-0}" >> "$file"
    
    append_section "$file" "SECTION 1.4 - BOOTLOADER"
    
    echo "1.4.1 - Bootloader password:" >> "$file"
    if grep -q "password_pbkdf2\|password" /boot/grub/grub.cfg 2>/dev/null; then
        echo "  COMPLIANT - GRUB password configured" >> "$file"
    else
        echo "  NON-COMPLIANT - GRUB password not configured" >> "$file"
    fi
    
    echo "1.4.2 - Bootloader permissions:" >> "$file"
    local grub_perms=$(stat -c %a /boot/grub/grub.cfg 2>/dev/null || echo "")
    if [[ "$grub_perms" == "600" ]] || [[ "$grub_perms" == "400" ]]; then
        echo "  COMPLIANT - grub.cfg permissions: $grub_perms" >> "$file"
    else
        echo "  NON-COMPLIANT - grub.cfg permissions: ${grub_perms:-not found}" >> "$file"
    fi
    
    append_section "$file" "SECTION 1.5 - KERNEL"
    
    echo "1.5.1 - ASLR:" >> "$file"
    local aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "")
    if [[ "$aslr" == "2" ]]; then
        echo "  COMPLIANT - ASLR enabled (value: $aslr)" >> "$file"
    else
        echo "  NON-COMPLIANT - ASLR value: ${aslr:-not set}" >> "$file"
    fi
    
    echo "1.5.2 - ptrace_scope:" >> "$file"
    local ptrace=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "")
    if [[ "$ptrace" == "1" ]] || [[ "$ptrace" == "2" ]] || [[ "$ptrace" == "3" ]]; then
        echo "  COMPLIANT - ptrace_scope restricted (value: $ptrace)" >> "$file"
    else
        echo "  NON-COMPLIANT - ptrace_scope value: ${ptrace:-not set}" >> "$file"
    fi
    
    echo "1.5.3 - Core dumps:" >> "$file"
    local suid_dump=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "")
    if [[ "$suid_dump" == "0" ]]; then
        echo "  COMPLIANT - Core dumps restricted (suid_dumpable: $suid_dump)" >> "$file"
    else
        echo "  NON-COMPLIANT - suid_dumpable value: ${suid_dump:-not set}" >> "$file"
    fi
    
    append_section "$file" "SECTION 3.3 - NETWORK PARAMETERS"
    
    echo "3.3.1 - IP forwarding:" >> "$file"
    local ip_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "")
    local ip6_fwd=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo "")
    if [[ "$ip_fwd" == "0" ]] && [[ "$ip6_fwd" == "0" ]]; then
        echo "  COMPLIANT - IP forwarding disabled" >> "$file"
    else
        echo "  NON-COMPLIANT - IPv4: ${ip_fwd:-?}, IPv6: ${ip6_fwd:-?}" >> "$file"
    fi
    
    echo "3.3.2 - Packet redirect sending:" >> "$file"
    local send_redir_all=$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null || echo "")
    local send_redir_def=$(sysctl -n net.ipv4.conf.default.send_redirects 2>/dev/null || echo "")
    if [[ "$send_redir_all" == "0" ]] && [[ "$send_redir_def" == "0" ]]; then
        echo "  COMPLIANT - Packet redirect sending disabled" >> "$file"
    else
        echo "  NON-COMPLIANT - all: ${send_redir_all:-?}, default: ${send_redir_def:-?}" >> "$file"
    fi
    
    echo "3.3.3 - ICMP redirects:" >> "$file"
    local accept_redir=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo "")
    if [[ "$accept_redir" == "0" ]]; then
        echo "  COMPLIANT - ICMP redirects not accepted" >> "$file"
    else
        echo "  NON-COMPLIANT - accept_redirects: ${accept_redir:-?}" >> "$file"
    fi
    
    echo "3.3.4 - Broadcast ICMP:" >> "$file"
    local icmp_bcast=$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null || echo "")
    if [[ "$icmp_bcast" == "1" ]]; then
        echo "  COMPLIANT - Broadcast ICMP ignored" >> "$file"
    else
        echo "  NON-COMPLIANT - icmp_echo_ignore_broadcasts: ${icmp_bcast:-?}" >> "$file"
    fi
    
    echo "3.3.9 - TCP SYN cookies:" >> "$file"
    local syncookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "")
    if [[ "$syncookies" == "1" ]]; then
        echo "  COMPLIANT - TCP SYN cookies enabled" >> "$file"
    else
        echo "  NON-COMPLIANT - tcp_syncookies: ${syncookies:-?}" >> "$file"
    fi
    
    append_section "$file" "SECTION 5.4 - AUTHENTICATION"
    
    echo "5.4.1.4 - SHA512 password hashing:" >> "$file"
    if grep -qE "^ENCRYPT_METHOD\s+(SHA512|YESCRYPT)" /etc/login.defs 2>/dev/null; then
        echo "  COMPLIANT - Strong hashing configured in login.defs" >> "$file"
    else
        echo "  NON-COMPLIANT - Strong hashing not configured" >> "$file"
    fi
    
    echo "5.4.1.5 - Inactive password lock:" >> "$file"
    local inactive=$(useradd -D 2>/dev/null | grep INACTIVE | cut -d= -f2 || echo "")
    if [[ -n "$inactive" ]] && [[ "$inactive" != "-1" ]] && [[ "$inactive" =~ ^[0-9]+$ ]] && [[ "$inactive" -le 45 ]]; then
        echo "  COMPLIANT - Inactive lock: $inactive days" >> "$file"
    else
        echo "  NON-COMPLIANT - Inactive lock: ${inactive:-not set}" >> "$file"
    fi
    
    append_section "$file" "SECTION 6 - LOGGING AND AUDITING"
    
    echo "6.2.1.2 - auditd enabled:" >> "$file"
    if systemctl is-enabled auditd &>/dev/null; then
        echo "  COMPLIANT - auditd is enabled" >> "$file"
    else
        echo "  NON-COMPLIANT - auditd not enabled" >> "$file"
    fi
    
    echo "6.3.1 - AIDE installed:" >> "$file"
    if command -v aide &>/dev/null; then
        echo "  COMPLIANT - AIDE is installed" >> "$file"
    else
        echo "  NON-COMPLIANT - AIDE not installed" >> "$file"
    fi
    
    log_success "CIS control status collected"
}

collect_security_tools() {
    local file="$OUTPUT_DIR/18_security_tools.txt"
    log_info "Collecting security tools status..."
    
    write_header "$file" "SECURITY TOOLS STATUS"
    
    append_section "$file" "INSTALLED SECURITY TOOLS"
    
    local tools=(
        "lynis:Lynis Security Auditing"
        "rkhunter:Rootkit Hunter"
        "chkrootkit:Rootkit Checker"
        "aide:Advanced Intrusion Detection Environment"
        "clamav:ClamAV Antivirus"
        "fail2ban-client:Fail2Ban Intrusion Prevention"
        "ufw:Uncomplicated Firewall"
        "nft:nftables"
        "auditctl:Linux Audit"
        "aa-status:AppArmor"
        "debsums:Debian File Verification"
        "apt-show-versions:Package Version Checker"
        "needrestart:Restart Checker"
    )
    
    for tool_info in "${tools[@]}"; do
        local cmd="${tool_info%%:*}"
        local desc="${tool_info##*:}"
        if command -v "$cmd" &>/dev/null; then
            local version=$($cmd --version 2>/dev/null | head -1 || echo "installed")
            echo "[INSTALLED] $desc ($cmd): $version" >> "$file"
        else
            echo "[MISSING]   $desc ($cmd)" >> "$file"
        fi
    done
    
    append_section "$file" "RKHUNTER STATUS"
    if command -v rkhunter &>/dev/null; then
        rkhunter --versioncheck 2>/dev/null >> "$file" || echo "rkhunter installed but version check failed" >> "$file"
        echo "" >> "$file"
        echo "Last run:" >> "$file"
        ls -la /var/log/rkhunter.log 2>/dev/null >> "$file" || echo "No log file found" >> "$file"
    else
        echo "rkhunter not installed" >> "$file"
    fi
    
    append_section "$file" "CLAMAV STATUS"
    if command -v clamscan &>/dev/null; then
        clamscan --version 2>/dev/null >> "$file" || true
        echo "" >> "$file"
        systemctl is-active clamav-freshclam 2>/dev/null >> "$file" || echo "freshclam not running" >> "$file"
    else
        echo "ClamAV not installed" >> "$file"
    fi
    
    append_section "$file" "FAIL2BAN STATUS"
    if command -v fail2ban-client &>/dev/null; then
        fail2ban-client status 2>/dev/null >> "$file" || echo "Fail2Ban not running" >> "$file"
    else
        echo "Fail2Ban not installed" >> "$file"
    fi
    
    append_section "$file" "COMPILER PRESENCE (Security consideration)"
    local compilers_found=false
    for compiler in gcc g++ cc clang make; do
        if command -v "$compiler" &>/dev/null; then
            echo "[PRESENT] $compiler: $(which $compiler)" >> "$file"
            compilers_found=true
        fi
    done
    if ! $compilers_found; then
        echo "No compilers found (good for production servers)" >> "$file"
    fi
    
    log_success "Security tools status collected"
}

run_lynis_audit() {
    local file="$OUTPUT_DIR/17_lynis_report.txt"
    log_section "Running Lynis security audit..."
    
    write_header "$file" "LYNIS SECURITY AUDIT REPORT"
    
    # Check if Lynis is installed
    if ! command -v lynis &>/dev/null; then
        log_warning "Lynis not installed. Installing..."
        
        # Try to install Lynis
        if command -v apt-get &>/dev/null; then
            apt-get update -qq
            apt-get install -y -qq lynis 2>/dev/null || {
                # Try installing from official repository
                wget -q -O - https://packages.cisofy.com/keys/cisofy-software-public.key | apt-key add - 2>/dev/null || true
                echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" > /etc/apt/sources.list.d/cisofy-lynis.list 2>/dev/null || true
                apt-get update -qq 2>/dev/null || true
                apt-get install -y -qq lynis 2>/dev/null || {
                    log_error "Could not install Lynis. Skipping Lynis audit."
                    echo "Lynis could not be installed. Please install manually:" >> "$file"
                    echo "  apt-get install lynis" >> "$file"
                    echo "  # or from official repo:" >> "$file"
                    echo "  # https://packages.cisofy.com/" >> "$file"
                    return 1
                }
            }
        else
            log_error "apt-get not found. Cannot install Lynis automatically."
            echo "Lynis not installed and could not be auto-installed." >> "$file"
            return 1
        fi
    fi
    
    log_info "Lynis version: $(lynis --version 2>/dev/null | head -1)"
    
    # Create Lynis report directory
    local lynis_report_dir="$OUTPUT_DIR/lynis"
    mkdir -p "$lynis_report_dir"
    
    append_section "$file" "LYNIS AUDIT EXECUTION"
    echo "Audit started: $(date '+%Y-%m-%d %H:%M:%S')" >> "$file"
    
    # Run Lynis audit
    local lynis_opts="--no-colors --quick"
    if [[ "$LYNIS_AUDIT_ONLY" == "true" ]]; then
        lynis_opts="--no-colors --quick --auditor 'CIS Hardening Script'"
    fi
    
    log_info "Running: lynis audit system $lynis_opts"
    
    # Run Lynis and capture output
    lynis audit system $lynis_opts --report-file "$lynis_report_dir/lynis-report.dat" \
        --log-file "$lynis_report_dir/lynis.log" 2>&1 | tee -a "$file" || true
    
    echo "" >> "$file"
    echo "Audit completed: $(date '+%Y-%m-%d %H:%M:%S')" >> "$file"
    
    append_section "$file" "LYNIS HARDENING INDEX"
    
    # Extract hardening index from report
    if [[ -f "$lynis_report_dir/lynis-report.dat" ]]; then
        local hardening_index=$(grep "hardening_index=" "$lynis_report_dir/lynis-report.dat" 2>/dev/null | cut -d= -f2 || echo "")
        if [[ -n "$hardening_index" ]]; then
            echo "Hardening Index: $hardening_index / 100" >> "$file"
            log_success "Lynis Hardening Index: $hardening_index / 100"
        fi
        
        # Extract warnings and suggestions counts
        local warning_count=$(grep -c "^warning\[\]=" "$lynis_report_dir/lynis-report.dat" 2>/dev/null || echo "0")
        local suggestion_count=$(grep -c "^suggestion\[\]=" "$lynis_report_dir/lynis-report.dat" 2>/dev/null || echo "0")
        
        echo "Warnings: $warning_count" >> "$file"
        echo "Suggestions: $suggestion_count" >> "$file"
    fi
    
    append_section "$file" "LYNIS WARNINGS"
    if [[ -f "$lynis_report_dir/lynis-report.dat" ]]; then
        grep "^warning\[\]=" "$lynis_report_dir/lynis-report.dat" 2>/dev/null | \
            sed 's/warning\[\]=//g' | head -30 >> "$file" || echo "No warnings" >> "$file"
    fi
    
    append_section "$file" "LYNIS TOP SUGGESTIONS"
    if [[ -f "$lynis_report_dir/lynis-report.dat" ]]; then
        grep "^suggestion\[\]=" "$lynis_report_dir/lynis-report.dat" 2>/dev/null | \
            sed 's/suggestion\[\]=//g' | head -30 >> "$file" || echo "No suggestions" >> "$file"
    fi
    
    # Copy full Lynis report
    if [[ -f "$lynis_report_dir/lynis-report.dat" ]]; then
        cp "$lynis_report_dir/lynis-report.dat" "$OUTPUT_DIR/lynis-report-full.dat"
    fi
    if [[ -f "$lynis_report_dir/lynis.log" ]]; then
        cp "$lynis_report_dir/lynis.log" "$OUTPUT_DIR/lynis-full.log"
    fi
    
    log_success "Lynis audit completed"
}

#===============================================================================
# Main Execution
#===============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --phase)
                PHASE="$2"
                shift 2
                ;;
            --output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --skip-lynis)
                RUN_LYNIS=false
                shift
                ;;
            --lynis-quick)
                LYNIS_AUDIT_ONLY=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --version|-v)
                show_version
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Validate phase
    if [[ -z "$PHASE" ]]; then
        log_error "Phase is required. Use --phase <initial|post>"
        show_help
        exit 1
    fi
    
    if [[ "$PHASE" != "initial" ]] && [[ "$PHASE" != "post" ]]; then
        log_error "Invalid phase: $PHASE. Must be 'initial' or 'post'"
        exit 1
    fi
    
    # Set default output directory based on phase
    if [[ -z "$OUTPUT_DIR" ]]; then
        if [[ "$PHASE" == "initial" ]]; then
            OUTPUT_DIR="./initial_logs"
        else
            OUTPUT_DIR="./hardening_logs"
        fi
    fi
    
    # Print banner
    echo ""
    echo "==============================================================================="
    echo "  CIS Ubuntu Server 24.04 LTS - Security Analysis v${SCRIPT_VERSION}"
    echo "  Phase: $PHASE"
    echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Lynis: $(if $RUN_LYNIS; then echo 'Enabled'; else echo 'Disabled'; fi)"
    echo "==============================================================================="
    echo ""
    
    check_root
    create_output_dir
    
    # Run all collection functions
    collect_system_info
    collect_network_config
    collect_open_ports
    collect_firewall_status
    collect_kernel_params
    collect_kernel_modules
    collect_filesystem_mounts
    collect_apparmor_status
    collect_users_groups
    collect_password_policy
    collect_ssh_config
    collect_services
    collect_auditd_status
    collect_logging_config
    collect_file_permissions
    collect_cis_controls
    collect_security_tools
    
    # Run Lynis audit if enabled
    if $RUN_LYNIS; then
        run_lynis_audit
    fi
    
    echo ""
    echo "==============================================================================="
    log_success "Analysis complete. Output saved to: $OUTPUT_DIR"
    echo "==============================================================================="
    echo ""
    echo "Files generated:"
    ls -1 "$OUTPUT_DIR"/*.txt 2>/dev/null | while read -r f; do
        echo "  - $(basename "$f")"
    done
    
    # Show Lynis score summary if available
    if [[ -f "$OUTPUT_DIR/lynis/lynis-report.dat" ]]; then
        local score=$(grep "hardening_index=" "$OUTPUT_DIR/lynis/lynis-report.dat" 2>/dev/null | cut -d= -f2 || echo "")
        if [[ -n "$score" ]]; then
            echo ""
            echo "  Lynis Hardening Index: $score / 100"
        fi
    fi
    echo ""
}

main "$@"
