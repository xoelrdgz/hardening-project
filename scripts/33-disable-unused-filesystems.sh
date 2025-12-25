#!/usr/bin/env bash
#===============================================================================
# CIS Control: 1.1.1.10 - Ensure unused filesystems are disabled
# Profile: Level 1 - Server
# Automated: Yes (Manual in CIS benchmark, but can be automated)
# Description: Disables mounting of rarely-used filesystem types
#===============================================================================

set -euo pipefail

CONTROL_ID="1.1.1.10"
CONTROL_DESC="Ensure unused filesystems are disabled"
MODPROBE_CONF="/etc/modprobe.d/cis-filesystems.conf"

# Filesystem modules to disable (CIS recommended)
UNUSED_FILESYSTEMS=(
    "cramfs"
    "freevxfs"
    "hfs"
    "hfsplus"
    "jffs2"
    "squashfs"
    "udf"
)

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
    
    for fs in "${UNUSED_FILESYSTEMS[@]}"; do
        local showconfig
        showconfig=$(modprobe --showconfig 2>/dev/null | grep -P "^\s*(install|blacklist)\s+${fs}\b" || true)
        
        local is_disabled=true
        
        # Check if install is set to /bin/false or /bin/true
        if ! echo "$showconfig" | grep -Pq "install\s+${fs}\s+(\/usr)?\/bin\/(true|false)"; then
            is_disabled=false
        fi
        
        # Check if blacklisted
        if ! echo "$showconfig" | grep -Pq "blacklist\s+${fs}"; then
            is_disabled=false
        fi
        
        if $is_disabled; then
            log_success "[$CONTROL_ID] Filesystem '$fs' is disabled"
        else
            # Check if module exists
            if find /lib/modules/*/kernel/fs -name "${fs}.ko*" 2>/dev/null | grep -q .; then
                log_error "[$CONTROL_ID] Filesystem '$fs' is not disabled"
                result=1
            else
                log_info "[$CONTROL_ID] Filesystem '$fs' module not present on system"
            fi
        fi
    done
    
    return $result
}

#===============================================================================
# Remediation Function
#===============================================================================
remediate() {
    log_info "[$CONTROL_ID] Remediating: $CONTROL_DESC"
    
    backup_file "$MODPROBE_CONF"
    
    # Create/update modprobe configuration
    cat > "$MODPROBE_CONF" << 'EOF'
# CIS Control 1.1.1.10 - Disable unused filesystems
# Managed by CIS hardening scripts
EOF
    
    for fs in "${UNUSED_FILESYSTEMS[@]}"; do
        # Check if module exists on the system
        if find /lib/modules/*/kernel/fs -name "${fs}.ko*" 2>/dev/null | grep -q .; then
            log_info "[$CONTROL_ID] Disabling filesystem: $fs"
            
            # Add install directive
            if ! grep -q "^install ${fs}" "$MODPROBE_CONF" 2>/dev/null; then
                echo "install ${fs} /bin/false" >> "$MODPROBE_CONF"
            fi
            
            # Add blacklist directive
            if ! grep -q "^blacklist ${fs}" "$MODPROBE_CONF" 2>/dev/null; then
                echo "blacklist ${fs}" >> "$MODPROBE_CONF"
            fi
            
            # Unload if currently loaded
            if lsmod | grep -q "^${fs} "; then
                modprobe -r "$fs" 2>/dev/null || true
            fi
        else
            log_info "[$CONTROL_ID] Filesystem '$fs' module not present - skipping"
        fi
    done
    
    chmod 644 "$MODPROBE_CONF"
    
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
