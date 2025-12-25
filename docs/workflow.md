# CIS Hardening Workflow

## Version 1.0.0

This document describes the complete hardening workflow for Ubuntu Server 24.04 LTS systems using both Bash scripts and Ansible automation.

---

## Overview

The hardening process consists of six phases:

1. **Initial Analysis** - Collect baseline security state and Lynis score
2. **Security Tools** - Install required security tools
3. **CIS Hardening** - Apply CIS benchmark controls
4. **Lynis Improvements** - Additional hardening for better Lynis score
5. **Firewall Configuration** - Configure nftables firewall
6. **Post Analysis** - Verify improvements and generate report

---

## Bash Script Workflow

### Quick Start (Full Automated Workflow)

```bash
# Run complete hardening workflow
sudo ./scripts/00-cis-hardening-main.sh full

# With custom options
sudo ./scripts/00-cis-hardening-main.sh full --ssh-port 2222 --tcp-ports 80,443
```

### Step-by-Step Workflow

```bash
# Step 1: Collect initial state and Lynis score
sudo ./scripts/00-cis-hardening-main.sh analyze --phase initial

# Step 2: Install security tools
sudo ./scripts/00-cis-hardening-main.sh tools

# Step 3: Apply CIS hardening controls
sudo ./scripts/00-cis-hardening-main.sh harden

# Step 4: Apply Lynis score improvements
sudo ./scripts/00-cis-hardening-main.sh lynis-improve

# Optional: Remove compilers for production servers
sudo ./scripts/00-cis-hardening-main.sh lynis-improve --remove-compilers

# Step 5: Configure nftables firewall
sudo ./scripts/00-cis-hardening-main.sh firewall --ssh-port 22 --tcp-ports 443

# Step 6: Collect post-hardening state
sudo ./scripts/00-cis-hardening-main.sh analyze --phase post

# Step 7: Generate report
sudo ./scripts/00-cis-hardening-main.sh report
```

### Individual Scripts

| Script | Description |
|--------|-------------|
| `cis-analyze.sh` | Security analysis with Lynis integration |
| `40-install-security-tools.sh` | Install security tools |
| `41-lynis-improvements.sh` | Additional Lynis hardening |
| `42-configure-nftables.sh` | nftables firewall configuration |
| `01-33: CIS controls` | Individual CIS control scripts |

---

## Ansible Workflow

### Quick Start

```bash
# Full hardening with all features
ansible-playbook -i inventory.yml playbooks/harden.yml

# With Ansible Vault for secrets
ansible-playbook -i inventory.yml playbooks/harden.yml --ask-vault-pass
```

### Using Tags

```bash
# Install security tools only
ansible-playbook -i inventory.yml playbooks/harden.yml --tags security_tools

# Apply CIS controls without security tools
ansible-playbook -i inventory.yml playbooks/harden.yml --skip-tags security_tools

# Apply Lynis improvements only
ansible-playbook -i inventory.yml playbooks/harden.yml --tags lynis_improvements

# Configure firewall only
ansible-playbook -i inventory.yml playbooks/harden.yml --tags firewall
```

### Available Tags

| Tag | Description |
|-----|-------------|
| `security_tools` | Install Lynis, AIDE, rkhunter, etc. |
| `lynis_improvements` | Additional Lynis hardening |
| `section1` to `section6` | CIS benchmark sections |
| `filesystem`, `kernel`, `network` | Specific areas |
| `firewall`, `nftables` | Firewall configuration |
| `ssh`, `pam`, `sudo` | Authentication hardening |

### Configuration Variables

Key variables in `defaults/main.yml`:

```yaml
# Enable/disable features
install_security_tools: true
install_recommended_tools: true
install_clamav: false
apply_lynis_improvements: true
remove_compilers: false

# Firewall settings
ssh_port: 22
nft_enable_ipv6: false
nft_rate_limit_ssh: true
nft_allowed_tcp_ports: []
nft_allowed_udp_ports: []

# Fail2Ban settings
fail2ban_bantime: 3600
fail2ban_ssh_maxretry: 3
```

---

## Security Tools Installed

### Essential Tools

| Tool | Purpose |
|------|---------|
| **Lynis** | Security auditing and hardening score |
| **auditd** | Linux audit framework |
| **AIDE** | File integrity monitoring |
| **rkhunter** | Rootkit detection |
| **chkrootkit** | Rootkit checker |

### Recommended Tools

| Tool | Purpose |
|------|---------|
| **Fail2Ban** | Intrusion prevention (SSH brute-force) |
| **debsums** | Package file verification |
| **needrestart** | Restart notification |
| **nftables** | Modern firewall |

### Optional Tools

| Tool | Purpose |
|------|---------|
| **ClamAV** | Antivirus scanning |
| **acct** | Process accounting |
| **logwatch** | Log analysis |

---

## nftables Firewall Configuration

The firewall is configured with a default-deny policy:

### Default Behavior

- **DROP** all incoming traffic by default
- **ACCEPT** established/related connections
- **ACCEPT** loopback traffic
- **ACCEPT** ICMP ping and diagnostics
- **ACCEPT** SSH with rate limiting (4 connections/minute/IP)
- **DROP** all IPv6 traffic (configurable)
- **DROP** all forwarding (not a router)
- **ACCEPT** all outbound traffic

### Customization

```bash
# Bash script
sudo ./scripts/42-configure-nftables.sh \
    --ssh-port 22 \
    --tcp-ports 80,443 \
    --udp-ports 53 \
    --enable-ipv6

# Ansible variables
nft_allowed_tcp_ports:
  - 80
  - 443
nft_allowed_udp_ports:
  - 53
```

---

## Lynis Score Improvements

The Lynis improvements module applies these additional hardening measures:

### Kernel Hardening

- `kernel.dmesg_restrict = 1` - Restrict dmesg access
- `kernel.kptr_restrict = 2` - Restrict kernel pointer exposure
- `kernel.sysrq = 0` - Disable magic SysRq key
- `kernel.unprivileged_bpf_disabled = 1` - Restrict BPF

### Network Hardening

- Disable unused protocols: DCCP, SCTP, RDS, TIPC
- `net.ipv4.tcp_rfc1337 = 1` - RFC 1337 protection
- Disable IPv6 router advertisements

### File Permissions

- Secure cron directories (mode 0700)
- Create restrictive at.allow and cron.allow
- Set UMASK to 027
- Secure home directories (mode 0750)

### Service Hardening

- Disable unnecessary services (avahi, cups, bluetooth)
- Configure security banners
- Set shell timeout (15 minutes)

### Optional: Compiler Removal

For production servers, compilers can be removed:

```bash
# Bash
sudo ./scripts/41-lynis-improvements.sh --remove-compilers

# Ansible
remove_compilers: true
```

---

## Expected Lynis Score Improvements

| Phase | Expected Score |
|-------|----------------|
| Initial (default Ubuntu) | 55-65 |
| After CIS controls | 75-80 |
| After Lynis improvements | 82-88 |
| With compiler removal | 88-92 |

> **Tested Result**: This project achieved **62 → 84** (+22 points) improvement.

---

## Log Files and Reports

| Location | Description |
|----------|-------------|
| `/var/log/cis-hardening/` | All hardening logs |
| `initial_logs/` | Pre-hardening analysis |
| `hardening_logs/` | Post-hardening analysis |
| `lynis-report-full.dat` | Detailed Lynis report |

---

## Best Practices

1. **Always run initial analysis first** to establish baseline
2. **Review reports** before and after hardening
3. **Test in staging** before applying to production
4. **Keep backups** - all scripts create backups in `/var/backups/cis-hardening/`
5. **Reboot after hardening** to apply kernel module changes
6. **Document exceptions** for any skipped controls
7. **Regular audits** - run Lynis periodically

---

## Troubleshooting

### SSH Connection Lost

If you lose SSH access after firewall configuration:

1. Access the server via console
2. Check nftables rules: `nft list ruleset`
3. Flush rules if needed: `nft flush ruleset`
4. Restart with correct port: `./scripts/42-configure-nftables.sh --ssh-port YOUR_PORT`

### Audit Rules Locked

If audit rules are immutable:

1. Reboot the system
2. Modify rules in `/etc/audit/rules.d/`
3. Reload: `augenrules --load`

### Lynis Warnings

Check specific warnings:

```bash
# View Lynis report
cat /var/log/cis-hardening/17_lynis_report.txt

# Run Lynis directly
lynis audit system
```

