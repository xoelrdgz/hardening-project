# CIS Hardening for Ubuntu Server 24.04 LTS

![Ubuntu 24.04](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu)
![CIS Benchmark](https://img.shields.io/badge/CIS-v1.0.0-005A9C)
![Ansible](https://img.shields.io/badge/Ansible-2.14%2B-1A1918?logo=ansible)
![Lynis](https://img.shields.io/badge/Lynis-Integrated-00C853)
![License](https://img.shields.io/badge/License-MIT-green)

A production-ready implementation of CIS Benchmark security controls for Ubuntu Server 24.04 LTS, featuring standalone Bash scripts, an idempotent Ansible role, Lynis integration, and comprehensive security tooling.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Workflow](#workflow)
- [Project Structure](#project-structure)
- [Implemented Controls](#implemented-controls)
- [Security Tools](#security-tools)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [Validation](#validation)
- [Documentation](#documentation)
- [License](#license)
- [References](#references)

## Overview

This project implements security controls from the [CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0](https://www.cisecurity.org/benchmark/ubuntu_linux) with integrated Lynis security auditing. It provides two complementary approaches:

1. **Bash Scripts**: Standalone scripts for manual or automated hardening
2. **Ansible Role**: Infrastructure-as-code approach for scalable deployments

### Security Domains Covered

| Domain | Description |
|--------|-------------|
| Filesystem | USB storage, mount options, unused filesystems |
| Mandatory Access Control | AppArmor configuration and enforcement |
| Bootloader | GRUB password protection and permissions |
| Kernel | ASLR, ptrace scope, core dumps, memory protection |
| Services | Unnecessary service removal and configuration |
| Network | IP forwarding, ICMP, SYN cookies, protocol disabling |
| Firewall | nftables with default deny policy, rate limiting |
| SSH | Ciphers, MACs, authentication, brute-force protection |
| Authentication | Password policies, complexity, lockout |
| Sudo/PAM | Privilege escalation controls |
| Auditing | auditd rules and configuration |
| File Integrity | AIDE and debsums verification |
| Intrusion Detection | rkhunter, chkrootkit, Fail2Ban |

## Features

### Complete Security Solution

- **Lynis Integration**: Automated security auditing with score tracking
- **Security Tools**: Installs AIDE, rkhunter, chkrootkit, Fail2Ban, and more
- **nftables Firewall**: Hardened configuration with SSH rate limiting
- **Comprehensive Reporting**: Pre and post-hardening analysis

### Ansible Role

- **True Idempotency**: Uses native Ansible modules
- **Vault Integration**: GRUB password hash stored encrypted
- **Level Profiles**: Separate configurations for Level 1 and Level 2
- **Handler-Based Reboots**: Notifies when reboot is required
- **Safety Checks**: Pre-flight validation before dangerous operations

### Bash Scripts

- Complete workflow automation
- Standalone execution for each control
- Comprehensive logging
- Backup of modified configuration files
- Audit and remediation modes

## Quick Start

### Full Automated Workflow (Bash)

```bash
# Clone the repository
git clone https://github.com/xoelrdgz/hardening-project.git
cd hardening-project
chmod +x ./scripts/*.sh

# Run complete hardening with all features
sudo ./scripts/00-cis-hardening-main.sh full

# With custom firewall ports
sudo ./scripts/00-cis-hardening-main.sh full --ssh-port 22 --tcp-ports 80,443
```

### Ansible Playbook

```bash
cd ansible

# Install required collections
ansible-galaxy collection install -r requirements.yml

# Run full hardening
ansible-playbook site.yml --ask-vault-pass

# Run with specific features
ansible-playbook site.yml --tags "security_tools,lynis_improvements"
```

## Workflow

The hardening process follows six phases:

1. **Initial Analysis** → Collect baseline state with Lynis score
2. **Install Tools** → Security tools (Lynis, AIDE, rkhunter, etc.)
3. **Apply CIS Controls** → Hardening controls from CIS Benchmark
4. **Lynis Improvements** → Additional hardening based on Lynis suggestions
5. **Configure Firewall** → nftables with default deny policy
6. **Generate Report** → Post-hardening analysis and comparison

### Step-by-Step Commands

```bash
# Phase 1: Collect initial state with Lynis score
sudo ./scripts/00-cis-hardening-main.sh analyze --phase initial

# Phase 2: Install security tools (Lynis, AIDE, rkhunter, etc.)
sudo ./scripts/00-cis-hardening-main.sh tools

# Phase 3: Apply CIS hardening controls
sudo ./scripts/00-cis-hardening-main.sh harden

# Phase 4: Apply Lynis score improvements
sudo ./scripts/00-cis-hardening-main.sh lynis-improve

# Phase 5: Configure nftables firewall
sudo ./scripts/00-cis-hardening-main.sh firewall

# Phase 6: Collect post-hardening state and generate report
sudo ./scripts/00-cis-hardening-main.sh analyze --phase post
sudo ./scripts/00-cis-hardening-main.sh report
```

## Project Structure

```
hardening-project/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── .gitignore
│
├── scripts/                          # Bash implementation
│   ├── 00-cis-hardening-main.sh      # Main orchestrator
│   ├── 01-*.sh to 33-*.sh            # Individual CIS controls
│   ├── 40-install-security-tools.sh  # Security tools installer
│   ├── 41-lynis-improvements.sh      # Lynis score improvements
│   ├── 42-configure-nftables.sh      # Firewall configuration
│   └── cis-analyze.sh                # Security analysis with Lynis
│
├── ansible/
│   ├── site.yml                      # Main playbook
│   ├── requirements.yml              # Collection dependencies
│   ├── inventories/
│   ├── group_vars/
│   │   └── all/
│   │       ├── main.yml              # Global variables
│   │       └── vault.yml             # Encrypted secrets
│   └── roles/
│       └── cis_hardening/
│           ├── defaults/main.yml     # Default variables
│           ├── handlers/main.yml     # Service handlers
│           ├── tasks/
│           │   ├── main.yml
│           │   ├── section0_security_tools.yml
│           │   ├── section0_lynis_improvements.yml
│           │   ├── section1_*.yml to section6_*.yml
│           └── templates/
│               ├── nftables.conf.j2
│               ├── fail2ban_jail.local.j2
│               └── ...
│
├── docs/
│   ├── workflow.md                   # Detailed workflow documentation
│   ├── initial_state_report.md       # Pre-hardening assessment
│   └── hardening_results_report.md   # Post-hardening results
│
├── initial_logs/                     # Pre-hardening analysis
└── hardening_logs/                   # Post-hardening analysis
```

## Implemented Controls

### Level 1 Controls (Essential Security)

| CIS ID | Description | Implementation |
|--------|-------------|----------------|
| 1.1.1.9 | Disable USB storage | Kernel module blacklist |
| 1.1.1.10 | Disable unused filesystems | Kernel module blacklist |
| 1.1.2.1.1 | /tmp separate partition | tmpfs/LVM mount |
| 1.1.2.1.4 | noexec on /tmp | Mount options |
| 1.3.1.2 | AppArmor in bootloader | GRUB configuration |
| 1.4.1 | Bootloader password | GRUB password (Vault) |
| 1.5.1 | ASLR enabled | sysctl |
| 1.5.2 | ptrace scope restricted | sysctl |
| 1.5.3 | Core dumps restricted | limits.conf + sysctl |
| 3.3.1 | IP forwarding disabled | sysctl |
| 3.3.2 | Packet redirect disabled | sysctl |
| 3.3.3 | ICMP redirects rejected | sysctl |
| 3.3.4 | Broadcast ICMP ignored | sysctl |
| 3.3.10 | TCP SYN cookies enabled | sysctl |
| 3.5.x | nftables configuration | Template + systemd |
| 5.1.x | SSH hardening | sshd_config |
| 5.2.x | Sudo configuration | sudoers.d |
| 5.3.x | PAM configuration | pam.d |
| 5.4.1.4 | SHA512 password hashing | login.defs |
| 6.2.1.2 | auditd enabled | systemd + rules |
| 6.3.1 | AIDE installed | Package + cron |

### Level 2 Controls (Enhanced Security)

| CIS ID | Description | Notes |
|--------|-------------|-------|
| 1.3.1.4 | AppArmor enforce all | All profiles in enforce mode |
| 6.2.3.20 | Audit immutable | Requires reboot to modify rules |

## Security Tools

### Installed by Default

| Tool | Purpose |
|------|---------|
| **Lynis** | Security auditing and hardening score |
| **auditd** | Linux audit framework |
| **AIDE** | File integrity monitoring |
| **rkhunter** | Rootkit detection |
| **chkrootkit** | Rootkit checker |
| **Fail2Ban** | Intrusion prevention (SSH) |
| **debsums** | Package file verification |
| **nftables** | Modern firewall |

### Optional Tools

| Tool | Enable With |
|------|-------------|
| **ClamAV** | `install_clamav: true` |
| **Process Accounting** | `--full` mode |

### Expected Lynis Score

| Phase | Score Range |
|-------|-------------|
| Initial (default Ubuntu) | 55-65 |
| After CIS controls | 75-80 |
| After Lynis improvements | 82-88 |

> **Note**: This project achieved an improvement from **62 to 84** (+22 points) on a test system.

## Requirements

### Target System

- Ubuntu Server 24.04 LTS
- Root or sudo access
- Minimum 1GB free space in /var/log
- Network connectivity

### Ansible Control Node

- Ansible 2.14+
- Python 3.10+
- Collections: `ansible.posix`, `community.general`

```bash
ansible-galaxy collection install -r ansible/requirements.yml
```

## Configuration

### Key Variables (Ansible)

```yaml
# defaults/main.yml

# Enable security tools
install_security_tools: true
install_recommended_tools: true
install_clamav: false

# Apply Lynis improvements
apply_lynis_improvements: true
remove_compilers: false  # WARNING: Only for production

# Firewall
ssh_port: 22
nft_rate_limit_ssh: true
nft_allowed_tcp_ports: []
nft_allowed_udp_ports: []

# Fail2Ban
fail2ban_ssh_maxretry: 3
fail2ban_bantime: 3600
```

### GRUB Password Setup

```bash
# Generate password hash
grub-mkpasswd-pbkdf2 --iteration-count=600000

# Store in vault
ansible-vault create group_vars/all/vault.yml

# Add content
cis_grub_password_hash: "grub.pbkdf2.sha512.600000.YOUR_HASH"
```

## Validation

```bash
# Run Lynis audit
sudo lynis audit system

# Verify sysctl settings
sysctl kernel.randomize_va_space    # Should be 2
sysctl net.ipv4.ip_forward          # Should be 0
sysctl net.ipv4.tcp_syncookies      # Should be 1

# Verify services
systemctl is-enabled auditd fail2ban nftables

# Verify firewall
nft list ruleset

# Verify file integrity tools
aide --check
rkhunter --check
```

## Documentation

- [Workflow Guide](docs/workflow.md) - Detailed workflow documentation
- [Initial State Report](docs/initial_state_report.md) - Pre-hardening assessment
- [Hardening Results Report](docs/hardening_results_report.md) - Post-hardening results

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Notice**: This project implements controls from the CIS Benchmarks. CIS Benchmarks are copyright of the Center for Internet Security, Inc. Users should obtain the official CIS Benchmark documentation from the CIS website.

## References

- [CIS Ubuntu Linux 24.04 LTS Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [Lynis Security Auditing](https://cisofy.com/lynis/)
- [Ansible Documentation](https://docs.ansible.com/)
- [Ubuntu Security Guide](https://ubuntu.com/security)
- [NIST SP 800-123: Guide to General Server Security](https://csrc.nist.gov/publications/detail/sp/800-123/final)
- [NIST SP 800-53: Security and Privacy Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

---

**Author**: xoelrdgz  
**Version**: 1.0.0  
**Last Updated**: December 2025
