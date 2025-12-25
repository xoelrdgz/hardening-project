# Initial System State Report

**Project:** CIS Hardening for Ubuntu Server 24.04 LTS  
**Version:** 1.0.0  
**Author:** xoelrdgz  
**Date:** December 25, 2025  
**Hostname:** ubuntu  

---

## 1. Executive Summary

This report documents the baseline security configuration of an Ubuntu 24.04.3 LTS server prior to applying CIS Benchmark hardening controls. The system presents a standard installation with several security mechanisms enabled by default, but also exhibits significant gaps that require remediation according to CIS v1.0.0 guidelines. The initial Lynis security audit score of **62** indicates a moderate security posture with significant room for improvement.

---

## 2. System Information

| Property | Value |
|----------|-------|
| Operating System | Ubuntu 24.04.3 LTS (Noble Numbat) |
| Kernel Version | 6.8.0-90-generic |
| Architecture | x86-64 |
| Virtualization | VMware |
| Total Memory | 1.9 GiB |
| CPUs | 2 (AMD Ryzen 5 5500U) |
| Root Filesystem | 9.8 GB (49% used) |

---

## 3. Network Configuration

### 3.1 Interfaces

- **ens33**: Primary interface with IP `192.168.x.x/24` (DHCP)
- **lo**: Loopback interface (127.0.0.1)
- IPv6 enabled with link-local address

### 3.2 Open Ports

| Port | Service | Binding |
|------|---------|---------|
| 22/TCP | SSH | 0.0.0.0 / [::] |
| 25/TCP | Postfix SMTP | 127.0.0.1 / [::1] |
| 53/UDP-TCP | systemd-resolved | 127.0.0.53, 127.0.0.54 |
| 68/UDP | DHCP client | 192.168.x.x |

---

## 4. Firewall Status

| Component | Status |
|-----------|--------|
| UFW | Inactive |
| iptables | ACCEPT policy, no rules |
| nftables | **Active with default-drop policy** |

**nftables Configuration:**
- Default DROP policy on INPUT and FORWARD chains
- Stateful connection tracking enabled
- SSH (port 22) allowed
- ICMP essential types allowed
- Loopback traffic allowed, spoofed loopback blocked

**CIS Impact:** Controls 4.3.x (nftables configuration) already satisfied.

---

## 5. Kernel Security Parameters

### 5.1 Compliant Settings

| Parameter | Value | CIS Control |
|-----------|-------|-------------|
| kernel.randomize_va_space | 2 | 1.5.1 ✓ |
| kernel.yama.ptrace_scope | 1 | 1.5.2 ✓ |
| fs.suid_dumpable | 0 | 1.5.3 ✓ |
| net.ipv4.ip_forward | 0 | 3.3.1 ✓ |
| net.ipv4.tcp_syncookies | 1 | 3.3.10 ✓ |
| net.ipv4.icmp_echo_ignore_broadcasts | 1 | 3.3.4 ✓ |
| net.ipv4.conf.all.send_redirects | 0 | 3.3.2 ✓ |
| net.ipv4.conf.all.accept_redirects | 0 | 3.3.3 ✓ |
| net.ipv6.conf.all.accept_redirects | 0 | 3.3.3 ✓ |

### 5.2 Non-Compliant Settings

| Parameter | Current | Required | CIS Control |
|-----------|---------|----------|-------------|
| net.ipv4.conf.all.log_martians | 0 | 1 | 3.3.9 |
| net.ipv4.conf.default.log_martians | 0 | 1 | 3.3.9 |
| net.ipv4.conf.all.secure_redirects | 1 | 0 | 3.3.5 |

---

## 6. Mandatory Access Control (AppArmor)

**Status:** Loaded and active

| Mode | Profiles |
|------|----------|
| Enforce | 112 |
| Complain | 0 |
| Unconfined | 7 |

**Unconfined Profiles:**
- lxc-attach, lxc-create, lxc-destroy, lxc-execute
- lxc-stop, lxc-unshare, lxc-usernsexec

**Enforced Processes:**
- `/usr/sbin/rsyslogd`

**GRUB Configuration:** `apparmor=1 security=apparmor`

**CIS Impact:** Control 1.3.1.4 partially satisfied - 7 profiles remain unconfined.

---

## 7. User and Authentication Configuration

### 7.1 User Accounts

- **Root:** bash shell, UID 0
- **Regular user:** (UID 1000, sudo group)
- **System accounts:** Multiple with nologin shells

### 7.2 Password Policy (login.defs)

| Setting | Current | CIS Required | Control |
|---------|---------|--------------|---------|
| PASS_MAX_DAYS | Configured | 365 | 5.4.1.1 ✓ |
| PASS_MIN_DAYS | Configured | 1 | 5.4.1.1 ✓ |
| PASS_WARN_AGE | 7 | 7 | ✓ |
| ENCRYPT_METHOD | SHA512 | SHA512 | 5.4.1.4 ✓ |

### 7.3 PAM Configuration

- Basic pam_unix with obscure checks
- Password strength tools detected
- Sudoers configured at `/etc/sudoers.d/cis-hardening`

---

## 8. SSH Configuration

**Service Status:** Active (socket-activated)

### Current Settings

| Parameter | Value | CIS Required |
|-----------|-------|--------------|
| PasswordAuthentication | yes | Acceptable |
| PermitRootLogin | (default) | no (5.1.20) |
| X11Forwarding | yes | no |
| MaxAuthTries | (default 6) | 4 (5.1.6) |
| ClientAliveInterval | (default 0) | 15-300 (5.1.7) |

**CIS Impact:** Multiple SSH controls require configuration.

---

## 9. System Services

### 9.1 Security Services

| Service | Status |
|---------|--------|
| auditd | Enabled, Running |
| AppArmor | Enabled, Active |
| rsyslog | Enabled, Running |
| nftables | Enabled, Active |

### 9.2 Services to Review

- `ModemManager.service` - Likely unnecessary
- `postfix.service` - Review MTA requirements (CIS 2.1.21)
- Cloud-init services - If not cloud-deployed

### 9.3 Missing Security Tools

| Tool | Status |
|------|--------|
| fail2ban | Not Installed |
| chkrootkit | Not Found |
| rkhunter | Not Found |
| libpam-tmpdir | Not Installed |
| apt-listchanges | Not Installed |
| debsums | Not Installed |

---

## 10. Audit System (auditd)

**Status:** Running and enabled (CIS 6.2.1.2 ✓)

### Configuration

| Setting | Value |
|---------|-------|
| Log file | /var/log/audit/audit.log |
| Audit rules | Configured |

---

## 11. Filesystem Configuration

### 11.1 Mount Analysis

| Mount Point | Separate Partition | noexec | nosuid | nodev |
|-------------|-------------------|--------|--------|-------|
| /tmp | Yes (tmpfs 2G) | Yes | Yes | Yes |
| /dev/shm | N/A (tmpfs) | Yes | Yes | Yes |
| /boot | Yes | No | No | No |
| /run | N/A (tmpfs) | No | Yes | Yes |

**CIS Impact:** Controls 1.1.2.x for /tmp and /dev/shm are satisfied.

### 11.2 USB Storage

Module status: **Disabled** via modprobe configuration

**CIS Impact:** Control 1.1.1.9 already satisfied.

---

## 12. Logging Configuration

**Rsyslog:** Active with proper configuration

| Log | Status |
|-----|--------|
| auth.log | Active |
| syslog | Active |
| kern.log | Active |
| audit/audit.log | Active |

---

## 13. Lynis Security Audit

**Hardening Index:** 62 / 100

### Warnings (2)

| ID | Description |
|----|-------------|
| MAIL-8818 | SMTP banner information disclosure |
| FIRE-4512 | iptables modules loaded but no rules active |

### Key Suggestions (35 total)

| Category | Items |
|----------|-------|
| Security Tools | Install fail2ban, libpam-tmpdir, apt-listbugs |
| SSH Hardening | ClientAliveCountMax, MaxSessions, Port |
| Kernel | Several sysctl values differ from profile |
| Banners | Legal banners needed for /etc/issue |

---

## 14. CIS Controls Gap Analysis

### Already Compliant (L1 Controls)

| CIS ID | Description | Status |
|--------|-------------|--------|
| 1.1.1.9 | USB storage disabled | ✓ |
| 1.1.2.1.4 | noexec on /tmp | ✓ |
| 1.5.1 | ASLR enabled | ✓ |
| 1.5.2 | ptrace_scope restricted | ✓ |
| 1.5.3 | Core dumps restricted | ✓ |
| 3.3.1 | IP forwarding disabled | ✓ |
| 3.3.2 | Packet redirect disabled | ✓ |
| 3.3.3 | ICMP redirects rejected | ✓ |
| 4.3.x | nftables configuration | ✓ |

### Controls Requiring Attention

| CIS ID | Description | Status |
|--------|-------------|--------|
| 1.3.1.4 | AppArmor all enforce mode | Partial (7 unconfined) |
| 5.1.x | SSH hardening | ❌ |
| 3.3.9 | Log martian packets | ❌ |

---

## 15. Recommendations

Based on the CIS Benchmark v1.0.0 and this project's scope:

1. **Install security tools:**
   - fail2ban for brute-force protection
   - chkrootkit and rkhunter for rootkit scanning
   - libpam-tmpdir, apt-listchanges, debsums

2. **SSH hardening:**
   - Configure MaxAuthTries, ClientAliveInterval
   - Disable PermitRootLogin, X11Forwarding
   - Set strong ciphers and MACs

3. **AppArmor:**
   - Move remaining 7 profiles to enforce mode

4. **Kernel hardening:**
   - Enable log_martians
   - Increase ptrace_scope to 2

5. **Legal banners:**
   - Configure /etc/issue and /etc/issue.net

---

*Report generated from initial_logs collected on December 25, 2025 at 11:20 UTC*
