# CIS Hardening Results Report

**Project:** CIS Hardening for Ubuntu Server 24.04 LTS  
**Version:** 1.0.0  
**Author:** xoelrdgz  
**Date:** December 25, 2025  
**Hostname:** ubuntu  

---

## 1. Executive Summary

This report documents the results of applying CIS Benchmark v1.0.0 hardening controls to an Ubuntu 24.04.3 LTS server. The hardening scripts and Ansible playbooks successfully remediated multiple security gaps identified in the initial state assessment. The Lynis security audit score improved from **62 to 84** (+22 points), reflecting a significantly stronger security posture suitable for production environments.

**Overall Results:**

| Metric | Value |
|--------|-------|
| Lynis Score (Before) | 62/100 |
| Lynis Score (After) | 84/100 |
| Improvement | +22 points |
| Warnings Reduced | 35 → 23 suggestions |
| Security Tools Installed | 7 new tools |
| AppArmor Unconfined | 7 → 0 profiles |

---

## 2. Kernel Security Parameters

### 2.1 Parameters Changed

| Parameter | Initial Value | Post-Hardening | CIS Control | Status |
|-----------|---------------|----------------|-------------|--------|
| kernel.yama.ptrace_scope | 1 | 2 | 1.5.2 | FIXED |
| net.ipv4.conf.all.log_martians | 0 | 1 | 3.3.9 | FIXED |
| net.ipv4.conf.default.log_martians | 0 | 1 | 3.3.9 | FIXED |
| net.ipv4.conf.all.secure_redirects | 1 | 0 | 3.3.5 | FIXED |
| net.ipv4.conf.default.accept_source_route | 1 | 0 | 3.3.x | FIXED |
| net.ipv4.tcp_rfc1337 | 0 | 1 | - | FIXED |
| kernel.kptr_restrict | 1 | 2 | - | FIXED |
| kernel.sysrq | 176 | 0 | - | FIXED |
| kernel.unprivileged_bpf_disabled | 2 | 1 | - | FIXED |
| kernel.perf_event_paranoid | 4 | 3 | - | FIXED |
| fs.protected_fifos | 1 | 2 | - | FIXED |
| net.ipv6.conf.all.accept_ra | 1 | 0 | - | FIXED |
| net.ipv6.conf.default.accept_ra | 1 | 0 | - | FIXED |

### 2.2 Parameters Already Compliant

| Parameter | Value | CIS Control |
|-----------|-------|-------------|
| kernel.randomize_va_space | 2 | 1.5.1 |
| fs.suid_dumpable | 0 | 1.5.3 |
| net.ipv4.ip_forward | 0 | 3.3.1 |
| net.ipv4.tcp_syncookies | 1 | 3.3.10 |
| net.ipv4.icmp_echo_ignore_broadcasts | 1 | 3.3.4 |
| net.ipv4.conf.all.send_redirects | 0 | 3.3.2 |
| net.ipv4.conf.all.accept_redirects | 0 | 3.3.3 |
| net.ipv6.conf.all.accept_redirects | 0 | 3.3.3 |

---

## 3. AppArmor Configuration

### 3.1 Profile Status Comparison

| Metric | Initial | Post-Hardening | Change |
|--------|---------|----------------|--------|
| Profiles Loaded | 119 | 119 | - |
| Profiles in Enforce Mode | 112 | 119 | +7 |
| Profiles in Complain Mode | 0 | 0 | - |
| Profiles in Unconfined Mode | 7 | 0 | -7 |

### 3.2 Profiles Moved to Enforce Mode

The following profiles were converted from unconfined to enforce mode:
- lxc-attach
- lxc-create
- lxc-destroy
- lxc-execute
- lxc-stop
- lxc-unshare
- lxc-usernsexec

### 3.3 GRUB Configuration

| Setting | Status |
|---------|--------|
| AppArmor in GRUB | `apparmor=1 security=apparmor` |

**CIS Control 1.3.1.2:** PASSED - AppArmor configured at boot  
**CIS Control 1.3.1.4:** PASSED - All profiles now in enforce mode

---

## 4. SSH Server Hardening

### 4.1 Configuration Changes (CIS 5.1.x)

| Parameter | Initial Value | Post-Hardening | CIS Control |
|-----------|---------------|----------------|-------------|
| MaxAuthTries | 6 (default) | 3 | 5.1.6 |
| ClientAliveInterval | 0 (default) | 300 | 5.1.7 |
| ClientAliveCountMax | 3 (default) | 3 | 5.1.7 |
| PermitRootLogin | default (yes) | no | 5.1.20 |
| X11Forwarding | yes | no | 5.1.x |
| PermitEmptyPasswords | default | no | 5.1.x |
| HostbasedAuthentication | default | no | 5.1.x |
| IgnoreRhosts | default | yes | 5.1.x |
| LoginGraceTime | default | 60 | 5.1.x |
| LogLevel | default | VERBOSE | 5.1.x |
| AllowTcpForwarding | default | no | 5.1.x |
| AllowAgentForwarding | default | no | 5.1.x |
| StrictModes | default | yes | 5.1.x |
| MaxSessions | default | 10 | 5.1.x |
| MaxStartups | default | 10:30:60 | 5.1.x |
| Banner | none | /etc/issue.net | 5.1.x |

### 4.2 Cryptographic Settings

```
Ciphers: aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs: hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
```

---

## 5. Firewall Configuration

### 5.1 nftables Implementation (CIS 4.3.x)

**Initial State:** Basic nftables ruleset  
**Post-Hardening:** Enhanced nftables ruleset with SSH rate limiting

```
table inet filter {
    set ssh_limit {
        type ipv4_addr
        size 65535
        flags dynamic,timeout
        timeout 1m
    }

    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop
        iif "lo" accept
        iif != "lo" ip daddr 127.0.0.0/8 drop
        ip protocol icmp icmp type { echo-reply, destination-unreachable, echo-request, time-exceeded, parameter-problem } accept
        tcp dport 22 ct state new add @ssh_limit { ip saddr limit rate 4/minute burst 8 packets } accept
        tcp dport 22 ct state new drop
        limit rate 5/minute burst 10 packets log prefix "nftables-dropped-input: " level info
        counter drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        limit rate 1/minute burst 5 packets log prefix "nftables-forward: "
        counter drop
    }

    chain output {
        type filter hook output priority filter; policy accept;
        counter accept
    }
}

table ip6 filter {
    chain input { type filter hook input priority filter; policy drop; }
    chain forward { type filter hook forward priority filter; policy drop; }
    chain output { type filter hook output priority filter; policy drop; }
}
```

### 5.2 Firewall Features

- Default DROP policy on INPUT and FORWARD chains
- Stateful connection tracking enabled
- SSH rate limiting (4/minute per IP with burst of 8)
- IPv6 traffic blocked by default
- Logging of dropped packets
- Loopback traffic allowed, spoofed loopback blocked
- ICMP essential types allowed

---

## 6. Security Tools Installed

### 6.1 New Tools Added

| Tool | Purpose | Status |
|------|---------|--------|
| fail2ban | Brute-force protection | Installed with jail.local |
| chkrootkit | Rootkit scanner | Installed |
| rkhunter | Rootkit Hunter | Installed |
| libpam-tmpdir | PAM session temp directories | Installed and Enabled |
| apt-listchanges | APT change notifications | Installed and enabled |
| debsums | Package integrity verification | Installed with cron job |
| AIDE | File integrity monitoring | Installed with database |

### 6.2 fail2ban Configuration

- SSH jail enabled
- Integration with nftables (banaction = nftables)
- Custom jail.local configured

---

## 7. Lynis Audit Comparison

### 7.1 Score Improvement

| Metric | Initial | Post-Hardening | Change |
|--------|---------|----------------|--------|
| Hardening Index | 62 | 84 | +22 |
| Tests Performed | 265 | 268 | +3 |
| Warnings | 2 | 2 | - |
| Suggestions | 35 | 23 | -12 |

### 7.2 Components Status

| Component | Initial | Post-Hardening |
|-----------|---------|----------------|
| Firewall | ✓ | ✓ |
| Malware Scanner | ✗ | ✓ |
| IDS/IPS | ✗ | ✓ |
| Automation | ✗ | ✓ (Ansible) |
| Session Timeout | ✗ | ✓ |

### 7.3 Key Improvements

| Category | Before | After |
|----------|--------|-------|
| libpam-tmpdir | Not Installed | Installed and Enabled |
| fail2ban | Not Installed | Installed with jail.local |
| apt-listchanges | Not Installed | Installed and enabled |
| debsums | Not Found | Found with cron job |
| File integrity (AIDE) | Found | Found with database |
| Rootkit scanners | Not Found | chkrootkit + rkhunter |
| Session timeout | NONE | FOUND |
| Umask in login.defs | SUGGESTION | OK |
| Core dumps (systemd) | DEFAULT | DISABLED |
| Legal banners | WEAK | OK |
| Cron directories | SUGGESTION | OK |
| /etc/crontab | SUGGESTION | OK |

---

## 8. CIS Controls Summary

### 8.1 Controls Addressed

| CIS ID | Description | Status |
|--------|-------------|--------|
| 1.1.1.9 | USB storage disabled | PASSED |
| 1.1.1.10 | Unused filesystems disabled | PASSED |
| 1.1.2.1.1 | /tmp separate partition | PASSED (tmpfs) |
| 1.1.2.1.4 | noexec on /tmp | PASSED |
| 1.1.2.2.4 | noexec on /dev/shm | PASSED |
| 1.3.1.2 | AppArmor bootloader | PASSED |
| 1.3.1.4 | AppArmor profiles enforcing | PASSED |
| 1.5.1 | ASLR enabled | PASSED |
| 1.5.2 | ptrace_scope restricted | PASSED (level 2) |
| 1.5.3 | Core dumps restricted | PASSED |
| 3.3.1 | IP forwarding disabled | PASSED |
| 3.3.2 | Packet redirect disabled | PASSED |
| 3.3.3 | ICMP redirects rejected | PASSED |
| 3.3.4 | Broadcast ICMP ignored | PASSED |
| 3.3.5 | Secure redirects disabled | PASSED |
| 3.3.9 | Log martian packets | PASSED |
| 3.3.10 | TCP SYN cookies enabled | PASSED |
| 4.3.x | nftables configuration | PASSED |
| 5.1.x | SSH hardening | PASSED |
| 6.2.1.2 | auditd enabled | PASSED |

### 8.2 Remaining Suggestions

| CIS ID | Description | Notes |
|--------|-------------|-------|
| AUTH-9229 | PAM hashing rounds | Optional enhancement |
| AUTH-9282 | Account expire dates | Requires manual setup |
| FILE-6310 | /home /var partitions | Architecture decision |
| MAIL-8818 | SMTP banner | Postfix configuration |
| SSH-7408 | Port, TCPKeepAlive | Optional hardening |

---

## 9. File Permissions Improvements

### 9.1 Cron Directories

| Directory | Before | After |
|-----------|--------|-------|
| /etc/cron.d | SUGGESTION | OK |
| /etc/cron.daily | SUGGESTION | OK |
| /etc/cron.hourly | SUGGESTION | OK |
| /etc/cron.weekly | SUGGESTION | OK |
| /etc/cron.monthly | SUGGESTION | OK |
| /etc/crontab | SUGGESTION | OK |

### 9.2 Legal Banners

| File | Before | After |
|------|--------|-------|
| /etc/issue | WEAK | OK |
| /etc/issue.net | WEAK | OK |
| /etc/motd | Not checked | OK |

---

## 10. Recommendations

### 10.1 Post-Hardening Validation

1. **Verify SSH connectivity** after configuration changes
2. **Run Lynis audit** periodically to monitor score
3. **Initialize AIDE database** and run regular checks:
   ```bash
   sudo aideinit
   sudo aide --check
   ```

### 10.2 Remaining Improvements

1. **SMTP Banner:** Hide mail_name in Postfix configuration
2. **Password Hashing Rounds:** Configure in /etc/login.defs
3. **Account Expiration:** Set expire dates for password-protected accounts
4. **Compiler Access:** Consider restricting to root only

### 10.3 Ongoing Maintenance

- Review audit logs regularly: `/var/log/audit/audit.log`
- Monitor fail2ban: `fail2ban-client status sshd`
- Run rootkit scans: `sudo chkrootkit` and `sudo rkhunter --check`
- Update AIDE database after authorized system changes
- Periodically re-run hardening scripts after system updates

---

## 11. Conclusion

The CIS hardening implementation successfully improved the security posture of this Ubuntu 24.04 LTS server. Key achievements include:

- **Lynis Score:** Improved from 62 to 84 (+22 points)
- **AppArmor:** All 119 profiles now in enforce mode (7 moved from unconfined)
- **Kernel:** Enhanced ptrace_scope, log_martians, and additional hardening
- **SSH:** Comprehensive hardening with restricted ciphers and authentication
- **Firewall:** Enhanced nftables with SSH rate limiting
- **Security Tools:** 7 new tools installed (fail2ban, rootkit scanners, integrity tools)
- **Legal Banners:** Configured for /etc/issue and /etc/issue.net

The system has achieved substantial CIS compliance and is suitable for production server use.

---

*Report generated: December 25, 2025*  
*Based on comparison of initial_logs (11:20 UTC) and hardening_logs (14:50 UTC)*
