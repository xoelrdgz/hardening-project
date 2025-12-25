# CIS Ubuntu 24.04 LTS Hardening - Ansible Role

**Version**: 1.0.0

Professional Ansible implementation of CIS Benchmark controls for Ubuntu Server 24.04 LTS.

## Features

- **True Idempotency**: Uses native Ansible modules (`ansible.posix.mount`, `ansible.posix.sysctl`, `community.general.pam_limits`, `template`, etc.) instead of shell commands
- **Ansible Vault Integration**: All secrets (GRUB password) stored encrypted
- **Level 1 & Level 2 Profiles**: Separate variable files for different security requirements
- **Handler-Based Reboot Notifications**: Detects changes requiring reboot without forcing it
- **Safety Checks**: Audit immutable mode includes pre-flight safety validations

## Requirements

- Ansible >= 2.14
- Target: Ubuntu Server 24.04 LTS
- Python 3 on target hosts
- Collections:
  ```bash
  ansible-galaxy collection install -r requirements.yml
  ```

## Quick Start

### 1. Install Dependencies

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml
```

### 2. Configure GRUB Password (Vault)

Generate a GRUB password hash:

```bash
grub-mkpasswd-pbkdf2 --iteration-count=600000
```

Create/edit the vault file:

```bash
ansible-vault create group_vars/all/vault.yml
# Or edit existing:
ansible-vault edit group_vars/all/vault.yml
```

Add the hash:

```yaml
cis_grub_password_hash: "grub.pbkdf2.sha512.600000.YOUR_HASH_HERE..."
```

### 3. Configure Inventory

Edit `inventories/production`:

```ini
[level1_servers]
web-server-01 ansible_host=192.168.1.10

[level2_servers]
secure-server-01 ansible_host=192.168.1.100
```

### 4. Run the Playbook

```bash
# Audit mode (check without changes)
ansible-playbook site.yml --check --diff --ask-vault-pass

# Apply Level 1 hardening
ansible-playbook site.yml --ask-vault-pass

# Apply Level 2 hardening
ansible-playbook site.yml -e "cis_level=2" --ask-vault-pass

# Target specific hosts
ansible-playbook site.yml --limit web-server-01 --ask-vault-pass
```

## Directory Structure

```
ansible/
├── ansible.cfg                 # Ansible configuration
├── requirements.yml            # Collection dependencies
├── site.yml                    # Main playbook
├── inventories/
│   └── production              # Production inventory
├── group_vars/
│   ├── all/
│   │   ├── main.yml            # Global variables
│   │   └── vault.yml           # Encrypted secrets (Vault)
│   └── level2_servers.yml      # Level 2 specific vars
├── host_vars/                  # Per-host variables
└── roles/
    └── cis_hardening/
        ├── defaults/main.yml   # Default variables
        ├── vars/
        │   ├── level1.yml      # Level 1 profile
        │   └── level2.yml      # Level 2 profile
        ├── tasks/
        │   ├── main.yml
        │   ├── section1_filesystem.yml
        │   ├── section1_apparmor.yml
        │   ├── section1_bootloader.yml
        │   ├── section1_kernel.yml
        │   ├── section3_network.yml
        │   ├── section5_authentication.yml
        │   ├── section6_logging.yml
        │   ├── section6_audit.yml
        │   └── section6_aide.yml
        ├── handlers/main.yml   # Service handlers
        ├── templates/
        │   ├── grub_40_custom.j2
        │   ├── sysctl_hardening.conf.j2
        │   ├── sysctl_network.conf.j2
        │   ├── compliance_report.j2
        │   └── audit_rules/
        │       ├── 50-time-change.rules.j2
        │       ├── 50-identity.rules.j2
        │       ├── 50-mounts.rules.j2
        │       ├── 50-perm_chng.rules.j2
        │       └── 99-finalize.rules.j2
        └── meta/main.yml       # Role metadata
```

## CIS Controls Implemented

### Level 1 Controls (All Servers)

| Control | Description | Module Used |
|---------|-------------|-------------|
| 1.1.1.9 | Disable USB storage | `lineinfile`, `modprobe` |
| 1.1.2.1.1 | /tmp separate partition | `ansible.posix.mount` |
| 1.1.2.1.4 | noexec on /tmp | `ansible.posix.mount` |
| 1.1.2.2.4 | noexec on /dev/shm | `ansible.posix.mount` |
| 1.3.1.2 | AppArmor bootloader | `lineinfile`, `template` |
| 1.4.1 | GRUB password | `template` + Vault |
| 1.4.2 | GRUB config permissions | `file` |
| 1.5.1 | ASLR enabled | `ansible.posix.sysctl` |
| 1.5.2 | ptrace_scope | `ansible.posix.sysctl` |
| 1.5.3 | Core dumps restricted | `pam_limits`, `sysctl` |
| 1.6.1.4 | MOTD access | `template`, `file` |
| 2.1.1 | autofs disabled | `systemd` |
| 2.1.21 | MTA local-only | `lineinfile` |
| 2.2.4 | Telnet removed | `apt` |
| 3.1.2 | Wireless disabled | `lineinfile`, `command` |
| 3.3.x | Network parameters | `ansible.posix.sysctl` |
| 4.3.x | nftables firewall | `template`, `systemd` |
| 5.1.x | SSH hardening | `template` |
| 5.2.x | Sudo configuration | `lineinfile` |
| 5.3.x | PAM password policies | `lineinfile`, `apt` |
| 5.4.1.4 | SHA512 passwords | `lineinfile` |
| 5.4.1.5 | Inactive password lock | `command` (useradd -D) |
| 5.4.2.1 | Root only UID 0 | Validation only |
| 6.1.3.4 | rsyslog permissions | `lineinfile` |
| 6.2.1.2 | auditd enabled | `systemd` |
| 6.2.2.3 | Disk full action | `lineinfile` |
| 6.2.3.x | Audit rules | `template` |
| 6.3.1 | AIDE installed | `apt`, `cron` |

### Level 2 Controls (High Security)

| Control | Description | Notes |
|---------|-------------|-------|
| 1.3.1.4 | AppArmor enforce all | All profiles in enforce mode |
| 6.2.3.20 | Audit immutable | **CAUTION**: Requires reboot to modify |

## Variable Profiles

### Level 1 (Default)

```yaml
cis_level: 1
cis_audit_immutable: false
cis_apparmor_enforce_all: false
```

### Level 2 (High Security)

```yaml
cis_level: 2
cis_audit_immutable: true
cis_apparmor_enforce_all: true
cis_sysctl_settings:
  kernel.yama.ptrace_scope: 2  # admin-only
```

## Handlers and Reboot Management

The role uses handlers to manage service restarts and reboot notifications:

```yaml
handlers:
  - notify reboot required    # Sets flag, doesn't force reboot
  - update grub               # Runs update-grub
  - reload sysctl             # Applies kernel parameters
  - restart rsyslog           # Restarts logging
  - restart auditd            # Restarts audit daemon
  - reload audit rules        # Loads new audit rules
```

**Reboot is NEVER forced automatically.** Check the compliance report or `/var/run/reboot-required` after the run.

## Safety Checks for Audit Immutable Mode

Before enabling audit immutable mode (`-e 2`), the role validates:

1. **Disk Space**: ≥ 20% free on audit log partition
2. **Log Rotation**: `max_log_file_action = rotate` configured
3. **Rules Loaded**: At least 5 audit rules active

To bypass (NOT RECOMMENDED):

```yaml
cis_audit_immutable_safety_checks: false
```

## Vault Management

### Encrypt the vault file

```bash
ansible-vault encrypt group_vars/all/vault.yml
```

### Edit encrypted vault

```bash
ansible-vault edit group_vars/all/vault.yml
```

### Use a password file

```bash
echo "your-vault-password" > ~/.vault_pass
chmod 600 ~/.vault_pass
ansible-playbook site.yml --vault-password-file ~/.vault_pass
```

## Tags

Run specific sections:

```bash
# Only filesystem hardening
ansible-playbook site.yml --tags filesystem

# Only audit rules
ansible-playbook site.yml --tags audit

# Skip AIDE initialization (slow)
ansible-playbook site.yml --skip-tags aide
```

Available tags:
- `section1`, `section3`, `section5`, `section6`
- `filesystem`, `apparmor`, `bootloader`, `kernel`, `network`
- `authentication`, `pam`
- `logging`, `rsyslog`, `audit`, `auditd`, `aide`, `integrity`

## License

MIT

## Author

xoelrdgz
