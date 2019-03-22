# GRUB2 installation and configuration

Configures the GRUB2 bootloader for compliance with SELinux and auditd
requirements. Also, [password-protects](https://access.redhat.com/solutions/2253401) the bootloader
to prevent unauthorised users from forcing single-user mode and dropping to a root
shell.

## Requirements

None. The required packages are managed by the role.

## Role Variables

- From `defaults/main.yml`

```yml
# Update the grub configuration.
security_enable_grub_update: 'yes'
# Require authentication in GRUB to boot into single-user or maintenance modes.
security_require_grub_authentication: 'yes'                   # V-71961 / V-71963
# Password should be stored in a vault
security_grub_password: "{{ vault_security_grub_password }}"
```

- From `vars/main.yml`

```yml
# grub main linux configuration
grub_linux_file: /etc/grub.d/10_linux
grub_conf_dir: '/boot/grub2'
grub_conf_dir_efi: "/boot/efi/EFI/{{ ansible_distribution | lower | replace(' ', '') }}"
# Commands
grub_update_cmd: "/usr/sbin/grub2-mkconfig -o {{ grub_config_dir }}/grub.cfg"
```

## Dependencies

This role depends on `ansible-os-hardening-audit` and `ansible-os-hardening-selinux`.

## Example Playbook

Example of how to use this role:

```yml
    - hosts: servers
      roles:
         - { role: ansible-os-hardening-grub2 }
```

## License

Apache 2.0, as this work is derived from [OpenStack's ansible-hardening role](https://github.com/openstack/ansible-hardening).

## Author Information

[David Sastre](david.sastre@redhat.com)
