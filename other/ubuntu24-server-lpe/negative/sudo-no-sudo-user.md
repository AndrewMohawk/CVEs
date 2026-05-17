# Negative: sudo no-sudo-user pre-auth surfaces

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server default.

Result: no root proof. A normal `attacker` user outside `sudo`, `admin`, `adm`, `lxd`, `docker`, `shadow`, and `root` could not turn default `sudo` 1.9.15p5 pre-auth or partial-privilege behavior into root execution.

## Evidence

Reusable probe and captured log:

```sh
bash -n pocs/sudo_no_sudo_user_probe.sh
./pocs/sudo_no_sudo_user_probe.sh ubuntu24-server-lpe-target | tee logs/sudo-no-sudo-user.out
```

Package and backport state from the target:

```text
sudo  1.9.15p5-3ubuntu5.24.04.2
libc6:arm64  2.39-0ubuntu8.7
libpam-modules:arm64  1.5.3-5ubuntu5.5
SECURITY UPDATE: Local Privilege Escalation via host option
CVE-2025-32462
SECURITY UPDATE: Local Privilege Escalation via chroot option
CVE-2025-32463
```

Default mode and policy:

```text
-rwsr-xr-x 4755 root root /usr/bin/sudo
-rwsr-xr-x 4755 root root /usr/bin/sudoedit
-r--r----- 440 root root /etc/sudoers
drwxr-xr-x 755 root root /etc/sudoers.d
root ALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
%sudo ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d
```

Attacker boundary:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
attacker_group_boundary=ok_not_privileged
```

## Tested boundaries

The bounded pass covered:

```text
sudo -k/-l/-ll/-v command paths with no password
sudo -e and sudoedit editor selection with hostile EDITOR/VISUAL/SUDO_EDITOR/PATH
SUDO_ASKPASS with a fake badpass helper
hostile PATH command lookup before authorization
locale/gconv environment variables
attacker-controlled chroot tree for recent -R/chroot/NSS-style parser paths
chdir/chroot/runas parser handling, including numeric root and invalid uid forms
host option list paths for CVE-2025-32462-style behavior
sudoers include/stat behavior and attacker write/symlink attempts under /etc/sudoers.d
timestamp, lecture, and log path creation state
```

Key denials:

```text
sudo -n -l: sudo: a password is required
sudo -n -ll: sudo: a password is required
sudo -n -v: Sorry, user attacker may not run sudo on 4f5b414436ae.
sudo -n /usr/bin/id: sudo: a password is required
sudo -e -n /etc/hosts: sudo: a password is required
sudoedit -n /etc/hosts: sudoedit: a password is required
sudo -R attacker_chroot -n -l: sudo: a password is required
sudo -R attacker_chroot -n /usr/bin/id: sudo: a password is required
sudo -D attacker_dir -n /usr/bin/id: sudo: a password is required
sudo -u#-1 -n /usr/bin/id: sudo: unknown user #-1
sudo -u#4294967295 -n /usr/bin/id: sudo: unknown user #4294967295
sudo -h not-the-host -n -l: unable to resolve host; then password required
touch /etc/sudoers.d/00-sudo-no-sudo-user-probe: Permission denied
ln -s attacker_sudoers /etc/sudoers.d/00-sudo-no-sudo-user-probe: Permission denied
```

The only attacker-controlled helper that executed was fake `SUDO_ASKPASS`, and it ran unprivileged:

```text
fake_askpass real=1001 effective=1001 args=[sudo] password for attacker:
sudo: 3 incorrect password attempts
```

Root markers stayed absent:

```text
absent /root/sudo_no_sudo_user_root_marker
absent /root/sudo_no_sudo_user_editor_marker
absent /root/sudo_no_sudo_user_askpass_marker
absent /root/sudo_no_sudo_user_path_marker
absent /root/sudo_no_sudo_user_chroot_marker
absent /root/sudo_no_sudo_user_nss_marker
absent /root/sudo_no_sudo_user_gconv_marker
root_proof=no
```

Timestamp and lecture state did not create attacker credentials:

```text
absent /run/sudo/ts/attacker
absent /var/lib/sudo/lectured/attacker
```

Cleanup and systemd health:

```text
cleanup_leftovers=absent
systemctl is-system-running: running
systemctl --failed --no-legend: no output
```

## Conclusion

No LPE was validated for the default updated Ubuntu 24.04 Server `sudo` package from a normal user with no sudo/admin group membership and no password. The reachable behavior stayed at password requirement, sudoers denial, parser rejection, unprivileged askpass execution, or filesystem permission denial. No PoC for root escalation was produced.
