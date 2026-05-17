# Negative: Account/Auth Setuid and Setgid Edge Helpers

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server default package state.

Result: no valid `uid=1001(attacker)` to root local privilege escalation was found in the bounded account/auth helper surface.

## Surface

Audited helpers:

```text
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/sudo
/usr/bin/chage
/usr/bin/expiry
/usr/sbin/unix_chkpwd
/usr/sbin/pam_extrausers_chkpwd
/usr/lib/polkit-1/polkit-agent-helper-1
```

Default reachability is real: the first seven are setuid root, `chage`/`expiry`/`unix_chkpwd`/`pam_extrausers_chkpwd` are setgid `shadow`, and `polkit-agent-helper-1` is setuid root. The attacker user is only in its private group and is not in `sudo`, `adm`, `lxd`, `docker`, `shadow`, or `root`.

Affected package versions from the target:

```text
passwd                    1:4.13+dfsg1-4ubuntu3.2
login                     1:4.13+dfsg1-4ubuntu3.2
util-linux                2.39.3-9ubuntu6.5
sudo                      1.9.15p5-3ubuntu5.24.04.2
polkitd                   124-2ubuntu1.24.04.3
libpam-modules:arm64      1.5.3-5ubuntu5.5
libpam-modules-bin        1.5.3-5ubuntu5.5
```

## Tested trust boundaries

Reusable probe:

```sh
/Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe/pocs/authhelpers_probe.sh ubuntu24-server-lpe-target
```

The probe was syntax checked with `bash -n` and run live against the target. Helper invocations are wrapped with `timeout`; credential-required paths were treated as negative unless they produced root execution without credentials.

Tested candidates:

```text
chfn GECOS newline injection in full name and allowed room/work/home fields
chfn colon/control separator injection
chsh newline and attacker-controlled shell path injection
passwd/chage privileged account mutation against root
gpasswd privileged group mutation against root/shadow
newgrp privileged group entry
su root command execution with hostile PATH/SHELL/env
sudo root command execution and askpass with no sudoers rights
direct unix_chkpwd and pam_extrausers_chkpwd invocation
direct polkit-agent-helper-1 invocation
shadow-utils --root/chroot redirection into attacker-controlled trees
attacker-controlled account-file symlinks inside --root trees
attempts to pre-place /etc passwd/group lock or swap-file symlinks
hostile PATH/EDITOR/VISUAL/PAGER/SUDO_ASKPASS/GCONV_PATH/CHARSET propagation
```

Key negative results:

```text
chfn -f with newline payload: Permission denied
chfn -r with newline payload: PAM authentication failure
chfn -w with colon payload: PAM authentication failure
chsh newline shell payload: PAM authentication failure
chsh attacker path shell: PAM authentication failure
passwd -d root: Permission denied
gpasswd -a attacker root: Permission denied
gpasswd -M attacker root: Permission denied
newgrp shadow: Invalid password
su root: Authentication failure
sudo: no password / incorrect password; no sudoers authorization
chage -E -1 root: Permission denied
polkit-agent-helper-1 attacker cookie: FAILURE
unix_chkpwd / pam_extrausers_chkpwd direct calls: failure only
```

The `--root` path was the most interesting candidate. If any setuid helper accepted an attacker-controlled chroot before dropping privilege, it could expose attacker-controlled account files, NSS, or PAM modules to a root process. In this target all tested variants failed before entering the tree:

```text
chfn -R /home/attacker/authhelpers_probe/chroot ...: Operation not permitted
chsh -R /home/attacker/authhelpers_probe/chroot ...: Operation not permitted
passwd -R /home/attacker/authhelpers_probe/chroot ...: Operation not permitted
gpasswd -Q /home/attacker/authhelpers_probe/chroot ...: Operation not permitted
chage -R /home/attacker/authhelpers_probe/chroot ...: Operation not permitted
```

Symlink/race attempts also did not produce a write primitive. Attacker-created account-file symlinks inside the fake chroot were not reached because `--root` failed first, and direct `/etc` lock/swap symlink placement failed with `Permission denied` except for `/etc/.pwd.lock`, which already exists and is not attacker-controlled.

## Integrity proof

The probe hashed `/etc/passwd`, `/etc/shadow`, `/etc/group`, and `/etc/gshadow` before and after all triggers. The hashes matched:

```text
account_files_unchanged=yes
root_env_marker=absent
root_symlink_marker=absent
attacker_env_helper_marker=absent
cleanup_leftovers=0
```

No command produced root execution, no root-owned marker was created, and no account/group database changed.

## Cleanup

The probe removes:

```text
/home/attacker/authhelpers_probe
/tmp/authhelpers_env_marker
/tmp/authhelpers_fake_executed
/root/authhelpers_env_marker
/root/authhelpers_symlink_escape
```

Post-run cleanup check returned `cleanup_leftovers=0`.

## Conclusion

This surface is default-installed and locally reachable, but I did not validate a privilege increase. The reachable behavior remained confined to authentication failure, policy denial, read-only self-status/listing, or blocked chroot/symlink setup. No PoC for LPE was produced because the surface was negative.
