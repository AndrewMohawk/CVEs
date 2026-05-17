# Auth Helper Evidence - 2026-05-16

Target: `ubuntu24-server-lpe-target`

Scope owner: account/auth setuid and setgid helpers only.

## Default target proof

Ubuntu release:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_CODENAME=noble
```

Default server metapackages:

```text
ubuntu-minimal  1.539.2
ubuntu-standard 1.539.2
ubuntu-server   1.539.2
```

Attacker:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
sudo:x:27:ubuntu
adm:x:4:ubuntu,syslog
lxd:x:101:
shadow:x:42:
root:x:0:
```

The attacker is not in `sudo`, `adm`, `lxd`, `docker`, `shadow`, or `root`.

## Package and mode proof

Owning packages:

```text
passwd: /usr/bin/chage
passwd: /usr/bin/chfn
passwd: /usr/bin/chsh
passwd: /usr/bin/expiry
passwd: /usr/bin/gpasswd
passwd: /usr/bin/passwd
login: /usr/bin/newgrp
util-linux: /usr/bin/su
sudo: /usr/bin/sudo
libpam-modules-bin: /usr/sbin/unix_chkpwd
libpam-modules-bin: /usr/sbin/pam_extrausers_chkpwd
polkitd: /usr/lib/polkit-1/polkit-agent-helper-1
```

Versions:

```text
passwd                    1:4.13+dfsg1-4ubuntu3.2
login                     1:4.13+dfsg1-4ubuntu3.2
util-linux                2.39.3-9ubuntu6.5
sudo                      1.9.15p5-3ubuntu5.24.04.2
polkitd                   124-2ubuntu1.24.04.3
libpam-modules:arm64      1.5.3-5ubuntu5.5
libpam-modules-bin        1.5.3-5ubuntu5.5
```

Default modes:

```text
-rwsr-xr-x 4755 root root   /usr/bin/chfn
-rwsr-xr-x 4755 root root   /usr/bin/chsh
-rwsr-xr-x 4755 root root   /usr/bin/passwd
-rwsr-xr-x 4755 root root   /usr/bin/gpasswd
-rwsr-xr-x 4755 root root   /usr/bin/newgrp
-rwsr-xr-x 4755 root root   /usr/bin/su
-rwsr-xr-x 4755 root root   /usr/bin/sudo
-rwxr-sr-x 2755 root shadow /usr/bin/chage
-rwxr-sr-x 2755 root shadow /usr/bin/expiry
-rwxr-sr-x 2755 root shadow /usr/sbin/unix_chkpwd
-rwxr-sr-x 2755 root shadow /usr/sbin/pam_extrausers_chkpwd
-rwsr-xr-x 4755 root root   /usr/lib/polkit-1/polkit-agent-helper-1
```

Account/config file modes:

```text
-rw-r--r-- 644 root root   /etc/passwd
-rw-r----- 640 root shadow /etc/shadow
-rw-r--r-- 644 root root   /etc/group
-rw-r----- 640 root shadow /etc/gshadow
-r--r----- 440 root root   /etc/sudoers
-rw-r--r-- 644 root root   /etc/login.defs
-rw-r--r-- 644 root root   /etc/shells
```

## Config anchors

`/etc/login.defs`:

```text
102 ENV_SUPATH PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
103 ENV_PATH   PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
214 CHFN_RESTRICT rwh
238 USERGROUPS_ENAB yes
295 ENCRYPT_METHOD SHA512
```

`/etc/shells`:

```text
2 /bin/sh
3 /usr/bin/sh
4 /bin/bash
5 /usr/bin/bash
6 /bin/rbash
7 /usr/bin/rbash
8 /usr/bin/dash
9 /usr/bin/screen
10 /usr/bin/tmux
```

`/etc/sudoers`:

```text
9  Defaults env_reset
10 Defaults mail_badpass
11 Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
47 root ALL=(ALL:ALL) ALL
53 %sudo ALL=(ALL:ALL) ALL
57 @includedir /etc/sudoers.d
```

PAM anchors:

```text
/etc/pam.d/chfn:7   auth sufficient pam_rootok.so
/etc/pam.d/chfn:12  @include common-auth
/etc/pam.d/chsh:8   auth required pam_shells.so
/etc/pam.d/chsh:12  auth sufficient pam_rootok.so
/etc/pam.d/passwd:5 @include common-password
/etc/pam.d/su:6     auth sufficient pam_rootok.so
/etc/pam.d/su:57    @include common-auth
/etc/pam.d/sudo:6   session required pam_env.so readenv=1 user_readenv=0
/etc/pam.d/sudo:9   @include common-auth
/etc/pam.d/common-auth:17     auth [success=1 default=ignore] pam_unix.so nullok
/etc/pam.d/common-password:25 password [success=1 default=ignore] pam_unix.so obscure yescrypt
```

## Probe run

Command:

```sh
bash -n /Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe/pocs/authhelpers_probe.sh
/Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe/pocs/authhelpers_probe.sh ubuntu24-server-lpe-target
```

All helper invocations in the probe use `timeout`; password prompts are fed bounded input or allowed to fail under timeout. Per the updated constraint, password-required behavior is negative unless it yields root without credentials.

Selected live results:

```text
chfn newline full-name injection: chfn: Permission denied.
chfn newline allowed room-field injection: chfn: PAM: Authentication failure
chfn colon allowed work-phone field injection: chfn: PAM: Authentication failure
chfn disallowed other-field blocked: chfn: Permission denied.
chsh newline shell injection: chsh: PAM: Authentication failure
chsh unlisted attacker path: chsh: PAM: Authentication failure
passwd root delete denied: passwd: Permission denied.
passwd attacker status only: attacker L 2026-05-16 0 99999 7 -1
gpasswd add attacker to root denied: gpasswd: Permission denied.
gpasswd member-list overwrite denied: gpasswd: Permission denied.
newgrp privileged group denied: Invalid password.
su root denied with hostile env: su: Authentication failure
sudo no rights with hostile env: 1 incorrect password attempt
sudo askpass no rights: sudo: a password is required
chage root write denied: chage: Permission denied.
polkit helper direct bad cookie: FAILURE
unix_chkpwd direct: -1
unix_chkpwd newline user: -1, rc=10
pam_extrausers_chkpwd direct: -1
```

The `--root`/chroot redirection path was tested because it would be a serious trust-boundary bug if a setuid helper accepted an attacker-controlled root and then loaded attacker-controlled NSS/PAM/account files:

```text
chfn -R /home/attacker/authhelpers_probe/chroot ...: Operation not permitted, rc=3
chsh -R /home/attacker/authhelpers_probe/chroot ...: Operation not permitted, rc=3
passwd -R /home/attacker/authhelpers_probe/chroot ...: Operation not permitted, rc=3
gpasswd -Q /home/attacker/authhelpers_probe/chroot ...: Operation not permitted, rc=3
chage -R /home/attacker/authhelpers_probe/chroot ...: Operation not permitted, rc=3
```

Account-file symlink/race setup was blocked:

```text
chfn --root symlink passwd denied before account-file write: Operation not permitted
gpasswd --root symlink group denied before account-file write: Operation not permitted
ln -s /root/authhelpers_symlink_escape /etc/passwd.lock: Permission denied
ln -s /root/authhelpers_symlink_escape /etc/passwd+: Permission denied
ln -s /root/authhelpers_symlink_escape /etc/group+: Permission denied
ln -s /root/authhelpers_symlink_escape /etc/gshadow+: Permission denied
```

Integrity and marker results:

```text
account_files_unchanged=yes
root_env_marker=absent
root_symlink_marker=absent
attacker_env_helper_marker=absent
cleanup_leftovers=0
```

The before and after SHA-256 hashes for `/etc/passwd`, `/etc/shadow`, `/etc/group`, and `/etc/gshadow` matched exactly.
