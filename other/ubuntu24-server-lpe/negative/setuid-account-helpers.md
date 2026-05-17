# Negative triage: setuid account-management helpers

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS, Docker-only userspace target after full-upgrade simulation. Attacker context: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no validated uid1001-to-root LPE in this helper slice. The account-management helpers are default-installed and setuid root, but the default attacker account is password-locked, policy/config files are root-owned, privileged group passwords are locked, `--root` chroot options do not execute as uid1001, and the one attacker-controlled helper execution path found (`newgrp` honoring `SHELL`) runs after all effective/saved root privilege and capabilities are gone.

## Current target proof

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'id; uname -a; cat /etc/os-release; dpkg-query -W passwd login libpam-modules libpam-runtime libpam0g libpolkit-agent-1-0 policykit-1 polkitd 2>/dev/null || true'
```

Result:

```text
uid=0(root) gid=0(root) groups=0(root)
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux
PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
libpam-modules:arm64	1.5.3-5ubuntu5.5
libpam-runtime	1.5.3-5ubuntu5.5
libpam0g:arm64	1.5.3-5ubuntu5.5
libpolkit-agent-1-0:arm64	124-2ubuntu1.24.04.3
login	1:4.13+dfsg1-4ubuntu3.2
passwd	1:4.13+dfsg1-4ubuntu3.2
policykit-1	
polkitd	124-2ubuntu1.24.04.3
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'apt-get -s full-upgrade 2>&1 | sed -n "1,80p"'
```

Result:

```text
Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
```

Package ownership:

```text
login: /etc/login.defs
login: /usr/bin/newgrp
passwd: /etc/pam.d/chfn
passwd: /etc/pam.d/chsh
passwd: /etc/pam.d/passwd
passwd: /usr/bin/chfn
passwd: /usr/bin/chsh
passwd: /usr/bin/gpasswd
passwd: /usr/bin/passwd
polkitd: /usr/lib/pam.d/polkit-1
polkitd: /usr/lib/polkit-1/polkit-agent-helper-1
util-linux: /etc/pam.d/su
util-linux: /usr/bin/su
```

## Default install and permissions

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'stat -c "%A %U %G %a %n" /usr/bin/chfn /usr/bin/chsh /usr/bin/passwd /usr/bin/gpasswd /usr/bin/newgrp /usr/bin/su /usr/lib/polkit-1/polkit-agent-helper-1; ls -l /etc/login.defs /etc/passwd /etc/group /etc/gshadow /etc/subuid /etc/subgid /etc/shells; ls -ld /etc/pam.d /run /run/lock /tmp /var/tmp'
```

Result:

```text
-rwsr-xr-x root root 4755 /usr/bin/chfn
-rwsr-xr-x root root 4755 /usr/bin/chsh
-rwsr-xr-x root root 4755 /usr/bin/passwd
-rwsr-xr-x root root 4755 /usr/bin/gpasswd
-rwsr-xr-x root root 4755 /usr/bin/newgrp
-rwsr-xr-x root root 4755 /usr/bin/su
-rwsr-xr-x root root 4755 /usr/lib/polkit-1/polkit-agent-helper-1
-rw-r--r-- 1 root root     832 May 16 10:22 /etc/group
-rw-r----- 1 root shadow   708 May 16 10:22 /etc/gshadow
-rw-r--r-- 1 root root   12345 Feb 22  2024 /etc/login.defs
-rw-r--r-- 1 root root    1657 May 16 10:22 /etc/passwd
-rw-r--r-- 1 root root     148 May 16 10:22 /etc/shells
-rw-r--r-- 1 root root      42 May 16 10:22 /etc/subgid
-rw-r--r-- 1 root root      42 May 16 10:22 /etc/subuid
drwxr-xr-x  1 root root 4096 May 16 10:22 /etc/pam.d
drwxr-xr-x 24 root root  720 May 16 10:54 /run
drwxrwxrwt  4 root root   80 May 16 10:56 /run/lock
drwxrwxrwt  1 root root 4096 May 16 11:02 /tmp
drwxrwxrwt  1 root root 4096 May 16 11:02 /var/tmp
```

Attacker proof:

```sh
docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'id; getent passwd attacker; getent group attacker; umask; env | sort'
```

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
attacker:x:1001:1001::/home/attacker:/bin/bash
attacker:x:1001:
0022
DEBIAN_FRONTEND=noninteractive
HOME=/home/attacker
HOSTNAME=fd448ecbc136
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
PWD=/
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
```

Shadow state for relevant users:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'awk -F: '\''$1=="root" || $1=="ubuntu" || $1=="attacker" {print $1 ":" $2 ":" $3 ":" $4 ":" $5 ":" $6 ":" $7 ":" $8 ":" $9}'\'' /etc/shadow'
```

```text
root:*:20553:0:99999:7:::
ubuntu:!:20553:0:99999:7:::
attacker:!$y$j9T$.lMGEn4aD.zRGa6IjGVAw0$PjRMOg4GtFc2rFEBQj.ThM.EOt14nKgDCjtuEgHkmSD:20589:0:99999:7:::
```

The attacker account has a locked password hash (`!` prefix), so PAM-authenticated self-service writes are not reachable from the specified starting condition.

## Config paths and line refs

Relevant `/etc/login.defs` lines:

```text
102 ENV_SUPATH	PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
103 ENV_PATH	PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
214 CHFN_RESTRICT		rwh
238 USERGROUPS_ENAB yes
295 ENCRYPT_METHOD SHA512
333 NONEXISTENT	/nonexistent
339 #GRANT_AUX_GROUP_SUBIDS yes
365 #SU_WHEEL_ONLY
376 #CHFN_AUTH
377 #CHSH_AUTH
```

PAM line refs:

```text
/etc/pam.d/chfn:7  auth sufficient pam_rootok.so
/etc/pam.d/chfn:12 @include common-auth
/etc/pam.d/chfn:13 @include common-account
/etc/pam.d/chfn:14 @include common-session

/etc/pam.d/chsh:8  auth required pam_shells.so
/etc/pam.d/chsh:12 auth sufficient pam_rootok.so
/etc/pam.d/chsh:17 @include common-auth
/etc/pam.d/chsh:18 @include common-account
/etc/pam.d/chsh:19 @include common-session

/etc/pam.d/passwd:5 @include common-password

/etc/pam.d/su:6  auth sufficient pam_rootok.so
/etc/pam.d/su:36 session required pam_env.so readenv=1
/etc/pam.d/su:39 session required pam_env.so readenv=1 envfile=/etc/default/locale
/etc/pam.d/su:57 @include common-auth
/etc/pam.d/su:58 @include common-account
/etc/pam.d/su:59 @include common-session

/usr/lib/pam.d/polkit-1:3 @include common-auth
/usr/lib/pam.d/polkit-1:4 @include common-account
/usr/lib/pam.d/polkit-1:5 @include common-password
/usr/lib/pam.d/polkit-1:6 session required pam_env.so readenv=1 user_readenv=0
/usr/lib/pam.d/polkit-1:7 session required pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
/usr/lib/pam.d/polkit-1:8 @include common-session-noninteractive
```

`/etc/shells`:

```text
1 # /etc/shells: valid login shells
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

Groups and subids:

```text
/etc/group:21 sudo:x:27:ubuntu
/etc/group:59 attacker:x:1001:
/etc/gshadow:21 sudo:*::ubuntu
/etc/gshadow:59 attacker:!::
/etc/subuid:1 ubuntu:100000:65536
/etc/subuid:2 attacker:165536:65536
/etc/subgid:1 ubuntu:100000:65536
/etc/subgid:2 attacker:165536:65536
```

## `--root` chroot options

The shadow tools expose chroot options (`chfn -R`, `chsh -R`, `passwd -R`, `gpasswd -Q`). As uid1001 they do not become attacker-selected root-context file/PAM primitives.

Command:

```sh
docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'rm -rf /tmp/account-root; mkdir -p /tmp/account-root/etc/pam.d /tmp/account-root/lib/aarch64-linux-gnu/security /tmp/account-root/home/attacker; cp /etc/passwd /tmp/account-root/etc/passwd; cp /etc/group /tmp/account-root/etc/group; cp /etc/shadow /tmp/account-root/etc/shadow 2>/dev/null || true; cp /etc/gshadow /tmp/account-root/etc/gshadow 2>/dev/null || true; cp /etc/shells /tmp/account-root/etc/shells; for c in "chfn -R /tmp/account-root -r R attacker" "chsh -R /tmp/account-root -s /bin/sh attacker" "passwd -R /tmp/account-root -S attacker" "gpasswd -Q /tmp/account-root -a attacker sudo"; do printf "RUN %s\n" "$c"; sh -c "$c" 2>&1; printf "rc=%s\n" "$?"; done; rm -rf /tmp/account-root'
```

Result:

```text
RUN chfn -R /tmp/account-root -r R attacker
chfn: unable to chroot to directory /tmp/account-root: Operation not permitted
rc=3
RUN chsh -R /tmp/account-root -s /bin/sh attacker
chsh: unable to chroot to directory /tmp/account-root: Operation not permitted
rc=3
RUN passwd -R /tmp/account-root -S attacker
passwd: unable to chroot to directory /tmp/account-root: Operation not permitted
rc=3
RUN gpasswd -Q /tmp/account-root -a attacker sudo
gpasswd: unable to chroot to directory /tmp/account-root: Operation not permitted
rc=3
```

## `chfn` / GECOS

Default reachable attempts are PAM-gated or policy-denied before any `/etc/passwd` write. Full name is explicitly denied to a regular user by `CHFN_RESTRICT rwh`; room/phone fields require PAM auth and fail because the default attacker password is locked.

Command:

```sh
docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'for c in "chfn -r Room attacker" "chfn -f Rooted attacker" "chfn -r colon:field attacker" "chfn -r comma,field attacker" "chfn -r $(printf line\\nfield) attacker" "chfn root"; do printf "RUN %s\n" "$c"; timeout 3 sh -c "$c" 2>&1; printf "rc=%s\n" "$?"; getent passwd attacker; done'
```

Result:

```text
RUN chfn -r Room attacker
Password: chfn: PAM: Authentication failure
rc=1
attacker:x:1001:1001::/home/attacker:/bin/bash
RUN chfn -f Rooted attacker
chfn: Permission denied.
rc=1
attacker:x:1001:1001::/home/attacker:/bin/bash
RUN chfn -r colon:field attacker
Password: chfn: PAM: Authentication failure
rc=1
attacker:x:1001:1001::/home/attacker:/bin/bash
RUN chfn -r comma,field attacker
Password: chfn: PAM: Authentication failure
rc=1
attacker:x:1001:1001::/home/attacker:/bin/bash
RUN chfn -r $(printf line\nfield) attacker
Password: chfn: PAM: Authentication failure
rc=1
attacker:x:1001:1001::/home/attacker:/bin/bash
RUN chfn root
chfn: Permission denied.
rc=1
attacker:x:1001:1001::/home/attacker:/bin/bash
```

Root-side trace of the uid1001 run shows only root-owned PAM/config paths before auth failure:

```text
TRACE chfn-room
rc=1
Password: chfn: PAM: Authentication failure
9762 openat(AT_FDCWD, "/etc/login.defs", O_RDONLY) = 3
9762 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
9762 openat(AT_FDCWD, "/etc/pam.d/chfn", O_RDONLY) = 3
9762 openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/security/pam_rootok.so", O_RDONLY|O_CLOEXEC) = 4
9762 openat(AT_FDCWD, "/etc/pam.d/common-auth", O_RDONLY) = 4
9762 openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/security/pam_unix.so", O_RDONLY|O_CLOEXEC) = 5
9762 openat(AT_FDCWD, "/etc/shadow", O_RDONLY|O_CLOEXEC) = 3
```

## `chsh` / shell allowlist

Self-shell changes are also PAM-gated and fail from the default locked attacker account. Root shell changes are denied before auth.

Command:

```sh
docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'for c in "chsh -s /bin/sh attacker" "chsh -s /tmp/sh attacker" "chsh -s /bin/bash root" "chsh -s /usr/bin/screen attacker"; do printf "RUN %s\n" "$c"; timeout 3 sh -c "$c" 2>&1; printf "rc=%s\n" "$?"; getent passwd attacker; done'
```

Result:

```text
RUN chsh -s /bin/sh attacker
Password: chsh: PAM: Authentication failure
rc=1
attacker:x:1001:1001::/home/attacker:/bin/bash
RUN chsh -s /tmp/sh attacker
Password: chsh: PAM: Authentication failure
rc=1
attacker:x:1001:1001::/home/attacker:/bin/bash
RUN chsh -s /bin/bash root
You may not change the shell for 'root'.
rc=1
attacker:x:1001:1001::/home/attacker:/bin/bash
RUN chsh -s /usr/bin/screen attacker
Password: chsh: PAM: Authentication failure
rc=1
attacker:x:1001:1001::/home/attacker:/bin/bash
```

Trace confirms the shell allowlist and PAM paths are root-owned:

```text
TRACE chsh-invalid
rc=1
Password: chsh: PAM: Authentication failure
9754 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
9754 openat(AT_FDCWD, "/etc/shells", O_RDONLY|O_CLOEXEC) = 3
9754 openat(AT_FDCWD, "/etc/pam.d/chsh", O_RDONLY) = 3
9754 openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/security/pam_shells.so", O_RDONLY|O_CLOEXEC) = 4
9754 openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/security/pam_rootok.so", O_RDONLY|O_CLOEXEC) = 4
9754 openat(AT_FDCWD, "/etc/pam.d/common-auth", O_RDONLY) = 4
9754 openat(AT_FDCWD, "/etc/shadow", O_RDONLY|O_CLOEXEC) = 3
```

## `passwd`

The attacker can query only their own locked status. Admin operations and root status are denied. Own password change cannot proceed because the current password is locked.

Command:

```sh
docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'for c in "passwd -S attacker" "passwd -S root" "passwd -a -S" "passwd -d attacker" "passwd -l attacker" "passwd -e attacker" "passwd -n 0 attacker" "passwd -x 99999 attacker"; do printf "RUN %s\n" "$c"; sh -c "$c" 2>&1; printf "rc=%s\n" "$?"; done'
```

Result:

```text
RUN passwd -S attacker
attacker L 2026-05-16 0 99999 7 -1
rc=0
RUN passwd -S root
passwd: You may not view or modify password information for root.
rc=1
RUN passwd -a -S
passwd: Permission denied.
rc=1
RUN passwd -d attacker
passwd: Permission denied.
rc=1
RUN passwd -l attacker
passwd: Permission denied.
rc=1
RUN passwd -e attacker
passwd: Permission denied.
rc=1
RUN passwd -n 0 attacker
passwd: Permission denied.
rc=1
RUN passwd -x 99999 attacker
passwd: Permission denied.
rc=1
```

Command:

```sh
docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'for c in "passwd attacker" "passwd root" "passwd --repository files attacker" "passwd --repository nis attacker"; do printf "RUN %s\n" "$c"; out=$(mktemp); timeout 5 sh -c "printf '\''oldpass\\nnewpass\\nnewpass\\n'\'' | $c" >$out 2>&1; rc=$?; sed -n "1,30p" $out; printf "rc=%s\n" "$rc"; rm -f $out; done'
```

Result:

```text
RUN passwd attacker
Current password: passwd: Authentication token manipulation error
passwd: password unchanged
Changing password for attacker.
rc=10
RUN passwd root
passwd: You may not view or modify password information for root.
rc=1
RUN passwd --repository files attacker
Current password: passwd: Authentication token manipulation error
passwd: password unchanged
Changing password for attacker.
rc=10
RUN passwd --repository nis attacker
passwd: repository nis not supported
rc=6
```

Trace for the only successful query:

```text
TRACE passwd-status
rc=0
attacker L 2026-05-16 0 99999 7 -1
9738 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
9738 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
9738 openat(AT_FDCWD, "/etc/shadow", O_RDONLY|O_CLOEXEC) = 3
```

## `gpasswd`

The attacker is not a group administrator and cannot modify their own group or privileged groups. Default group passwords in `/etc/gshadow` are locked (`*`, `!`, or `!*`), so `newgrp` cannot use a group password to join privileged groups either.

Command:

```sh
docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'for c in "gpasswd attacker" "gpasswd -a attacker sudo" "gpasswd -d ubuntu sudo" "gpasswd -M attacker sudo" "gpasswd -A attacker sudo" "gpasswd -r sudo" "gpasswd -R sudo"; do printf "RUN %s\n" "$c"; timeout 3 sh -c "printf '\''attacker\\nattacker\\n'\'' | $c" 2>&1; printf "rc=%s\n" "$?"; done'
```

Result:

```text
RUN gpasswd attacker
gpasswd: Permission denied.
rc=1
RUN gpasswd -a attacker sudo
gpasswd: Permission denied.
rc=1
RUN gpasswd -d ubuntu sudo
gpasswd: Permission denied.
rc=1
RUN gpasswd -M attacker sudo
gpasswd: Permission denied.
rc=1
RUN gpasswd -A attacker sudo
gpasswd: Permission denied.
rc=1
RUN gpasswd -r sudo
gpasswd: Permission denied.
rc=1
RUN gpasswd -R sudo
gpasswd: Permission denied.
rc=1
```

Malformed group names do not become file/path traversal or parser writes:

```text
RUN gpasswd -a attacker [attacker]
gpasswd: Permission denied.
rc=1
RUN gpasswd -a attacker [sudo]
gpasswd: Permission denied.
rc=1
RUN gpasswd -a attacker [root]
gpasswd: Permission denied.
rc=1
RUN gpasswd -a attacker [bad:name]
gpasswd: group 'bad:name' does not exist in /etc/group
rc=3
RUN gpasswd -a attacker [bad,member]
gpasswd: group 'bad,member' does not exist in /etc/group
rc=3
RUN gpasswd -a attacker [../etc/passwd]
gpasswd: group '../etc/passwd' does not exist in /etc/group
rc=3
RUN gpasswd -a attacker [bad
name]
gpasswd: group 'bad
name' does not exist in /etc/group
rc=3
```

Trace shows root-owned account DB reads, with no writable temporary path under `/tmp` or `/run/lock`:

```text
TRACE gpasswd-add
rc=1
gpasswd: Permission denied.
9746 openat(AT_FDCWD, "/etc/login.defs", O_RDONLY) = 4
9746 faccessat(AT_FDCWD, "/etc/gshadow", F_OK) = 0
9746 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 4
9746 openat(AT_FDCWD, "/etc/group", O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW) = 4
9746 openat(AT_FDCWD, "/etc/gshadow", O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW) = 4
```

## `newgrp`

Switching to the attacker's existing primary group succeeds and `newgrp` honors attacker-controlled `SHELL`, but it executes the shell as uid/gid 1001 with no effective capabilities. This is an attacker-code execution path, not a root-code execution path.

Command:

```sh
docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'rm -f /tmp/account-ng-shell /tmp/account-ng.out; printf "#!/bin/sh\n{ id; grep -E '\''^(Uid|Gid|Groups|CapEff|NoNewPrivs):'\'' /proc/self/status; } > /tmp/account-ng.out\ncat /tmp/account-ng.out\nexit 0\n" > /tmp/account-ng-shell; chmod 755 /tmp/account-ng-shell; timeout 5 env SHELL=/tmp/account-ng-shell PATH=/tmp:/usr/bin:/bin newgrp attacker; rc=$?; printf "rc=%s\n" "$rc"; rm -f /tmp/account-ng-shell /tmp/account-ng.out'
```

Result:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
Uid:	1001	1001	1001	1001
Gid:	1001	1001	1001	1001
Groups:	1001 
CapEff:	0000000000000000
NoNewPrivs:	0
rc=0
```

Privileged group attempts fail before shell execution:

```sh
docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'rm -f /tmp/account-ng-shell /tmp/account-ng.out; printf "#!/bin/sh\nid > /tmp/account-ng.out\nexit 0\n" > /tmp/account-ng-shell; chmod 755 /tmp/account-ng-shell; printf "RUN SHELL=/tmp/account-ng-shell newgrp sudo\n"; timeout 5 sh -c "printf '\''attacker\\n'\'' | env SHELL=/tmp/account-ng-shell newgrp sudo" 2>&1; printf "rc=%s\n" "$?"; printf "captured="; cat /tmp/account-ng.out 2>/dev/null || true; rm -f /tmp/account-ng-shell /tmp/account-ng.out'
```

```text
RUN SHELL=/tmp/account-ng-shell newgrp sudo
Password: Invalid password.
rc=1
captured=
```

Other group attempts:

```text
RUN newgrp attacker
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
rc=0
RUN newgrp sudo
Password: Invalid password.
rc=1
RUN newgrp root
Password: Invalid password.
rc=1
RUN newgrp nonexistent
newgrp: group 'nonexistent' does not exist
rc=1
```

## `su`

Root/ubuntu account switches require authentication and fail. Non-root use of alternate groups is rejected before auth. Environment preservation did not produce a privileged shell because authentication never succeeds.

Command:

```sh
docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'for c in "su root -c id" "su -c id" "su ubuntu -c id" "su -p root -c env" "su -s /bin/sh root -c id" "su -g sudo root -c id"; do printf "RUN %s\n" "$c"; out=$(mktemp); timeout 3 sh -c "printf '\''attacker\\n'\'' | $c" >$out 2>&1; rc=$?; sed -n "1,20p" $out; printf "rc=%s\n" "$rc"; rm -f $out; done'
```

Result:

```text
RUN su root -c id
Password: rc=124
RUN su -c id
Password: su: Authentication failure
rc=1
RUN su ubuntu -c id
Password: su: Authentication failure
rc=1
RUN su -p root -c env
Password: su: Authentication failure
rc=1
RUN su -s /bin/sh root -c id
Password: su: Authentication failure
rc=1
RUN su -g sudo root -c id
su: only root can specify alternative groups
rc=1
```

## `polkit-agent-helper-1`

The helper is executable by uid1001 but is an authentication helper only. Direct invocation requires a target username, reads a password through PAM, and returns `FAILURE`. It does not execute attacker-controlled helpers or commands.

Command:

```sh
docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'for c in "/usr/lib/polkit-1/polkit-agent-helper-1" "/usr/lib/polkit-1/polkit-agent-helper-1 attacker" "/usr/lib/polkit-1/polkit-agent-helper-1 root" "/usr/lib/polkit-1/polkit-agent-helper-1 nonexistent"; do printf "RUN %s\n" "$c"; out=$(mktemp); timeout 5 sh -c "printf '\''cookie\\nattacker\\n'\'' | $c" >$out 2>&1; rc=$?; sed -n "1,30p" $out; printf "rc=%s\n" "$rc"; rm -f $out; done'
```

Result:

```text
RUN /usr/lib/polkit-1/polkit-agent-helper-1
polkit-agent-helper-1: wrong number of arguments. This incident has been logged.
FAILURE
rc=1
RUN /usr/lib/polkit-1/polkit-agent-helper-1 attacker
PAM_PROMPT_ECHO_OFF Password: 
polkit-agent-helper-1: pam_authenticate failed: Authentication failure
FAILURE
rc=1
RUN /usr/lib/polkit-1/polkit-agent-helper-1 root
PAM_PROMPT_ECHO_OFF Password: 
polkit-agent-helper-1: pam_authenticate failed: Authentication failure
FAILURE
rc=1
RUN /usr/lib/polkit-1/polkit-agent-helper-1 nonexistent
PAM_PROMPT_ECHO_OFF Password: 
polkit-agent-helper-1: pam_authenticate failed: Authentication failure
FAILURE
rc=1
```

Malformed usernames did not change the outcome:

```text
RUN polkit-agent-helper-1 [bad:name]
PAM_PROMPT_ECHO_OFF Password: 
polkit-agent-helper-1: pam_authenticate failed: Authentication failure
FAILURE
rc=1
RUN polkit-agent-helper-1 [bad
name]
PAM_PROMPT_ECHO_OFF Password: 
polkit-agent-helper-1: pam_authenticate failed: Authentication failure
FAILURE
rc=1
```

Trace of a uid1001 helper run:

```text
rc=1
PAM_PROMPT_ECHO_OFF Password: 
FAILURE
polkit-agent-helper-1: pam_authenticate failed: Authentication failure
9835 openat(AT_FDCWD, "/etc/pam.d/polkit-1", O_RDONLY) = -1 ENOENT (No such file or directory)
9835 openat(AT_FDCWD, "/usr/lib/pam.d/polkit-1", O_RDONLY) = 3
9835 openat(AT_FDCWD, "/etc/pam.d/common-auth", O_RDONLY) = 4
9835 openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/security/pam_unix.so", O_RDONLY|O_CLOEXEC) = 5
9835 openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/security/pam_env.so", O_RDONLY|O_CLOEXEC) = 4
9835 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
9835 openat(AT_FDCWD, "/etc/shadow", O_RDONLY|O_CLOEXEC) = 3
```

Polkit rules are not attacker-writable:

```text
drwxr-x--- 2 root polkitd 4096 Apr 10 10:57 /etc/polkit-1/rules.d
drwxr-xr-x 2 root root    4096 May 16 10:22 /usr/share/polkit-1/rules.d
/usr/share/polkit-1/rules.d/49-ubuntu-admin.rules:2 return ["unix-group:sudo", "unix-group:admin"];
/usr/share/polkit-1/rules.d/50-default.rules:11 return ["unix-group:sudo"];
```

## Environment handling

Dynamic loader variables were ignored for setuid execution; no loader error or attacker library load occurred. The commands returned their normal permission/auth failures.

Command:

```sh
docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'for c in "passwd -S attacker" "gpasswd -a attacker sudo" "chfn -f X attacker" "chsh -s /bin/sh root" "newgrp nonexistent" "su -g sudo root -c id" "/usr/lib/polkit-1/polkit-agent-helper-1 attacker"; do printf "RUN env LD_PRELOAD=/tmp/nope.so LD_AUDIT=/tmp/nope.so %s\n" "$c"; out=$(mktemp); timeout 5 sh -c "printf '\''x\\n'\'' | env LD_PRELOAD=/tmp/nope.so LD_AUDIT=/tmp/nope.so PATH=/tmp:/usr/bin:/bin $c" >$out 2>&1; rc=$?; sed -n "1,12p" $out; printf "rc=%s\n" "$rc"; rm -f $out; done'
```

Result:

```text
RUN env LD_PRELOAD=/tmp/nope.so LD_AUDIT=/tmp/nope.so passwd -S attacker
attacker L 2026-05-16 0 99999 7 -1
rc=0
RUN env LD_PRELOAD=/tmp/nope.so LD_AUDIT=/tmp/nope.so gpasswd -a attacker sudo
gpasswd: Permission denied.
rc=1
RUN env LD_PRELOAD=/tmp/nope.so LD_AUDIT=/tmp/nope.so chfn -f X attacker
chfn: Permission denied.
rc=1
RUN env LD_PRELOAD=/tmp/nope.so LD_AUDIT=/tmp/nope.so chsh -s /bin/sh root
You may not change the shell for 'root'.
rc=1
RUN env LD_PRELOAD=/tmp/nope.so LD_AUDIT=/tmp/nope.so newgrp nonexistent
newgrp: group 'nonexistent' does not exist
rc=1
RUN env LD_PRELOAD=/tmp/nope.so LD_AUDIT=/tmp/nope.so su -g sudo root -c id
su: only root can specify alternative groups
rc=1
RUN env LD_PRELOAD=/tmp/nope.so LD_AUDIT=/tmp/nope.so /usr/lib/polkit-1/polkit-agent-helper-1 attacker
PAM_PROMPT_ECHO_OFF Password: 
polkit-agent-helper-1: pam_authenticate failed: Authentication failure
FAILURE
rc=1
```

## Locks, races, and writable directories

The account lock path is `/etc/.pwd.lock`, root-owned mode `0600`. Expected passwd/group/shadow lock names cannot be precreated by uid1001 because `/etc` is root-owned `0755`.

Command:

```sh
docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'for p in /etc/.pwd.lock /etc/passwd.lock /etc/group.lock /etc/gshadow.lock /etc/shadow.lock; do printf "RUN touch %s\n" "$p"; touch "$p" 2>&1; printf "rc=%s\n" "$?"; done; for d in /etc /etc/pam.d /etc/polkit-1/rules.d /usr/lib/pam.d /usr/share/polkit-1/rules.d; do stat -c "%A %U %G %a %n" "$d"; done'
```

Result:

```text
RUN touch /etc/.pwd.lock
touch: cannot touch '/etc/.pwd.lock': Permission denied
rc=1
RUN touch /etc/passwd.lock
touch: cannot touch '/etc/passwd.lock': Permission denied
rc=1
RUN touch /etc/group.lock
touch: cannot touch '/etc/group.lock': Permission denied
rc=1
RUN touch /etc/gshadow.lock
touch: cannot touch '/etc/gshadow.lock': Permission denied
rc=1
RUN touch /etc/shadow.lock
touch: cannot touch '/etc/shadow.lock': Permission denied
rc=1
drwxr-xr-x root root 755 /etc
drwxr-xr-x root root 755 /etc/pam.d
drwxr-x--- root polkitd 750 /etc/polkit-1/rules.d
drwxr-xr-x root root 755 /usr/lib/pam.d
drwxr-xr-x root root 755 /usr/share/polkit-1/rules.d
```

Subuid/subgid files are relevant only to uidmap-style helpers outside this slice and are not attacker-writable:

```text
sh: 1: cannot create /etc/subuid: Permission denied
sh: 1: cannot create /etc/subgid: Permission denied
RUN printf >> /etc/subuid
rc=2
RUN printf >> /etc/subgid
rc=2
-rw-r--r-- root root 644 /etc/subuid
-rw-r--r-- root root 644 /etc/subgid
```

## Cleanup verification

The only target-side writes were temporary `/tmp/account-*` probe files/directories. Each probe command removed its own files. Final cleanup/state check:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'find /tmp -maxdepth 1 -name "account-*" -o -name "account_*" | sort; getent passwd attacker; getent group attacker; awk -F: '\''$1=="attacker" {print $1 ":" $2 ":" $3 ":" $4 ":" $5 ":" $6 ":" $7 ":" $8 ":" $9}'\'' /etc/shadow'
```

Result:

```text
attacker:x:1001:1001::/home/attacker:/bin/bash
attacker:x:1001:
attacker:!$y$j9T$.lMGEn4aD.zRGa6IjGVAw0$PjRMOg4GtFc2rFEBQj.ThM.EOt14nKgDCjtuEgHkmSD:20589:0:99999:7:::
```

No `notes/account_*` or `pocs/account_*` artifact was created because no real uid1001-to-root LPE was validated.
