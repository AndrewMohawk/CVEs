# Negative: PAM session, MOTD, and login-like surfaces

Scope: stock Ubuntu 24.04 Server default install in `ubuntu24-server-lpe-target`, starting as `attacker` uid/gid 1001 with no sudo or extra groups. This pass covered default PAM session hooks, `pam_motd`/`update-motd`, `login`, `su`, `runuser`, `loginctl`/systemd-user, `machinectl`, SSH server reachability, and MOTD/cache writers for landscape, update-notifier, ubuntu-pro, fwupd, unattended-upgrades, and release-upgrader.

Result: no validated local privilege escalation. The only default PAM stack that includes `pam_motd` is `/etc/pam.d/login`, but `/usr/bin/login` is not setuid and cannot be invoked usefully from uid 1001; that leaves the root-getty/physical-console path out of scope. `openssh-server` and `/etc/pam.d/sshd` are absent. `su` is setuid but the attacker account password is locked in this target and the `su` stack has no `pam_motd`; `runuser` refuses non-root callers. `loginctl enable-linger attacker` is reachable for the user's own account, but it starts a normal uid 1001 user manager through `user@.service`; the fallback PAM stack has no MOTD or executable hooks, and cleanup disabled linger afterward.

## Default install proof

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'printf "== release ==\n"; cat /etc/os-release; uname -a; printf "== attacker ==\n"; id attacker; groups attacker; printf "== package versions ==\n"; dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n" login passwd util-linux systemd libpam0g libpam-modules libpam-runtime openssh-server openssh-client landscape-common update-notifier-common ubuntu-pro-client fwupd update-manager-core ubuntu-release-upgrader-core base-files 2>&1 | sort; printf "== login-like binaries ==\n"; for b in /usr/bin/login /bin/login /usr/bin/su /bin/su /usr/sbin/runuser /usr/bin/runuser /usr/bin/machinectl /usr/bin/loginctl /usr/bin/systemd-run /usr/bin/ssh /usr/sbin/sshd; do [ -e "$b" ] && stat -c "%A %U:%G %n" "$b"; done'
```

Result:

```text
== release ==
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
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux
== attacker ==
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
attacker : attacker
== package versions ==
base-files	13ubuntu10.4	ii 
fwupd	1.9.34-0ubuntu1~24.04.1	ii 
landscape-common	24.02-0ubuntu5.7	ii 
libpam-modules:arm64	1.5.3-5ubuntu5.5	ii 
libpam-runtime	1.5.3-5ubuntu5.5	ii 
libpam0g:arm64	1.5.3-5ubuntu5.5	ii 
login	1:4.13+dfsg1-4ubuntu3.2	ii 
openssh-client	1:9.6p1-3ubuntu13.16	ii 
openssh-server		un 
passwd	1:4.13+dfsg1-4ubuntu3.2	ii 
systemd	255.4-1ubuntu8.15	ii 
ubuntu-pro-client	37.2ubuntu~24.04	ii 
ubuntu-release-upgrader-core	1:24.04.28	ii 
update-manager-core	1:24.04.12	ii 
update-notifier-common	3.192.68.2	ii 
util-linux	2.39.3-9ubuntu6.5	ii 
== login-like binaries ==
-rwxr-xr-x root:root /usr/bin/login
-rwxr-xr-x root:root /bin/login
-rwsr-xr-x root:root /usr/bin/su
-rwsr-xr-x root:root /bin/su
-rwxr-xr-x root:root /usr/sbin/runuser
-rwxr-xr-x root:root /usr/bin/loginctl
-rwxr-xr-x root:root /usr/bin/systemd-run
-rwxr-xr-x root:root /usr/bin/ssh
```

Baseline cross-check:

```sh
printf '== baseline live-target-standard relevant packages ==\n'; rg -n '^(login|passwd|util-linux|systemd|libpam0g|libpam-modules|libpam-runtime|openssh-server|openssh-client|landscape-common|update-notifier-common|ubuntu-pro-client|fwupd|update-manager-core|ubuntu-release-upgrader-core|base-files)\s' baseline/live-target-standard/packages.txt || true; printf '== baseline users groups ==\n'; rg -n 'attacker|sudo|adm|ubuntu' baseline/live-target-standard/users-groups.txt | sed -n '1,80p'
```

Result:

```text
== baseline live-target-standard relevant packages ==
10:base-files	13ubuntu10.4
74:fwupd	1.9.34-0ubuntu1~24.04.1
122:landscape-common	24.02-0ubuntu5.7
279:libpam-runtime	1.5.3-5ubuntu5.5
374:login	1:4.13+dfsg1-4ubuntu3.2
407:openssh-client	1:9.6p1-3ubuntu13.16
413:passwd	1:4.13+dfsg1-4ubuntu3.2
522:systemd	255.4-1ubuntu8.15
542:ubuntu-pro-client	37.2ubuntu~24.04
544:ubuntu-release-upgrader-core	1:24.04.28
553:update-manager-core	1:24.04.12
554:update-notifier-common	3.192.68.2
559:util-linux	2.39.3-9ubuntu6.5
== baseline users groups ==
20:ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
33:attacker:x:1001:1001::/home/attacker:/bin/bash
40:adm:x:4:ubuntu,syslog
50:dialout:x:20:ubuntu
53:cdrom:x:24:ubuntu
54:floppy:x:25:ubuntu
56:sudo:x:27:ubuntu
57:audio:x:29:ubuntu
58:dip:x:30:ubuntu
67:video:x:44:ubuntu
69:plugdev:x:46:ubuntu
74:ubuntu:x:1000:
94:attacker:x:1001:
```

The current target shadow state also has root/ubuntu locked and attacker locked:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'sed -n "/^root:/p;/^attacker:/p;/^ubuntu:/p" /etc/passwd; sed -n "/^root:/p;/^attacker:/p;/^ubuntu:/p" /etc/shadow | sed -E "s#^([^:]+):([^:]{0,12}).*#\1:\2...#"'
```

```text
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
attacker:x:1001:1001::/home/attacker:/bin/bash
root:*...
ubuntu:!...
attacker:!$y$j9T$.lMG...
```

## PAM stack review

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'grep -RInE "pam_(motd|env|mail|lastlog|systemd|exec|loginuid|limits|umask|unix|nologin|securetty)|session" /etc/pam.d || true; for f in /etc/pam.d/login /etc/pam.d/su /etc/pam.d/runuser /etc/pam.d/runuser-l /etc/pam.d/systemd-user /etc/pam.d/sshd /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive /etc/pam.d/other; do [ -e "$f" ] && { echo "--- $f"; nl -ba "$f"; } || echo "--- $f MISSING"; done'
```

Key result excerpts:

```text
/etc/pam.d/login:27:session    required     pam_loginuid.so
/etc/pam.d/login:33:session    optional   pam_motd.so motd=/run/motd.dynamic
/etc/pam.d/login:34:session    optional   pam_motd.so noupdate
/etc/pam.d/login:51:session       required   pam_env.so readenv=1
/etc/pam.d/login:54:session       required   pam_env.so readenv=1 envfile=/etc/default/locale
/etc/pam.d/login:82:session    optional   pam_lastlog.so
/etc/pam.d/login:92:session    optional   pam_mail.so standard
/etc/pam.d/login:99:@include common-session
/etc/pam.d/su:36:session       required   pam_env.so readenv=1
/etc/pam.d/su:39:session       required   pam_env.so readenv=1 envfile=/etc/default/locale
/etc/pam.d/su:48:session    optional   pam_mail.so nopen
/etc/pam.d/su:59:@include common-session
/etc/pam.d/runuser:3:session		optional	pam_keyinit.so revoke
/etc/pam.d/runuser:4:session		required	pam_limits.so
/etc/pam.d/runuser:5:session		required	pam_unix.so
/etc/pam.d/runuser-l:4:-session	optional	pam_systemd.so
--- /etc/pam.d/systemd-user MISSING
--- /etc/pam.d/sshd MISSING
--- /etc/pam.d/common-session
    26	session optional			pam_umask.so
    28	session	required	pam_unix.so 
    29	session	optional	pam_systemd.so 
--- /etc/pam.d/common-session-noninteractive
    27	session optional			pam_umask.so
    29	session	required	pam_unix.so 
--- /etc/pam.d/other
    13	@include common-auth
    14	@include common-account
    15	@include common-password
    16	@include common-session
```

There is no default `pam_exec`, `pam_namespace`, or `pam_motd` in `su`, `runuser`, `common-session`, `common-session-noninteractive`, or the `other` fallback. `pam_motd` appears only in `login`; `sshd` is absent.

The root-owned environment and policy files used by `pam_env`, `pam_group`, `pam_limits`, and the landscape wrapper are not attacker-writable:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'readlink -v /etc/default/locale || true; readlink -f /etc/default/locale || true; namei -l /etc/default/locale /etc/environment /etc/security/pam_env.conf /etc/security/group.conf /etc/security/limits.conf /etc/security/namespace.conf 2>&1 | sed -n "1,180p"; sed -n "1,40p" /etc/default/locale 2>&1 || true'
```

```text
../locale.conf
/etc/locale.conf
f: /etc/default/locale
drwxr-xr-x root root /
drwxr-xr-x root root etc
drwxr-xr-x root root default
lrwxrwxrwx root root locale -> ../locale.conf
drwxr-xr-x root root   ..
-rw-r--r-- root root   locale.conf
f: /etc/environment
drwxr-xr-x root root /
drwxr-xr-x root root etc
-rw-r--r-- root root environment
f: /etc/security/pam_env.conf
drwxr-xr-x root root /
drwxr-xr-x root root etc
drwxr-xr-x root root security
-rw-r--r-- root root pam_env.conf
f: /etc/security/group.conf
drwxr-xr-x root root /
drwxr-xr-x root root etc
drwxr-xr-x root root security
-rw-r--r-- root root group.conf
f: /etc/security/limits.conf
drwxr-xr-x root root /
drwxr-xr-x root root etc
drwxr-xr-x root root security
-rw-r--r-- root root limits.conf
f: /etc/security/namespace.conf
drwxr-xr-x root root /
drwxr-xr-x root root etc
drwxr-xr-x root root security
-rw-r--r-- root root namespace.conf
LANG=C.UTF-8
```

Mail state was not a write primitive. `/var/mail` is `root:mail` group-writable only, attacker is not in `mail`, and no attacker spool exists:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'grep -nE "^(MAIL_DIR|MAIL_FILE|ENV_|SU_|LOGIN|UMASK|TTYGROUP|TTYPERM|DEFAULT_HOME|USERGROUPS_ENAB)" /etc/login.defs || true; ls -ld /var/mail /var/spool/mail 2>&1 || true; ls -l /var/mail 2>&1 || true'
```

```text
35:MAIL_DIR        /var/mail
87:SU_NAME		su
102:ENV_SUPATH	PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
103:ENV_PATH	PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
123:TTYGROUP	tty
124:TTYPERM		0600
151:UMASK		022
201:LOGIN_RETRIES		5
206:LOGIN_TIMEOUT		60
220:DEFAULT_HOME	yes
238:USERGROUPS_ENAB yes
drwxrwsr-x 2 root mail 4096 Apr 10 02:23 /var/mail
lrwxrwxrwx 1 root root    7 Apr 10 02:23 /var/spool/mail -> ../mail
total 0
```

## Login-like triggerability

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'runuser -u attacker -- bash -lc '\''set -o pipefail; id; printf "login attacker ->\n"; timeout 3 login attacker </dev/null; echo login_rc:$?; printf "runuser self ->\n"; runuser -u attacker -- id; echo runuser_rc:$?; printf "su self ->\n"; timeout 3 su attacker -c id </dev/null; echo su_self_rc:$?; printf "su root ->\n"; timeout 3 su root -c id </dev/null; echo su_root_rc:$?'\'''
```

Result:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
login attacker ->
login: Cannot possibly work without effective root
login_rc:1
runuser self ->
runuser: may not be used by non-root users
runuser_rc:1
su self ->
Password: su: Authentication failure
su_self_rc:1
su root ->
Password: su: Authentication failure
su_root_rc:1
```

Interpretation: `login` is a root/getty path, not a shell-reachable setuid path. `runuser` is root-only. `su` reaches authentication but not session as this default attacker account is password-locked; even if an unlocked user could `su` to self, the default `su` stack has no `pam_motd` or executable scripts.

## loginctl, machinectl, and systemd-user

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'runuser -u attacker -- bash -lc '\''id; command -v loginctl || true; command -v machinectl || true; printf "loginctl list-sessions ->\n"; loginctl list-sessions 2>&1; echo rc:$?; printf "loginctl enable-linger attacker ->\n"; timeout 5 loginctl enable-linger attacker 2>&1; echo rc:$?; printf "loginctl user-status attacker ->\n"; loginctl user-status attacker 2>&1 | sed -n "1,20p"; echo rc:${PIPESTATUS[0]}; printf "machinectl shell attacker@ ->\n"; timeout 5 machinectl shell attacker@ 2>&1; echo rc:$?'\'''
```

Result:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
/usr/bin/loginctl
loginctl list-sessions ->
No sessions.
rc:0
loginctl enable-linger attacker ->
rc:0
loginctl user-status attacker ->
attacker (1001)
  Since: Sat 2026-05-16 10:56:09 UTC; 39ms ago
  State: opening
 Linger: yes
   Unit: user-1001.slice
          └─user-runtime-dir@1001.service
            └─8229 /usr/lib/systemd/systemd-user-runtime-dir start 1001
rc:0
machinectl shell attacker@ ->
timeout: failed to run command 'machinectl': No such file or directory
rc:127
```

`user@.service` does name a PAM service, but `/etc/pam.d/systemd-user` is absent, so it falls back to `/etc/pam.d/other` above. No MOTD or executable hook is present:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'systemctl cat user@.service 2>/dev/null | sed -n "1,80p"; [ -e /etc/pam.d/systemd-user ] && nl -ba /etc/pam.d/systemd-user || echo MISSING /etc/pam.d/systemd-user'
```

```text
# /usr/lib/systemd/system/user@.service
[Unit]
Description=User Manager for UID %i
Documentation=man:user@.service(5)
After=user-runtime-dir@%i.service dbus.service systemd-oomd.service
Requires=user-runtime-dir@%i.service
IgnoreOnIsolate=yes

[Service]
User=%i
PAMName=systemd-user
Type=notify-reload
ExecStart=/usr/lib/systemd/systemd --user
Slice=user-%i.slice
KillMode=mixed
Delegate=pids memory cpu
DelegateSubgroup=init.scope
TasksMax=infinity
TimeoutStopSec=120s
KeyringMode=inherit
OOMScoreAdjust=100
MemoryPressureWatch=skip
MISSING /etc/pam.d/systemd-user
```

With linger enabled, user services run as uid 1001, not root:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'runuser -u attacker -- bash -lc '\''id; export XDG_RUNTIME_DIR=/run/user/1001; printf "runtime:%s\n" "$XDG_RUNTIME_DIR"; stat -c "%A %U:%G %n" "$XDG_RUNTIME_DIR" "$XDG_RUNTIME_DIR/bus" 2>&1 || true; systemctl --user is-system-running 2>&1; echo systemctl_rc:$?; systemd-run --user --wait --collect /usr/bin/id 2>&1; echo systemd_run_rc:$?'\'''
```

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
runtime:/run/user/1001
drwx------ attacker:attacker /run/user/1001
srw-rw-rw- attacker:attacker /run/user/1001/bus
running
systemctl_rc:0
Running as unit: run-u0.service; invocation ID: 2fb0e98741e7429b9b9e2c2cf2ed167d
Finished with result: success
Main processes terminated with: code=exited/status=0
Service runtime: 2ms
CPU time consumed: 2ms
Memory peak: 512.0K
Memory swap peak: 0B
systemd_run_rc:0
```

Process identity during the lingered user manager also showed uid 1001:

```text
8239       1 attacker attacker  1001  1001 /usr/lib/systemd/systemd --user
8240    8239 attacker attacker  1001  1001 (sd-pam)
```

Cleanup after the linger probe:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'loginctl disable-linger attacker 2>&1; echo disable_rc:$?; loginctl terminate-user attacker 2>&1; echo terminate_rc:$?; sleep 1; ls -l /var/lib/systemd/linger 2>&1 || true; loginctl user-status attacker 2>&1 | sed -n "1,18p"; [ -d /run/user/1001 ] && stat -c "%A %U:%G %n" /run/user/1001 || echo "MISSING /run/user/1001"'
```

```text
disable_rc:0
terminate_rc:0
total 0
Failed to get user: User ID 1001 is not logged in or lingering
MISSING /run/user/1001
```

## MOTD and cache paths

Relevant default MOTD files:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'ls -l /etc/update-motd.d /run/motd.dynamic /run/motd.dynamic.new /var/lib/landscape /var/log/landscape /var/lib/update-notifier /var/lib/ubuntu-advantage /var/lib/ubuntu-pro /var/lib/fwupd 2>&1 || true'
```

```text
ls: cannot access '/run/motd.dynamic': No such file or directory
ls: cannot access '/run/motd.dynamic.new': No such file or directory
ls: cannot access '/var/lib/ubuntu-pro': No such file or directory
ls: cannot access '/var/lib/fwupd': No such file or directory
/etc/update-motd.d:
total 56
-rwxr-xr-x 1 root root 1220 Apr 22  2024 00-header
-rwxr-xr-x 1 root root 1151 Apr 22  2024 10-help-text
lrwxrwxrwx 1 root root   46 May 16 10:22 50-landscape-sysinfo -> /usr/share/landscape/landscape-sysinfo.wrapper
-rwxr-xr-x 1 root root 5023 Apr 22  2024 50-motd-news
-rwxr-xr-x 1 root root  356 Apr 10 02:30 60-unminimize
-rwxr-xr-x 1 root root   84 Mar 13 03:54 85-fwupd
-rwxr-xr-x 1 root root  218 Apr  2  2025 90-updates-available
-rwxr-xr-x 1 root root  296 Apr  7 18:21 91-contract-ua-esm-status
-rwxr-xr-x 1 root root  558 Oct 10  2024 91-release-upgrade
-rwxr-xr-x 1 root root  165 Feb 12  2024 92-unattended-upgrades
-rwxr-xr-x 1 root root  379 Apr  2  2025 95-hwe-eol
-rwxr-xr-x 1 root root  111 Jul  3  2024 97-overlayroot
-rwxr-xr-x 1 root root  142 Apr  2  2025 98-fsck-at-reboot
-rwxr-xr-x 1 root root  144 Apr  2  2025 98-reboot-required

/var/lib/landscape:
total 0

/var/lib/ubuntu-advantage:
total 0

/var/lib/update-notifier:
total 8
drwxr-xr-x 3 root root 4096 May 16 10:22 package-data-downloads
drwxr-xr-x 2 root root 4096 Apr  2  2025 user.d

/var/log/landscape:
total 0
-rw-r--r-- 1 root root 0 May 16 10:22 sysinfo.log
```

Root-owned config/state permissions and attacker writability:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'for p in /etc/pam.d /etc/security /etc/environment /etc/default/locale /etc/update-motd.d /etc/default/motd-news /run /run/motd.d /run/motd.dynamic /var/cache/motd-news /var/lib/landscape /var/log/landscape /var/lib/update-notifier /var/lib/update-notifier/user.d /var/lib/update-notifier/package-data-downloads /var/lib/ubuntu-advantage /var/lib/ubuntu-advantage/messages /var/lib/ubuntu-release-upgrader /var/lib/fwupd /var/cache/fwupd /var/lib/PackageKit /var/lib/update-manager; do [ -e "$p" ] && stat -c "%A %U:%G %n" "$p" || echo "MISSING $p"; done; printf "== attacker writable among relevant roots ==\n"; runuser -u attacker -- sh -lc "for p in /etc/pam.d /etc/security /etc/environment /etc/default/locale /etc/update-motd.d /etc/default/motd-news /run /run/motd.d /var/cache/motd-news /var/lib/landscape /var/log/landscape /var/lib/update-notifier /var/lib/update-notifier/user.d /var/lib/update-notifier/package-data-downloads /var/lib/ubuntu-advantage /var/lib/ubuntu-advantage/messages /var/lib/ubuntu-release-upgrader /var/cache/fwupd /var/lib/PackageKit /var/lib/update-manager; do [ -e \"\$p\" ] && [ -w \"\$p\" ] && echo WRITABLE:\$p; done"'
```

```text
drwxr-xr-x root:root /etc/pam.d
drwxr-xr-x root:root /etc/security
-rw-r--r-- root:root /etc/environment
lrwxrwxrwx root:root /etc/default/locale
drwxr-xr-x root:root /etc/update-motd.d
-rw-r--r-- root:root /etc/default/motd-news
drwxr-xr-x root:root /run
MISSING /run/motd.d
MISSING /run/motd.dynamic
-rw-r--r-- root:root /var/cache/motd-news
drwxr-xr-x landscape:landscape /var/lib/landscape
drwxr-xr-x landscape:landscape /var/log/landscape
drwxr-xr-x root:root /var/lib/update-notifier
drwxr-xr-x root:root /var/lib/update-notifier/user.d
drwxr-xr-x root:root /var/lib/update-notifier/package-data-downloads
drwxr-xr-x root:root /var/lib/ubuntu-advantage
MISSING /var/lib/ubuntu-advantage/messages
drwxr-xr-x root:root /var/lib/ubuntu-release-upgrader
MISSING /var/lib/fwupd
MISSING /var/cache/fwupd
drwxr-xr-x root:root /var/lib/PackageKit
drwxr-xr-x root:root /var/lib/update-manager
== attacker writable among relevant roots ==
```

Direct attacker write probes:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'runuser -u attacker -- sh -lc "for p in /run/motd.dynamic /run/motd.dynamic.new /run/motd.d /run/motd.d/85-fwupd /var/cache/motd-news /var/lib/landscape/landscape-sysinfo.cache /var/lib/update-notifier/updates-available /var/lib/update-notifier/hwe-eol /var/lib/update-notifier/fsck-at-reboot /var/lib/update-notifier/user.d/pam-probe /var/lib/ubuntu-advantage/messages /var/lib/ubuntu-advantage/messages/motd-contract-status /var/lib/ubuntu-release-upgrader/release-upgrade-available; do printf \"touch %s -> \" \"\$p\"; touch \"\$p\" 2>&1 && echo OK || echo FAIL; done; rm -f /var/lib/update-notifier/user.d/pam-probe 2>/dev/null || true"'
```

```text
touch /run/motd.dynamic -> touch: cannot touch '/run/motd.dynamic': Permission denied
FAIL
touch /run/motd.dynamic.new -> touch: cannot touch '/run/motd.dynamic.new': Permission denied
FAIL
touch /run/motd.d -> touch: cannot touch '/run/motd.d': Permission denied
FAIL
touch /run/motd.d/85-fwupd -> touch: cannot touch '/run/motd.d/85-fwupd': No such file or directory
FAIL
touch /var/cache/motd-news -> touch: cannot touch '/var/cache/motd-news': Permission denied
FAIL
touch /var/lib/landscape/landscape-sysinfo.cache -> touch: cannot touch '/var/lib/landscape/landscape-sysinfo.cache': Permission denied
FAIL
touch /var/lib/update-notifier/updates-available -> touch: cannot touch '/var/lib/update-notifier/updates-available': Permission denied
FAIL
touch /var/lib/update-notifier/hwe-eol -> touch: cannot touch '/var/lib/update-notifier/hwe-eol': Permission denied
FAIL
touch /var/lib/update-notifier/fsck-at-reboot -> touch: cannot touch '/var/lib/update-notifier/fsck-at-reboot': Permission denied
FAIL
touch /var/lib/update-notifier/user.d/pam-probe -> touch: cannot touch '/var/lib/update-notifier/user.d/pam-probe': Permission denied
FAIL
touch /var/lib/ubuntu-advantage/messages -> touch: cannot touch '/var/lib/ubuntu-advantage/messages': Permission denied
FAIL
touch /var/lib/ubuntu-advantage/messages/motd-contract-status -> touch: cannot touch '/var/lib/ubuntu-advantage/messages/motd-contract-status': No such file or directory
FAIL
touch /var/lib/ubuntu-release-upgrader/release-upgrade-available -> touch: cannot touch '/var/lib/ubuntu-release-upgrader/release-upgrade-available': Permission denied
FAIL
```

Direct `run-parts` is attacker-reachable, but only as uid 1001:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'runuser -u attacker -- sh -lc "id; env PATH=/home/attacker/bin:/usr/bin:/bin LANG=zz_ZZ.UTF-8 LC_ALL=zz_ZZ.UTF-8 run-parts /etc/update-motd.d >/tmp/pam-motd-attacker.out 2>/tmp/pam-motd-attacker.err; rc=\$?; printf \"run-parts_rc:%s\n\" \"\$rc\"; ls -l /tmp/pam-motd-attacker.out /tmp/pam-motd-attacker.err; sed -n \"1,20p\" /tmp/pam-motd-attacker.err; rm -f /tmp/pam-motd-attacker.out /tmp/pam-motd-attacker.err"'
```

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
run-parts_rc:0
-rw-r--r-- 1 attacker attacker    0 May 16 10:55 /tmp/pam-motd-attacker.err
-rw-r--r-- 1 attacker attacker 1079 May 16 10:55 /tmp/pam-motd-attacker.out
```

Post-probe state had no attacker-owned MOTD artifacts:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'for p in /run/motd.dynamic /run/motd.dynamic.new /run/motd.d /run/motd.d/85-fwupd /var/cache/motd-news /var/lib/landscape/landscape-sysinfo.cache /var/lib/update-notifier/updates-available /var/lib/update-notifier/hwe-eol /var/lib/update-notifier/fsck-at-reboot /var/lib/ubuntu-advantage/messages /var/lib/ubuntu-release-upgrader/release-upgrade-available; do [ -e "$p" ] && stat -c "%A %U:%G %s %n" "$p" || echo "MISSING $p"; done; find /tmp /home/attacker -maxdepth 1 \( -name "pam-motd-*" -o -name "pam-session-*" -o -name "motd-*probe*" \) -printf "%M %u:%g %p\n" 2>/dev/null || true'
```

```text
MISSING /run/motd.dynamic
MISSING /run/motd.dynamic.new
MISSING /run/motd.d
MISSING /run/motd.d/85-fwupd
-rw-r--r-- root:root 216 /var/cache/motd-news
MISSING /var/lib/landscape/landscape-sysinfo.cache
-rw-r--r-- root:root 219 /var/lib/update-notifier/updates-available
MISSING /var/lib/update-notifier/hwe-eol
MISSING /var/lib/update-notifier/fsck-at-reboot
MISSING /var/lib/ubuntu-advantage/messages
MISSING /var/lib/ubuntu-release-upgrader/release-upgrade-available
```

## Script trust review

`/etc/update-motd.d/50-landscape-sysinfo` is the most suspicious PAM-time script because it writes a cache. It uses a hard-coded cache under `/var/lib/landscape`, sources only root-owned `/etc/default/locale`, and calls `/usr/bin/landscape-sysinfo`; uid 1001 cannot replace the cache path or locale file:

```text
/etc/update-motd.d/50-landscape-sysinfo:
     5	CACHE="/var/lib/landscape/landscape-sysinfo.cache"
    17	    # pam_motd does not carry the environment
    18	    [ -f /etc/default/locale ] && . /etc/default/locale
    19	    export LANG
    24	    if [ $(echo "`cut -f1 -d ' ' /proc/loadavg` < $THRESHOLD" | bc) -eq 1 ]; then
    25	        SYSINFO=$(printf "\n System information as of %s\n\n%s\n" \
    26	            "$(/bin/date)" \
    27	            "$(/usr/bin/landscape-sysinfo)")
    28	        echo "$SYSINFO" 2>/dev/null >"$CACHE" || true
    29	        chmod 0644 "$CACHE" 2>/dev/null || true
```

`50-motd-news` sources root-owned `/etc/default/motd-news`; the unquoted `$CACHE` writes are only attacker-controlled if that root-owned config is already compromised. The root timer is default active and writes `/var/cache/motd-news` as root, but uid 1001 cannot influence the config or cache path:

```text
/etc/update-motd.d/50-motd-news:
    33	[ -r /etc/default/motd-news ] && . /etc/default/motd-news
    40	[ -n "$URLS" ] || URLS="https://motd.ubuntu.com"
    42	[ -n "$CACHE" ] || CACHE="/var/cache/motd-news"
    56	  	if [ -r $CACHE ]; then
    58			safe_print $CACHE
    60			: > $CACHE
   126		wget --timeout "$WAIT" -U "$USER_AGENT" -O- --content-on-error "$u" >"$NEWS" 2>"$ERR" || result=$?
   140			safe_print "$NEWS" 2>/dev/null >$CACHE || true
```

Root-owned config sample:

```text
-rw-r--r-- root:root /etc/default/motd-news
     5	ENABLED=1
    13	URLS="https://motd.ubuntu.com"
    19	WAIT=5
-rw-r--r-- root:root 216 /var/cache/motd-news
```

`update-notifier` MOTD helpers write only under root-owned `/var/lib/update-notifier`:

```text
/usr/lib/update-notifier/update-motd-updates-available:
    15	stamp="/var/lib/update-notifier/updates-available"
    49	tmpfile=$(mktemp -p $(dirname "$stamp"))
    62	        /usr/lib/update-notifier/apt-check --human-readable "$NO_ESM_MESSAGES"
    65	    mv "$tmpfile" "$stamp"
    66	    chmod +r "$stamp"
/usr/lib/update-notifier/update-motd-hwe-eol:
    17	stamp="/var/lib/update-notifier/hwe-eol"
    57	tmpfile=$(mktemp -p $(dirname "$stamp"))
    65	    mv "$tmpfile" "$stamp"
/usr/lib/update-notifier/update-motd-fsck-at-reboot:
    18	stamp="/var/lib/update-notifier/fsck-at-reboot"
    82	  } > $stamp
```

`package-data-downloader` has a root-code-execution shape, but hook definitions and state are root-owned/package-owned and were already covered separately. Relevant paths in this target:

```text
/usr/lib/update-notifier/package-data-downloader:
    36	DATADIR = "/usr/share/package-data-downloads/"
    37	STAMPDIR = "/var/lib/update-notifier/package-data-downloads/"
    40	NOTIFIER_FILE = "/var/lib/update-notifier/user.d/data-downloads-failed"
   161	def get_hook_file_names():
   163	    for relfile in os.listdir(DATADIR):
   247	        hook = debian.deb822.Deb822()
   250	        for para in hook.iter_paragraphs(open(file)):
   255	                command = [para['Script']]
   271	                # Download each file and verify the sum
   287	                    result = subprocess.call(command)
```

```text
drwxr-xr-x root:root /usr/share/package-data-downloads
drwxr-xr-x root:root /var/lib/update-notifier/package-data-downloads
drwx------ _apt:root /var/lib/update-notifier/package-data-downloads/partial
drwxr-xr-x root:root /var/lib/update-notifier/user.d
```

Ubuntu Pro MOTD messages are hard-coded to `/var/lib/ubuntu-advantage/messages/*`. The directory is absent by default and the parent is root-owned. The writer is root-side timer/command logic; non-root `NoticesManager.add/remove` returns without writing.

```text
/etc/update-motd.d/91-contract-ua-esm-status:
     2	contract_status_stamp="/var/lib/ubuntu-advantage/messages/motd-contract-status"
     4	[ ! -r "$contract_status_stamp" ] || cat "$contract_status_stamp"
     6	auto_attach_stamp="/var/lib/ubuntu-advantage/messages/motd-auto-attach-status"
     8	[ ! -r "$auto_attach_stamp" ] || cat "$auto_attach_stamp"
/usr/lib/python3/dist-packages/uaclient/timer/update_messaging.py:
    71	    motd_contract_status_msg_path = os.path.join(
    72	        cfg.data_dir, "messages", MOTD_CONTRACT_STATUS_FILE_NAME
    97	        system.write_file(
    98	            motd_contract_status_msg_path,
   147	            system.write_file(
   148	                motd_contract_status_msg_path,
/usr/lib/python3/dist-packages/uaclient/files/notices.py:
   127	        if not util.we_are_currently_root():
   132	            return
   142	        system.write_file(
```

`fwupd` MOTD display is a cat of `/run/motd.d/85-fwupd`; `/run/motd.d` was missing in the Docker target and `/run` is root-owned. `fwupd.service` would create that runtime directory as root on non-container systems; `fwupd-refresh.service` is a restricted `fwupd-refresh` user service and its timer has `ConditionVirtualization=!container` here.

```text
/etc/update-motd.d/85-fwupd:
     3	if [ -f /run/motd.d/85-fwupd ]; then
     4	        cat /run/motd.d/85-fwupd
/usr/lib/systemd/system/fwupd.service:
    11	RuntimeDirectory=motd.d
    12	RuntimeDirectoryPreserve=yes
    25	StateDirectory=fwupd
    26	CacheDirectory=fwupd
/usr/lib/systemd/system/fwupd-refresh.service:
    10	CacheDirectory=fwupdmgr
    14	User=fwupd-refresh
/usr/lib/systemd/system/fwupd-refresh.timer:
    3	ConditionVirtualization=!container
```

Release-upgrader and unattended-upgrades MOTD hooks only read/write root-owned state:

```text
/usr/lib/ubuntu-release-upgrader/release-upgrade-motd:
    23	stamp=/var/lib/ubuntu-release-upgrader/release-upgrade-available
    31			/usr/lib/ubuntu-release-upgrader/check-new-release -q > "$stamp" &
    37	elif [ "$(id -u)" = 0 ]; then
    39		/usr/lib/ubuntu-release-upgrader/check-new-release -q > "$stamp" &
/usr/share/unattended-upgrades/update-motd-unattended-upgrades:
     5	if [ -f /var/lib/unattended-upgrades/kept-back ]; then
     8	$(wc -w < /var/lib/unattended-upgrades/kept-back) updates could not be installed automatically. For more details,
```

## Timer-driven root writers

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'for u in motd-news.service motd-news.timer update-notifier-motd.service update-notifier-motd.timer update-notifier-download.service update-notifier-download.timer fwupd-refresh.service fwupd-refresh.timer ua-timer.service ua-timer.timer apt-news.service esm-cache.service; do systemctl cat "$u" 2>/dev/null | sed -n "1,80p"; done; systemctl list-timers --all "*motd*" "*notifier*" "*fwupd*" "*ua*" "*esm*" 2>/dev/null || true'
```

Key result excerpts:

```text
# /usr/lib/systemd/system/motd-news.service
[Service]
Type=oneshot
ExecStart=/etc/update-motd.d/50-motd-news --force
# /usr/lib/systemd/system/update-notifier-motd.service
[Service]
ExecStart=/usr/lib/ubuntu-release-upgrader/release-upgrade-motd
Type=oneshot
# /usr/lib/systemd/system/update-notifier-download.service
[Service]
ExecStart=/usr/lib/update-notifier/package-data-downloader
Type=oneshot
# /usr/lib/systemd/system/fwupd-refresh.service
[Service]
Type=oneshot
CacheDirectory=fwupdmgr
ProtectSystem=strict
ProtectHome=read-only
User=fwupd-refresh
ExecStart=/usr/bin/fwupdmgr refresh
# /usr/lib/systemd/system/fwupd-refresh.timer
[Unit]
ConditionVirtualization=!container
# /usr/lib/systemd/system/ua-timer.timer
[Unit]
ConditionPathExists=/var/lib/ubuntu-advantage/private/machine-token.json

NEXT                            LEFT LAST                           PASSED UNIT                           ACTIVATES
Sat 2026-05-16 20:21:43 UTC       9h Sat 2026-05-16 10:32:12 UTC 22min ago motd-news.timer                motd-news.service
Sun 2026-05-17 10:29:05 UTC      23h Sat 2026-05-16 10:29:05 UTC 25min ago update-notifier-download.timer update-notifier-download.service
Sun 2026-05-17 16:30:48 UTC 1 day 5h -                                   - update-notifier-motd.timer     update-notifier-motd.service
-                                  - -                                   - fwupd-refresh.timer            fwupd-refresh.service
-                                  - -                                   - ua-timer.timer                 ua-timer.service
```

Conclusion: the root/timer writers are default-installed, but uid 1001 cannot control their script directories, config files, hook descriptors, cache paths, or stamp paths. No root write or root code execution was reachable from the unprivileged shell.
