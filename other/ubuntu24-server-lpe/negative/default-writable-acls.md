# Negative: default writable ACLs and mode mismatches on Ubuntu 24.04 Server

Target: `ubuntu24-server-lpe-target`

Result: no uid1001 `attacker` -> root, or uid1001 -> service-account -> root, LPE validated from default writable/group-writable/SGID directories, ACL-looking mode mismatches, or default root consumers.

## Baseline

Host/container identity:

```text
attacker:x:1001:1001::/home/attacker:/bin/bash
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_CODENAME=noble
```

Attacker groups:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
mail:x:8:
staff:x:50:
uuidd:x:102:
syslog:x:104:
landscape:x:108:
crontab:x:997:
utmp:x:43:
systemd-journal:x:999:
adm:x:4:ubuntu,syslog
```

Kernel hardening relevant to sticky directory races:

```text
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 1
fs.protected_regular = 2
```

Attacker-writable default directories outside `/home/attacker`:

```text
drwxrwsrwt root root 3777 /var/crash
drwxrwxrwt root root 1777 /tmp
drwxrwxrwt root root 1777 /tmp/.ICE-unix
drwxrwxrwt root root 1777 /tmp/.X11-unix
drwxrwxrwt root root 1777 /tmp/.XIM-unix
drwxrwxrwt root root 1777 /tmp/.font-unix
drwxrwxrwt root root 1777 /var/tmp
```

Default group-writable/SGID directory set:

```text
drwx-wx--T root crontab 1730 /var/spool/cron/crontabs
drwxr-sr-x root systemd-journal 2755 /var/log/journal
drwxr-sr-x root systemd-journal 2755 /var/log/journal/d1550bbf3ee64a61a434283f6f6d03db
drwxrwsr-x root mail 2775 /var/mail
drwxrwsr-x root staff 2775 /var/local
drwxrwsr-x uuidd uuidd 2775 /var/lib/libuuid
drwxrwsrwt root root 3777 /var/crash
drwxrwxr-x root landscape 775 /etc/landscape
drwxrwxr-x root syslog 775 /var/log
drwxrwxrwt root root 1777 /tmp
drwxrwxrwt root root 1777 /var/tmp
```

Direct attacker write probes:

```text
WRITE_OK /tmp -rw-r--r-- 644 attacker attacker /tmp/writable_acl_audit_probe
WRITE_OK /var/tmp -rw-r--r-- 644 attacker attacker /var/tmp/writable_acl_audit_probe
WRITE_OK /var/crash -rw-r--r-- 644 attacker root /var/crash/writable_acl_audit_probe
WRITE_OK /run/lock -rw-r--r-- 644 attacker attacker /run/lock/writable_acl_audit_probe
WRITE_OK /run/screen -rw-r--r-- 644 attacker attacker /run/screen/writable_acl_audit_probe
WRITE_DENY /var/mail touch: cannot touch '/var/mail/writable_acl_audit_probe': Permission denied
WRITE_DENY /var/local touch: cannot touch '/var/local/writable_acl_audit_probe': Permission denied
WRITE_DENY /var/cache/man touch: cannot touch '/var/cache/man/writable_acl_audit_probe': Permission denied
WRITE_DENY /var/lib/libuuid touch: cannot touch '/var/lib/libuuid/writable_acl_audit_probe': Permission denied
WRITE_DENY /var/log/sysstat touch: cannot touch '/var/log/sysstat/writable_acl_audit_probe': Permission denied
WRITE_DENY /var/spool/cron/crontabs touch: cannot touch '/var/spool/cron/crontabs/writable_acl_audit_probe': Permission denied
WRITE_DENY /etc/landscape touch: cannot touch '/etc/landscape/writable_acl_audit_probe': Permission denied
```

No default world-writable regular files were found. The only group-writable regular files in scope were not writable by uid1001:

```text
-rw-rw---- root utmp 660 /var/log/btmp
-rw-rw---- uuidd uuidd 660 /var/lib/libuuid/clock.txt
-rw-rw-r-- root utmp 664 /var/log/lastlog
-rw-rw-r-- root utmp 664 /var/log/wtmp
```

Default setuid/setgid and capabilities were present but did not introduce a writable-directory handoff:

```text
-rwsr-xr-- root messagebus 4754 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x root root 4755 /usr/bin/chfn
-rwsr-xr-x root root 4755 /usr/bin/chsh
-rwsr-xr-x root root 4755 /usr/bin/fusermount3
-rwsr-xr-x root root 4755 /usr/bin/gpasswd
-rwsr-xr-x root root 4755 /usr/bin/mount
-rwsr-xr-x root root 4755 /usr/bin/newgrp
-rwsr-xr-x root root 4755 /usr/bin/passwd
-rwsr-xr-x root root 4755 /usr/bin/su
-rwsr-xr-x root root 4755 /usr/bin/sudo
-rwsr-xr-x root root 4755 /usr/bin/umount
-rwsr-xr-x root root 4755 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x root root 4755 /usr/lib/polkit-1/polkit-agent-helper-1
-rwxr-sr-x root _ssh 2755 /usr/bin/ssh-agent
-rwxr-sr-x root crontab 2755 /usr/bin/crontab
-rwxr-sr-x root shadow 2755 /usr/bin/chage
-rwxr-sr-x root shadow 2755 /usr/bin/expiry
-rwxr-sr-x root shadow 2755 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x root shadow 2755 /usr/sbin/unix_chkpwd
-rwxr-sr-x root utmp 2755 /usr/lib/aarch64-linux-gnu/utempter/utempter
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
/usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p
```

Active default root consumers checked:

```text
cron.service                loaded active running Regular background program processing daemon
rsyslog.service             loaded active running System Logging Service
systemd-journald.service    loaded active running Journal Service
systemd-logind.service      loaded active running User Login Management
systemd-resolved.service    loaded active running Network Name Resolution
systemd-udevd.service       loaded active running Rule-based Manager for Device Events and Files
udisks2.service             loaded active running Disk Manager
unattended-upgrades.service loaded active running Unattended Upgrades Shutdown

sysstat-collect.timer          enabled
sysstat-summary.timer          enabled
man-db.timer                   enabled
logrotate.timer                enabled
systemd-tmpfiles-clean.timer   static
apt-daily.timer                enabled
apt-daily-upgrade.timer        enabled
update-notifier-download.timer enabled
update-notifier-motd.timer     enabled
apport-autoreport.path         enabled
apport-autoreport.timer        enabled
uuidd.socket                   enabled
```

## Candidate notes

### `/tmp`, `/var/tmp`, `/run/lock`

All are sticky world-writable. `/run/lock` is also mounted `tmpfs rw,nosuid,nodev,noexec`.

`fs.protected_regular=2` blocked a root shell redirection into an attacker-owned sticky-dir regular file:

```text
PRE -rw-r--r-- attacker attacker /tmp/writable_acl_audit_regular
ROOT_TRUNCATE_STATUS=2 ERR=sh: 1: cannot create /tmp/writable_acl_audit_regular: Permission denied
 CONTENT=attacker
```

Hardlink pinning of root-owned files was blocked:

```text
HARDLINK_RC=1 ERR=ln: failed to create hard link '/tmp/writable_acl_audit_hardlink' => '/etc/passwd': Operation not permitted
CREATED none
```

The X11 tmpfiles cleanup rule removed an attacker-owned symlink and did not touch its root-owned target:

```text
PRE symbolic link attacker attacker /tmp/.X0-lock -> '/tmp/.X0-lock' -> '/root/writable_acl_audit_x11_sentinel'
SENTINEL_AFTER_TMPFILES=sentinel
LEFT none
```

No default active root service was found that executes attacker content from these directories. Remaining abuse is lock/contention or cleanup interference, which is DoS-only and out of scope.

### `/var/crash`

Mode is unusual but expected for apport:

```text
drwxrwsrwt 3777 root root /var/crash
```

Attacker-created files inherit group `root` because of SGID, but remain uid `attacker`. Default root consumers:

```text
/etc/cron.daily/apport:4:find /var/crash/. ! -name . -prune -type f \( \( -size 0 -a \! -name '*.upload*' -a \! -name '*.drkonqi*' \) -o -mtime +7 \) -exec rm -f -- '{}' \;
/etc/cron.daily/apport:5:find /var/crash/. ! -name . -prune -type d -regextype posix-extended -regex '.*/[0-9]{12}$' \( -mtime +7 \) -exec rm -Rf -- '{}' \;
```

`apport-autoreport.path` is enabled but inactive by default because `/var/lib/apport/autoreport` is absent:

```text
ConditionPathExists=/var/lib/apport/autoreport was not met
```

The root cron cleanup did not follow attacker symlinks into root-owned paths:

```text
PRE symbolic link attacker root /var/crash/writable_acl_audit_old.crash -> '/var/crash/writable_acl_audit_old.crash' -> '/root/writable_acl_audit_sentinel'
PRE directory attacker root /var/crash/123456789012 -> '/var/crash/123456789012'
PRE symbolic link attacker root /var/crash/123456789012/link_to_root -> '/var/crash/123456789012/link_to_root' -> '/root/writable_acl_audit_sentinel'
PRE regular empty file attacker root /var/crash/writable_acl_audit_zero.crash -> '/var/crash/writable_acl_audit_zero.crash'
SENTINEL_AFTER_APPORT=sentinel
```

No root write/execute primitive validated.

### `/run/screen`

Current mode:

```text
drwxrwxrwt 1777 root utmp /run/screen
```

This comes from `/etc/tmpfiles.d/screen-cleanup.conf`:

```text
d /run/screen 1777 root utmp
```

The `screen` binary is not setuid or setgid:

```text
-rwxr-xr-x 1 root root 473008 Jan 22 19:59 /usr/bin/screen
```

Default root interaction is tmpfiles directory creation/mode normalization only. No active root process consumes attacker entries from `/run/screen`.

### `/var/mail`, `/var/local`, `/var/lib/libuuid`

These are SGID group-writable but not attacker-writable:

```text
drwxrwsr-x root mail 2775 /var/mail
drwxrwsr-x root staff 2775 /var/local
drwxrwsr-x uuidd uuidd 2775 /var/lib/libuuid
```

Attacker is not in `mail`, `staff`, or `uuidd`, and direct writes were denied. `uuidd.socket` is world-connectable, but the service runs as `uuidd:uuidd` and is confined to `/var/lib/libuuid` for writes. An attacker-triggered `uuidgen` request returned without leaving a persistent root process:

```text
User=uuidd
Group=uuidd
ReadWritePaths=/var/lib/libuuid/
UUIDD_PID=
srw-rw-rw- 666 root root /run/uuidd/request
drwxrwsr-x 2775 uuidd uuidd /var/lib/libuuid
-rw-rw---- 660 uuidd uuidd /var/lib/libuuid/clock.txt
```

No uid1001 -> uuidd write primitive or uuidd -> root reentry was found.

### `/var/cache/man`

Mode and consumer:

```text
drwxr-xr-x man man 755 /var/cache/man
ExecStart=+/usr/bin/install -d -o man -g man -m 0755 /var/cache/man
ExecStart=/usr/bin/mandb --quiet
User=man
```

The root `install -d` step only recreates/fixes the top-level directory. Attacker cannot write there, and `mandb` runs as `man` with `PrivateTmp=true` and `ProtectSystem=full`.

### `/var/log`, journal, sysstat

`/var/log` is group-writable by `syslog`; attacker is not in `syslog`.

```text
drwxrwxr-x root syslog 775 /var/log
-rw-r----- 640 syslog adm /var/log/syslog
-rw-r----- 640 syslog adm /var/log/auth.log
-rw-r----- 640 syslog adm /var/log/kern.log
```

`rsyslogd` drops to `syslog:syslog` and has no effective capabilities:

```text
Uid:	103	103	103	103
Gid:	104	104	104	104
CapEff:	0000000000000000
```

Root `logrotate` uses fixed configs under `/etc/logrotate.d`; global config includes:

```text
su root adm
create
include /etc/logrotate.d
```

The rsyslog rotate script path is fixed:

```text
/var/log/syslog
/var/log/mail.log
/var/log/kern.log
/var/log/auth.log
/var/log/user.log
/var/log/cron.log
{
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
	sharedscripts
	postrotate
		/usr/lib/rsyslog/rsyslog-rotate
	endscript
}
```

Journal has an ACL marker (`+`), but tmpfiles grants read/search to `adm`, not write; attacker is not `adm`:

```text
drwxr-sr-x+ 1 root systemd-journal 4096 May 16 10:23 /var/log/journal
a+ /var/log/journal    - - - - d:group::r-x,d:group:adm:r-x,group::r-x,group:adm:r-x
a+ /var/log/journal/%m - - - - d:group:adm:r-x,group:adm:r-x
a+ /var/log/journal/%m/system.journal - - - - group:adm:r--
```

Sysstat uses root-owned `/var/log/sysstat` and root-owned config:

```text
drwxr-xr-x root root 755 /var/log/sysstat
/usr/lib/sysstat/sa1:13:SA_DIR=/var/log/sysstat
/usr/lib/sysstat/sa1:26:[ -d /var/log/sysstat ] || mkdir /var/log/sysstat
/usr/lib/sysstat/sa2:11:SA_DIR=/var/log/sysstat
```

No attacker-controlled path reaches root execution.

### Cron spool

Modes:

```text
drwxr-xr-x root root 755 /var/spool/cron
drwx-wx--T root crontab 1730 /var/spool/cron/crontabs
-rwxr-sr-x root crontab 2755 /usr/bin/crontab
```

Direct attacker write to `/var/spool/cron/crontabs` was denied. The setgid `crontab` helper only creates per-user crontabs; cron executes those entries as that user, not root.

## Cleanup

All audit artifacts in the target container were removed. Final check:

```text
find /tmp /var/tmp /var/crash /run/lock /run/screen -xdev -maxdepth 2 \( -name "writable_acl_audit_*" -o -name 123456789012 -o -name .X0-lock \) -printf "LEFT %M %u %g %p -> %l\n"
```

Output was empty.

No `notes/writable_acl_*.md` or `pocs/writable_acl_*.sh|py` was created because no real LPE validated.
