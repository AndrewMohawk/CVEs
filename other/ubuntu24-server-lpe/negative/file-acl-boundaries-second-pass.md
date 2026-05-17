# Negative: file/group/ACL trust-boundary second pass

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`.

Result: no default Ubuntu 24.04 Server uid1001 `attacker` to root LPE was validated in this file/group/ACL lane. No root proof exists from this pass.

Reproducer: `pocs/file_acl_probe.sh ubuntu24-server-lpe-target`

## Default install and reachability proof

Target identity:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
Linux 4f5b414436ae 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
attacker supplementary groups: attacker
```

Relevant default package proof:

```text
util-linux 2.39.3-9ubuntu6.5
bsdextrautils 2.39.3-9ubuntu6.5
libutempter0 1.2.1-3build1
cron 3.0pl1-184ubuntu2
logrotate 3.21.0-2build1
rsyslog 8.2312.0-3ubuntu9.2
apport 2.28.1-0ubuntu3.8
systemd 255.4-1ubuntu8.15
uuid-runtime 2.39.3-9ubuntu6.5
postfix not-installed
mailutils not-installed
bsd-mailx uninstalled
```

Helper modes:

```text
/usr/bin/write                               root:root 0755
/usr/bin/wall                                root:root 0755
/usr/lib/aarch64-linux-gnu/utempter/utempter root:utmp 2755
/usr/bin/mail                                absent
/usr/bin/mailx                               absent
/usr/sbin/sendmail                           absent
/usr/bin/crontab                             root:crontab 2755
```

`write --help` and `wall --timeout 1 attacker_file` were reachable as the attacker, but both helpers are plain `0755 root:root`; no setuid/setgid transition was present. `utempter` is reachable through `libutempter` and could add/remove a bounded utmp record for the attacker's PTY, but left no stale record and did not produce arbitrary file write or root execution.

## Writable and group-writable surface

Default writable/group-writable items in the probe:

```text
-rw-rw---- root utmp  /var/log/btmp
-rw-rw---- uuidd uuidd /var/lib/libuuid/clock.txt
-rw-rw-r-- root utmp  /run/utmp
-rw-rw-r-- root utmp  /var/log/lastlog
-rw-rw-r-- root utmp  /var/log/wtmp
drwx-wx--T root crontab /var/spool/cron/crontabs
drwxrwsr-x root mail    /var/mail
drwxrwsr-x root staff   /var/local
drwxrwsr-x uuidd uuidd  /var/lib/libuuid
drwxrwsrwt root root    /var/crash
drwxrwxr-x root landscape /etc/landscape
drwxrwxr-x root syslog  /var/log
drwxrwxrwt root root    /run/lock
drwxrwxrwt root root    /tmp
drwxrwxrwt root root    /var/tmp
drwxrwxrwt root utmp    /run/screen
```

The normal attacker is only in group `attacker`, so direct writes were denied to `/var/mail`, `/var/local`, `/var/lib/libuuid`, `/etc/landscape`, `/var/log`, `/var/spool/cron/crontabs`, `/var/cache/man`, `/etc/cron.d`, `/etc/logrotate.d`, `/etc/tmpfiles.d`, `/usr/local/bin`, and `/usr/local/sbin`.

Group-writable regular files did not expose a write primitive:

```text
APPEND_DENY /run/utmp
APPEND_DENY /var/log/wtmp
APPEND_DENY /var/log/btmp
APPEND_DENY /var/log/lastlog
APPEND_DENY /var/lib/libuuid/clock.txt
READ_OK /run/utmp
READ_OK /var/log/wtmp
READ_DENY /var/log/btmp
READ_OK /var/log/lastlog
READ_DENY /var/lib/libuuid/clock.txt
```

## Root consumers

Active/default root consumers in scope included `cron.service`, `rsyslog.service`, `logrotate.timer`, `systemd-tmpfiles-clean.timer`, `systemd-update-utmp.service`, and the tmpfiles setup services.

Relevant config observed:

```text
/etc/tmpfiles.d/screen-cleanup.conf: d /run/screen 1777 root utmp
/usr/lib/tmpfiles.d/x11.conf: r! /tmp/.X[0-9]*-lock
/usr/lib/tmpfiles.d/var.conf: f /var/log/wtmp 0664 root utmp -
/usr/lib/tmpfiles.d/var.conf: f /var/log/btmp 0660 root utmp -
/usr/lib/tmpfiles.d/var.conf: f /var/log/lastlog 0664 root utmp -
/usr/lib/tmpfiles.d/cron-daemon-common.conf: d /var/spool/cron/crontabs 1730 root crontab
/usr/lib/tmpfiles.d/00rsyslog.conf: z /var/log 0775 root syslog -
/etc/cron.daily/apport: find /var/crash/. ... -exec rm -f -- '{}' ;
/etc/cron.daily/apport: find /var/crash/. ... -exec rm -Rf -- '{}' ;
/etc/logrotate.d/rsyslog: fixed /var/log/syslog, mail.log, kern.log, auth.log, user.log, cron.log
/etc/logrotate.d/wtmp: /var/log/wtmp
/etc/logrotate.d/btmp: /var/log/btmp
```

Attacker append to root-rotated logs was denied for `/var/log/syslog`, `/var/log/auth.log`, `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog`, `/var/log/dpkg.log`, and `/var/log/apt/history.log`. `logrotate -d /etc/logrotate.conf` read root-owned configs and considered fixed root-owned log paths; no attacker-controlled config or path reached root execution.

## Link and sticky-dir protections

Kernel hardening:

```text
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 1
```

Hardlink attempts from attacker-writable directories to `/etc/shadow` failed:

```text
/tmp       Invalid cross-device link
/var/tmp   Operation not permitted
/run/lock  Invalid cross-device link
/run/screen Invalid cross-device link
/var/crash Operation not permitted
```

Root shell truncation into attacker-owned regular files in sticky directories was blocked by `fs.protected_regular=2`:

```text
ROOT_TRUNCATE /tmp rc=2 Permission denied
ROOT_TRUNCATE /var/tmp rc=2 Permission denied
ROOT_TRUNCATE /run/lock rc=2 Permission denied
ROOT_TRUNCATE /run/screen rc=2 Permission denied
ROOT_TRUNCATE /var/crash rc=2 Permission denied
```

Tmpfiles and cron cleanup did not follow attacker symlinks into root-owned targets:

```text
/tmp/.X0-lock -> /root/file_acl_probe_root_marker
/root/file_acl_probe_root_marker remained root:root with original sentinel content

/run/screen/file_acl_probe_link -> /root/file_acl_probe_screen_marker
/root/file_acl_probe_screen_marker remained absent

/var/crash/file_acl_probe_old.crash -> /root/file_acl_probe_root_marker
/var/crash/123456789012/link -> /root/file_acl_probe_crash_dir_marker
/root/file_acl_probe_root_marker remained intact
/root/file_acl_probe_crash_dir_marker remained absent
```

The Apport cron cleanup removed the attacker-created old empty crash file and numeric crash directory, but did not create or modify the root symlink targets.

## Conclusion

This second pass did not find a default normal-user to root escalation. The remaining exposed surfaces are bounded accounting writes (`utempter`/utmp), readable accounting metadata (`wtmp`, `lastlog`, `/run/utmp`), and sticky-directory cleanup/removal behavior. None produced root command execution, arbitrary root file write, root-owned helper execution from an attacker path, or a root proof artifact.

The probe cleaned its test artifacts and ended with:

```text
no root proof marker remains
```
