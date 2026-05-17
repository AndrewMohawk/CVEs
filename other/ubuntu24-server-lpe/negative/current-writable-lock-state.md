# Negative: current writable and lock-state refresh

Date: 2026-05-17
Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS
Result: no validated uid1001-to-root LPE.

## Scope

This pass refreshed the live writable filesystem, group-writable state, world sockets, and sticky lock directories after the previous candidate work. The goal was to find a default root consumer of attacker-precreated names, especially under `/run/lock`, `/var/crash`, `/tmp`, `/var/tmp`, and service runtime sockets.

## Live state

The attacker identity remained:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

The relevant writable/default-reachable roots were:

```text
1777 root:root /tmp
1777 root:root /var/tmp
1777 root:root /run/lock
1777 root:utmp /run/screen
3777 root:root /var/crash
2775 root:mail /var/mail
2775 root:staff /var/local
2775 uuidd:uuidd /var/lib/libuuid
775 root:landscape /etc/landscape
775 root:syslog /var/log
666 root:root /run/dbus/system_bus_socket
666 root:root /run/snapd.socket
666 root:root /run/snapd-snap.socket
666 root:root /run/systemd/journal/socket
666 root:root /run/systemd/journal/stdout
666 root:root /run/systemd/userdb/io.systemd.DynamicUser
666 root:root /run/systemd/io.systemd.ManagedOOM
666 root:root /run/uuidd/request
777 root:root /run/systemd/notify
```

uid1001 is not in `mail`, `staff`, `uuidd`, `landscape`, `syslog`, `utmp`, or `crontab`, so group-writable service paths did not become writable to the attacker. Direct `find` as uid1001 showed only the expected sticky directories, the attacker's home/cache, and stale attacker-owned probe files under `/tmp`.

## Lock consumers

`/run/lock` is mounted as sticky tmpfs:

```text
tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime
drwxrwxrwt root:root /run/lock
```

The only root-impacting precreation primitive still identified in the live grep pass was the previously documented open-iscsi lock reuse. It remains non-countable because default root `open-iscsi.service` is condition-gated without `/etc/iscsi/nodes` or `/sys/class/iscsi_session`, and uid1001 cannot trigger root `iscsiadm`.

Other lock users either use root-owned directories, fixed root state, or advisory `flock` on root-owned files. No default active root service consumed an attacker-created `/run/lock` name as a command, config file, writable target with attacker content, or symlink-following root write.

## Root proof

No root marker was created, and the target remained healthy:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend | wc -l -> 0
```

## Why scanners miss it

Mode scans over-rank this lane because many root-owned sockets are intentionally `0666`, `/run/lock` and `/var/crash` are writable, and several service accounts own group-writable state. The exploitable question is whether uid1001 is in the relevant groups and whether a default root consumer later opens attacker-precreated names unsafely. In this target, those follow-on consumers were either absent, condition-gated, credential-bound, or used root-owned paths.
