# Negative: journald, notify, and systemd world-writable sockets

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, Docker-only Ubuntu 24.04.4 Server userspace target after full upgrade. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no uid1001-to-root LPE validated. The sockets are default-installed, default-active, and intentionally writable, but the live tests only allowed attacker-attributed logging/query traffic. No root file write, unit state change, root command execution, or privileged file descriptor transfer was found.

## Package and default proof

```text
systemd 255.4-1ubuntu8.15
rsyslog 8.2312.0-3ubuntu9.2
util-linux 2.39.3-9ubuntu6.5
```

Active units:

```text
systemd-journald.service               loaded active running Journal Service
systemd-journald-dev-log.socket        loaded active running Journal Socket (/dev/log)
systemd-journald.socket                loaded active running Journal Socket
systemd-journal-catalog-update.service loaded active exited  Rebuild Journal Catalog
systemd-journal-flush.service          loaded active exited  Flush Journal to Persistent Storage
```

Relevant socket modes:

```text
srw-rw-rw- root:root /run/systemd/journal/dev-log
srw-rw-rw- root:root /run/systemd/journal/socket
srw-rw-rw- root:root /run/systemd/journal/stdout
srw-rw-rw- root:root /run/systemd/journal/syslog
srwxrwxrwx root:root /run/systemd/notify
srw-rw-rw- root:root /run/systemd/userdb/io.systemd.DynamicUser
srw-rw-rw- root:root /run/systemd/io.systemd.ManagedOOM
```

Unit line refs:

```text
/usr/lib/systemd/system/systemd-journald.socket:22 ListenDatagram=/run/systemd/journal/socket
/usr/lib/systemd/system/systemd-journald.socket:23 ListenStream=/run/systemd/journal/stdout
/usr/lib/systemd/system/systemd-journald.socket:24 PassCredentials=yes
/usr/lib/systemd/system/systemd-journald.socket:28 SocketMode=0666
/usr/lib/systemd/system/systemd-journald.service:30 ExecStart=/usr/lib/systemd/systemd-journald
/usr/lib/systemd/system/systemd-journald.service:35 NoNewPrivileges=yes
/usr/lib/systemd/system/systemd-journald.service:40 RestrictAddressFamilies=AF_UNIX AF_NETLINK
/usr/lib/systemd/system/systemd-journald.service:49 Sockets=systemd-journald.socket systemd-journald-dev-log.socket
```

## Probes

Attacker log injection remained attributed to uid1001:

```sh
runuser -u attacker -- logger -p authpriv.warning systemd-journal-probe
journalctl -n 5 --no-pager
```

Observed:

```text
attacker[15848]: systemd-journal-probe
```

Raw writes to the stream protocol did not create a root-controlled write primitive:

```sh
runuser -u attacker -- sh -lc 'printf x | nc -U /run/systemd/journal/stdout'
```

Observed journal error:

```text
systemd-journald[28]: Control protocol line not properly terminated.
```

Varlink surfaces were read-only or subscription-only:

```text
io.systemd.UserDatabase.GetUserRecord/GetGroupRecord/GetMemberships
io.systemd.ManagedOOM.SubscribeManagedOOMCGroups
io.systemd.Resolve.ResolveHostname/ResolveAddress
```

`systemd-notify` from the attacker could not affect unit state without a notify socket in the service context:

```text
No status data could be sent: $NOTIFY_SOCKET was not set
```

## Dead end

The writable socket modes are a real default attack surface, but systemd passes credentials on journald sockets and records the sender as the attacker. The stream protocol rejected malformed attacker input, persistent journal files are `root:systemd-journal` and not attacker-writable, and varlink endpoints exposed no method that mutates root-owned configuration or executes helpers. No privilege increase was achieved.

Cleanup: removed `/tmp/journal_stdout_probe`; no linger files, test units, or attacker-owned files under `/run/systemd` remained.
