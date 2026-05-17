# Negative: journald, userdb, managed-oom, and system notification sockets

Status: no validated LPE from a normal non-sudo user in the stock Ubuntu 24.04 Server Docker target.

## Target proof

Target container: `ubuntu24-server-lpe-target`

Relevant package versions:

```text
systemd 255.4-1ubuntu8.15
rsyslog 8.2312.0-3ubuntu9.2
util-linux 2.39.3-9ubuntu6.5
```

The target is the stock server task image built with `ubuntu-minimal`, `ubuntu-standard`, and `ubuntu-server`; `apt-get -s full-upgrade` reported `0 upgraded, 0 newly installed, 0 to remove`.

## Default-reachable surface

World-reachable systemd/journal sockets were present by default:

```text
srwxrwxrwx root:root 777 /run/systemd/notify
srw-rw-rw- root:root 666 /run/systemd/userdb/io.systemd.DynamicUser
srw-rw-rw- root:root 666 /run/systemd/io.systemd.ManagedOOM
srw-rw-rw- root:root 666 /run/systemd/journal/stdout
srw-rw-rw- root:root 666 /run/systemd/journal/socket
srw-rw-rw- root:root 666 /run/systemd/journal/dev-log
srw-rw-rw- root:root 666 /run/systemd/journal/syslog
drwxr-sr-x root:systemd-journal 2755 /var/log/journal
-rw-rw-r-- root:utmp 664 /var/log/wtmp
-rw-rw-r-- root:utmp 664 /run/utmp
```

The journald unit confirms intentional unprivileged write reachability:

```text
/usr/lib/systemd/system/systemd-journald.socket:22:ListenDatagram=/run/systemd/journal/socket
/usr/lib/systemd/system/systemd-journald.socket:23:ListenStream=/run/systemd/journal/stdout
/usr/lib/systemd/system/systemd-journald.socket:24:PassCredentials=yes
/usr/lib/systemd/system/systemd-journald.socket:25:PassSecurity=yes
/usr/lib/systemd/system/systemd-journald.socket:28:SocketMode=0666
```

`systemd-journald.service` is sandboxed and receives credentials from the socket:

```text
/usr/lib/systemd/system/systemd-journald.service:30:ExecStart=/usr/lib/systemd/systemd-journald
/usr/lib/systemd/system/systemd-journald.service:31:FileDescriptorStoreMax=4224
/usr/lib/systemd/system/systemd-journald.service:35:NoNewPrivileges=yes
/usr/lib/systemd/system/systemd-journald.service:40:RestrictAddressFamilies=AF_UNIX AF_NETLINK
/usr/lib/systemd/system/systemd-journald.service:41:RestrictNamespaces=yes
/usr/lib/systemd/system/systemd-journald.service:49:Sockets=systemd-journald.socket systemd-journald-dev-log.socket
/usr/lib/systemd/system/systemd-journald.service:61:CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_SYSLOG CAP_AUDIT_CONTROL CAP_AUDIT_READ CAP_CHOWN CAP_DAC_READ_SEARCH CAP_FOWNER CAP_SETUID CAP_SETGID CAP_MAC_OVERRIDE
```

Other default root jobs using the journal database were also present but not attacker-controlled:

```text
/usr/lib/systemd/system/systemd-journal-flush.service:24:ExecStart=journalctl --flush
/usr/lib/systemd/system/systemd-journal-flush.service:25:ExecStop=journalctl --smart-relinquish-var
/usr/lib/systemd/system/systemd-journal-catalog-update.service:25:ExecStart=journalctl --update-catalog
/usr/lib/systemd/system/systemd-update-utmp.service:25:ExecStart=systemd-update-utmp reboot
/usr/lib/systemd/system/systemd-update-utmp.service:26:ExecStop=systemd-update-utmp shutdown
```

## Unprivileged probes

As `attacker`:

```sh
runuser -u attacker -- logger -p authpriv.warning systemd-journal-probe
printf x | nc -U /run/systemd/journal/stdout
runuser -u attacker -- varlinkctl introspect /run/systemd/userdb/io.systemd.DynamicUser io.systemd.UserDatabase
runuser -u attacker -- varlinkctl introspect /run/systemd/io.systemd.ManagedOOM io.systemd.ManagedOOM
runuser -u attacker -- systemd-notify --status=probe
```

Observed journal result:

```text
attacker[15848]: systemd-journal-probe
systemd-journald[28]: Control protocol line not properly terminated.
```

`systemd-notify` without a service notification environment failed as the unprivileged user:

```text
No status data could be sent: $NOTIFY_SOCKET was not set
```

The userdb varlink API exposed read-only lookup methods:

```text
io.systemd.UserDatabase.GetUserRecord(uid,userName,service)
io.systemd.UserDatabase.GetGroupRecord(gid,groupName,service)
io.systemd.UserDatabase.GetMemberships(userName,groupName,service)
```

The managed-oom varlink API exposed subscription only:

```text
io.systemd.ManagedOOM.SubscribeManagedOOMCGroups()
```

## Dead end

The world-writable journald sockets are a default trust boundary, but submitted log records are credential-tagged and do not become root-controlled input for a root command path in the tested default state. Malformed stream input produced journald parser errors only.

The userdb and managed-oom varlink sockets are default reachable, but the exposed methods are read-only lookup/subscription surfaces. No method accepted attacker-controlled root file paths, unit names, environment, or command execution data.

The system notification socket is mode `0777`, but service state mutation is credential/cgroup-bound. A normal shell does not have a valid `NOTIFY_SOCKET` service context, and no root unit transition or command execution path was validated.

## Cleanup

No persistent cleanup was required beyond letting journald rotate normally. Probe messages remained in the journal as expected.

## Why scanners may flag it

Static checks and generic socket enumerators will flag the `0666` and `0777` root-owned sockets. That is not enough for this goal: the reachable methods and credential semantics were checked and did not produce privilege escalation.

## Suggested hardening

No Ubuntu Security issue is claimed from this candidate. Defense-in-depth ideas only:

```text
- Keep PassCredentials=yes on journald sockets and reject records with inconsistent SCM_CREDENTIALS.
- Preserve read-only method shape for userdb and managed-oom varlink services.
- Keep notification handling bound to unit credentials/cgroup membership.
- Add regression tests that unprivileged writes to journald/stdout sockets cannot spoof UID 0 metadata.
```
