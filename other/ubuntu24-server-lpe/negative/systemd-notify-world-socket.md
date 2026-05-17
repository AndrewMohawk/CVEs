# Negative: systemd notify socket spoofing/fd-store

Status: no validated LPE.

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

## Default proof

The systemd notify socket is world-writable by design:

```text
srwxrwxrwx root:root socket /run/systemd/notify
systemd 255.4-1ubuntu8.15
```

Default services using notify/fd-store in the target included:

```text
dbus.service               Type=notify        NotifyAccess=main FDStore=0
rsyslog.service            Type=notify        NotifyAccess=main FDStore=0
systemd-journald.service   Type=notify        NotifyAccess=main FDStore=4224
systemd-logind.service     Type=notify-reload NotifyAccess=main FDStore=512
systemd-resolved.service   Type=notify        NotifyAccess=main FDStore=0
systemd-udevd.service      Type=notify-reload NotifyAccess=main FDStore=0
snapd.service              Type=notify        NotifyAccess=all  FDStore=0, inactive
```

## Tested triggers

Attacker sends to `/run/systemd/notify` return success:

```sh
runuser -u attacker -- bash -lc \
  'NOTIFY_SOCKET=/run/systemd/notify systemd-notify --ready --status=ubulpe-attacker-status; echo rc:$?'
```

Observed:

```text
rc:0
```

Spoofing root service PIDs did not change their systemd status text:

```sh
for u in rsyslog.service systemd-journald.service systemd-logind.service dbus.service systemd-resolved.service; do
  pid=$(systemctl show "$u" -p MainPID --value)
  before=$(systemctl show "$u" -p StatusText --value)
  runuser -u attacker -- bash -lc \
    "NOTIFY_SOCKET=/run/systemd/notify systemd-notify --pid=$pid --status=ubulpe-$u-spoof --ready; echo rc:\\$?"
  after=$(systemctl show "$u" -p StatusText --value)
  printf '%s before=%s after=%s\n' "$u" "$before" "$after"
done
```

Observed:

```text
rsyslog.service before= after=
systemd-journald.service before=Processing requests... after=Processing requests...
systemd-logind.service before=Processing requests... after=Processing requests...
dbus.service before= after=
systemd-resolved.service before=Processing requests... after=Processing requests...
```

FD-store attempts against services with `FileDescriptorStoreMax` also did not change stored FD counts:

```sh
before=$(systemctl show systemd-journald.service -p NFileDescriptorStore --value)
runuser -u attacker -- bash -lc '
  for i in 1 2 3; do
    exec 3</etc/passwd
    NOTIFY_SOCKET=/run/systemd/notify systemd-notify --fd=3 --fdname=ubulpe$i --status=fdstore-$i
    echo send$i rc:$?
    exec 3<&-
  done'
after=$(systemctl show systemd-journald.service -p NFileDescriptorStore --value)
```

Observed:

```text
before=14
send1 rc:0
send2 rc:0
send3 rc:0
after=14
```

## Why this is not a finding

The socket is reachable, but PID1 did not attribute attacker datagrams or passed file descriptors to root services. `systemd-notify` returning `0` only means the datagram was sent; it does not prove PID1 accepted the state transition or fd-store request. `NotifyAccess=main` services ignored spoofed `MAINPID`/`STATUS`/`READY`, and journald's fd-store count stayed unchanged.

No root code execution, root-owned attacker-controlled file write, accepted fd-store injection, or service state takeover was reached.

## Cleanup

No persistent files were created.

## Suggested hardening

No proven security fix. For diagnostics, operators should not treat successful `systemd-notify` exit status from an arbitrary process as evidence that PID1 accepted the notification.
