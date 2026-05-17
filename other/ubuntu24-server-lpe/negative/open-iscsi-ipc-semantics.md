# Negative: open-iscsi socket activation and database semantics

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server Docker target  
Result: no validated uid1001-to-root LPE. `ROOT_PROOF=no`.

## Default proof

Packages and identity from `logs/open-iscsi-ipc-semantics.out`:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
open-iscsi        2.1.9-3ubuntu5.4
libopeniscsiusr   2.1.9-3ubuntu5.4
systemd           255.4-1ubuntu8.15
```

The root daemon socket is enabled and listens on an abstract Unix socket:

```text
/usr/lib/systemd/system/iscsid.socket:
ListenStream=@ISCSIADM_ABSTRACT_NAMESPACE
WantedBy=sockets.target
```

The activated daemon runs as root:

```text
/usr/lib/systemd/system/iscsid.service:
ExecStartPre=/usr/lib/open-iscsi/startup-checks.sh
ExecStart=/usr/sbin/iscsid
ConditionVirtualization=!private-users
```

The root login service is enabled but default-condition-gated without configured
nodes or an existing kernel iSCSI session:

```text
/usr/lib/systemd/system/open-iscsi.service:
ConditionDirectoryNotEmpty=|/etc/iscsi/nodes
ConditionDirectoryNotEmpty=|/sys/class/iscsi_session
ExecStart=/usr/sbin/iscsiadm -m node --loginall=automatic
```

Default root database state:

```text
drwxr-xr-x root:root /etc/iscsi
-rw------- root:root /etc/iscsi/initiatorname.iscsi
-rw-r--r-- root:root /etc/iscsi/iscsid.conf
```

## Trigger attempts

The probe first removed any test-created `/etc/iscsi/nodes`,
`/etc/iscsi/send_targets`, and `/run/lock/iscsi` state, then ran:

```sh
runuser -u attacker -- iscsiadm -m node --op new \
  --targetname iqn.2026-05.invalid:codex --portal 127.0.0.1:3260
runuser -u attacker -- iscsiadm -m discoverydb -t sendtargets \
  -p 127.0.0.1:3260 --op new
runuser -u attacker -- iscsiadm -m discoverydb -t sendtargets \
  -p 127.0.0.1:3260 --op update \
  -n discovery.sendtargets.auth.authmethod -v None
runuser -u attacker -- timeout 8 iscsiadm -m discovery -t sendtargets \
  -p 127.0.0.1:3260
```

Observed results:

```text
node_new_rc=6
iscsiadm: read error (-1/104), daemon died?
iscsiadm: Could not make /etc/iscsi/ifaces. HW/OFFLOAD iscsi may not be supported
iscsiadm: Error while adding record: encountered iSCSI database failure

discoverydb_new_rc=6
iscsiadm: Could not make /etc/iscsi/send_targets: Permission denied

discoverydb_update_rc=6
iscsiadm: Discovery record [127.0.0.1,3260] not found.

discovery_rc=6
iscsiadm: can not connect to iSCSI daemon (111)!
iscsiadm: Could not make /etc/iscsi/send_targets: Permission denied
```

Socket activation did start root `iscsid`, but the Docker host kernel lacks
`NETLINK_ISCSI`, so the daemon exited before accepting useful root-side
database or session operations:

```text
iscsid: iSCSI daemon with pid=252554 started!
iscsid: can not create NETLINK_ISCSI socket [Protocol not supported]
iscsid.service: Main process exited, code=exited, status=1/FAILURE
iscsid.socket: Failed with result 'service-start-limit-hit'
```

No root-owned iSCSI records were created:

```text
-rw------- root:root /etc/iscsi/initiatorname.iscsi
-rw-r--r-- root:root /etc/iscsi/iscsid.conf
drwxr-xr-x root:root /etc/iscsi
```

## Conclusion

This is a real default root IPC boundary and is adjacent to the earlier
`/run/lock/iscsi` root empty-file primitive. In this stock Docker Server target,
uid1001 can cause socket activation of root `iscsid`, but cannot keep the daemon
alive, cannot write `/etc/iscsi` node/discovery records, cannot satisfy
`open-iscsi.service` conditions, and cannot make the root `iscsiadm
--loginall=automatic` path consume attacker-controlled state.

No root marker was produced:

```text
ROOT_PROOF=no
systemctl is-system-running -> running
systemctl --failed --no-legend -> no failed units
```

## Cleanup

The probe restores any pre-existing `/etc/iscsi/nodes` and
`/etc/iscsi/send_targets` directories, removes `/run/lock/iscsi`, resets
`iscsid.service`/`iscsid.socket`, restarts `iscsid.socket`, and removes
`/tmp/open-iscsi-ipc-semantics` plus `/root/open_iscsi_ipc_semantics_root`.

## Why scanners may miss it

A socket listing shows an enabled root abstract socket and an unprivileged client
binary. The exploitable boundary depends on live daemon startup, kernel iSCSI
support, root database write ownership, systemd conditions, and whether
`iscsiadm` operations happen client-side as uid1001 or daemon-side as root. That
requires semantic testing rather than static IPC enumeration.
