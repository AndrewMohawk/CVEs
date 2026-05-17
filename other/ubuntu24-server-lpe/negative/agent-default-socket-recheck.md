# Negative: less-common default socket recheck

Date: 2026-05-17
Target: `ubuntu24-server-lpe-target`
Image: `ubuntu24-server-default-lpe:20260516-standard`
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`
PoC: `pocs/agent_default_socket_recheck.sh`
Log: `logs/agent_default_socket_recheck.out`

## Result

No uid1001-to-root LPE was validated in the default socket-activated daemon
lane. Final probe state was:

```text
ROOT_PROOF=NO
systemctl is-system-running -> running
systemctl --failed --no-legend -> empty
losetup -a -> empty
```

The probe checked the default `systemctl list-sockets --all` surface for
`multipathd`, `iscsid`, `dm-event`, `lvm2-lvmpolld`, `apport-forward`,
`systemd-fsckd`, `systemd-pcrextend`, `systemd-sysext`, `systemd-initctl`,
`snapd`, `lxd-installer`, `uuidd`, journald stdout/dev-log/syslog, and related
runtime paths.

## Default proof

Packages from the target:

```text
apport 2.28.1-0ubuntu3.8
dmeventd/dmsetup 2:1.02.185-3ubuntu3.2
lvm2 2.03.16-3ubuntu3.2
lxd-installer 4ubuntu0.1
multipath-tools 0.9.4-5ubuntu8.1
open-iscsi/libopeniscsiusr 2.1.9-3ubuntu5.4
rsyslog 8.2312.0-3ubuntu9.2
snapd 2.74.1+ubuntu24.04.4
systemd/systemd-sysv/udev 255.4-1ubuntu8.15
util-linux/libuuid1/uuid-runtime 2.39.3-9ubuntu6.5
```

Default sockets from the live target included:

```text
@/org/kernel/linux/storage/multipathd -> multipathd.socket
@ISCSIADM_ABSTRACT_NAMESPACE -> iscsid.socket
/run/apport.socket -> apport-forward.socket
/run/dmeventd-client, /run/dmeventd-server -> dm-event.socket
/run/lvm/lvmpolld.socket -> lvm2-lvmpolld.socket
/run/lxd-installer.socket -> lxd-installer.socket
/run/snapd.socket, /run/snapd-snap.socket -> snapd.socket
/run/systemd/fsck.progress -> systemd-fsckd.socket
/run/systemd/io.systemd.PCRExtend -> systemd-pcrextend.socket
/run/systemd/io.systemd.sysext -> systemd-sysext.socket
/run/initctl and /dev/initctl -> systemd-initctl.socket
/run/uuidd/request -> uuidd.socket
/run/systemd/journal/{socket,stdout,dev-log,syslog} -> journald/syslog
```

Key packaged unit boundaries were captured with line numbers in the log:

```text
multipathd.socket: ConditionVirtualization=!container, ListenStream=@/org/kernel/linux/storage/multipathd
iscsid.socket: ListenStream=@ISCSIADM_ABSTRACT_NAMESPACE
open-iscsi.service: gated by /etc/iscsi/nodes or /sys/class/iscsi_session
dm-event.socket: /run/dmeventd-* FIFOs, SocketMode=0600
lvm2-lvmpolld.socket: /run/lvm/lvmpolld.socket, SocketMode=0600
apport-forward.socket: /run/apport.socket, SocketMode=0600, PassCredentials=true
systemd-fsckd.socket: /run/systemd/fsck.progress, SocketMode=0600
systemd-pcrextend.socket: ConditionSecurity=measured-uki, SocketMode=0600
systemd-sysext.socket: ConditionCapability=CAP_SYS_ADMIN, SocketMode=0600
systemd-initctl.socket: /run/initctl plus /dev/initctl, SocketMode=0600
snapd.socket: /run/snapd.socket and /run/snapd-snap.socket, SocketMode=0666
lxd-installer.socket: /run/lxd-installer.socket, root:lxd 0660
uuidd.service: User=uuidd, Group=uuidd, ReadWritePaths=/var/lib/libuuid/
systemd-journald.socket/dev-log/syslog: SocketMode=0666 with PassCredentials/PassSecurity
```

## Trigger results

Root-only socket paths blocked uid1001 before parser reachability:

```text
/run/apport.socket -> EACCES
/run/lvm/lvmpolld.socket -> EACCES
/run/lxd-installer.socket -> EACCES
/run/initctl and /dev/initctl -> EACCES
/run/systemd/io.systemd.sysext -> EACCES
/run/dmeventd-client and /run/dmeventd-server -> Permission denied
```

Inactive or condition-gated sockets were not reachable:

```text
/run/systemd/fsck.progress -> ENOENT
/run/systemd/io.systemd.PCRExtend -> ENOENT
multipath abstract socket -> ECONNREFUSED in Docker because ConditionVirtualization=!container
```

Reachable sockets did not produce privilege:

```text
iscsid abstract socket: first connect succeeded, then root iscsid exited before useful dispatch:
  can not create NETLINK_ISCSI socket [Protocol not supported]
  iscsid.socket: Failed with result 'service-start-limit-hit'

snapd /run/snapd.socket:
  GET /v2/system-info -> 200
  POST install/start payloads carrying the root marker -> 401 login-required
  /run/snapd-snap.socket -> 403 could not determine snap name for pid

uuidd /run/uuidd/request:
  UUID requests succeeded, but daemon ran as uuidd:uuidd and only wrote uuidd-owned clock state

journald/syslog sockets:
  spoof payloads were accepted as log records, but journal attribution kept _UID=1001 and _CAP_EFFECTIVE=0 for the attacker sender; `_UID=0` fields stayed message/raw text
```

Additional client commands stayed blocked:

```sh
iscsiadm -m discoverydb -t sendtargets -p 127.0.0.1:3260 --op new
iscsiadm -m discovery -t sendtargets -p 127.0.0.1:3260
multipath -ll
multipathd -k'show daemon'
lvm fullreport --config 'global { use_lvmpolld=1 }'
systemd-sysext merge
/sbin/lxc version
telinit 3
```

All failed due to DAC, polkit/systemd auth, default service conditions, missing
kernel support in the Docker target, or non-root service-account confinement.

## Root marker

The probe injected `/root/agent_default_socket_recheck_root` into raw textual,
HTTP, abstract-socket, journald/syslog, LVM, initctl, snapd, and lxd-installer
payloads. The marker was absent at the end:

```text
absent /root/agent_default_socket_recheck_root
absent /tmp/agent_default_socket_recheck_root
ROOT_PROOF=NO
```

## Cleanup

The probe removed:

```text
/root/agent_default_socket_recheck_root
/tmp/agent_default_socket_recheck_root
/tmp/agent-default-socket-recheck*
/run/lock/iscsi
```

It also reset failed state for the socket services it intentionally stressed
and restarted default active sockets. Final target health was `running`, with no
failed units and no loop devices.

## Why scanners may miss this

Static socket enumerators over-rank this lane because several root-owned sockets
are world-connectable or abstract and therefore have no filesystem mode:
`snapd`, `uuidd`, journald/syslog, and `iscsid`. The exploitability hinge was in
the semantic boundary: systemd unit conditions, `SocketMode`, Unix peer
credentials, `PassCredentials`, snapd route authentication, uuidd's service-user
drop, and open-iscsi's daemon startup/IPC split. A generic fuzzer can reach some
parsers but will not show a privilege increase without proving the root-side
operation that consumes attacker-controlled data.

## Triage fix guidance

No Ubuntu Security issue is claimed from this pass. Hardening/regression ideas:

```text
- Keep 0600 modes on root parser/control sockets.
- Preserve PassCredentials/PassSecurity on journald and syslog sockets.
- Keep snapd mutating routes behind login/polkit and reject non-snap peers on /run/snapd-snap.socket.
- Keep uuidd running as uuidd:uuidd with only /var/lib/libuuid writable.
- Consider rate-limiting or quieter handling for unprivileged iscsid abstract-socket activation in container kernels where NETLINK_ISCSI is unsupported.
```
