# Negative: root daemon sockets and storage/control IPC deep pass

Date: 2026-05-16
Target: `ubuntu24-server-lpe-target`
Image: `ubuntu24-server-default-lpe:20260516-standard`
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`

## Result

No uid1001-to-root local privilege escalation was validated in this lane.

The only default in-scope endpoint that uid1001 can reach and use normally is `/run/uuidd/request`, but the service runs as `uuidd:uuidd` and only issues UUIDs. The only default root-activated endpoint without filesystem DAC is open-iscsi's abstract `@ISCSIADM_ABSTRACT_NAMESPACE`; uid1001 can activate root `iscsid`, but the daemon failed in this Docker kernel before management dispatch (`NETLINK_ISCSI` unsupported), and the package default requires UID-authenticated management IPC. The previously observed `/run/lock/iscsi` symlink primitive still creates an empty root-owned file if root later runs `iscsiadm`, but I found no default uid1001 path that causes root `iscsiadm` to run.

## Default install and listening proof

Package versions:

```text
dmeventd              2:1.02.185-3ubuntu3.2
dmsetup               2:1.02.185-3ubuntu3.2
libopeniscsiusr       2.1.9-3ubuntu5.4
lvm2                  2.03.16-3ubuntu3.2
multipath-tools       0.9.4-5ubuntu8.1
open-iscsi            2.1.9-3ubuntu5.4
systemd/udev          255.4-1ubuntu8.15
util-linux/uuid-runtime 2.39.3-9ubuntu6.5
sysvinit-utils        3.08-6ubuntu3
```

Live unit state:

```text
uuidd.socket active/running, uuidd.service active/running
dm-event.socket active/listening, dm-event.service inactive
lvm2-lvmpolld.socket active/listening, lvm2-lvmpolld.service inactive
multipathd.socket inactive/dead, multipathd.service inactive/dead, ConditionVirtualization=!container unmet
iscsid.socket active/listening, iscsid.service inactive/dead
iscsiuio.socket/service not found
systemd-fsckd.socket inactive/dead
systemd-initctl.socket active/listening
systemd-udevd-control.socket and systemd-udevd.service active/running
systemd-pcrextend.socket inactive/dead, ConditionSecurity=measured-uki unmet
systemd-sysext.socket active/listening
```

Live socket/path state:

```text
srw-rw-rw- root:root /run/uuidd/request
prw------- root:root /run/dmeventd-client
prw------- root:root /run/dmeventd-server
srw------- root:root /run/lvm/lvmpolld.socket
drwx------ root:root /run/multipath
MISSING /run/lock/iscsi
prw------- root:root /run/initctl
srw------- root:root /run/udev/control
MISSING /run/systemd/io.systemd.PCRExtend
srw------- root:root /run/systemd/io.systemd.sysext
MISSING /run/systemd/fsck.progress
```

`/proc/net/unix` had listeners for `/run/lvm/lvmpolld.socket`, `/run/udev/control`, `/run/systemd/io.systemd.sysext`, `/run/uuidd/request`, and `@ISCSIADM_ABSTRACT_NAMESPACE`. It did not have live listeners for multipathd, fsckd, or PCRExtend.

## uuidd

Code/config anchors:

- `/usr/lib/systemd/system/uuidd.socket:5`: `ListenStream=/run/uuidd/request`
- `/usr/lib/systemd/system/uuidd.service:7`: `ExecStart=/usr/sbin/uuidd --socket-activation`
- `/usr/lib/systemd/system/uuidd.service:9-19`: runs as `User=uuidd`, `Group=uuidd`, with strict system protection and `ReadWritePaths=/var/lib/libuuid/`

Runtime proof:

```text
/run/uuidd/request: socket srw-rw-rw- root:root
uuidd process: user/group uuidd:uuidd, euid 101, egid 102
/var/lib/libuuid: drwxrwsr-x uuidd:uuidd
/var/lib/libuuid/clock.txt: -rw-rw---- uuidd:uuidd
```

Attacker commands worked but only returned UUIDs:

```text
uuidgen
uuidgen -t
uuidd -r
uuidd -t
```

A raw uid1001 socket connection to `/run/uuidd/request` succeeded; sending malformed probe bytes produced `ECONNRESET`. I found no root-owned write or privileged command semantic here because the service is not root and its only writeable state is owned by `uuidd`.

## dmeventd and lvmpolld

Code/config anchors:

- `/usr/lib/systemd/system/dm-event.socket:7-10`: two FIFOs, `SocketMode=0600`, `RemoveOnStop=true`
- `/usr/lib/systemd/system/dm-event.service:12`: root `ExecStart=/usr/sbin/dmeventd -f`
- `/usr/lib/systemd/system/lvm2-lvmpolld.socket:8-10`: `/run/lvm/lvmpolld.socket`, `SocketMode=0600`, `RemoveOnStop=true`
- `/usr/lib/systemd/system/lvm2-lvmpolld.service:13`: root `ExecStart=/usr/sbin/lvmpolld -t 60 -f`

uid1001 reachability:

```text
/run/dmeventd-client: open write 13 Permission denied
/run/dmeventd-server: open write 13 Permission denied
/run/lvm/lvmpolld.socket: connect 13 Permission denied
```

LVM/device-mapper commands did not bypass the sockets:

```text
lvm version: device-mapper version ioctl failed: Permission denied
pvscan --cache: Failed to create /run/lvm/pvs_online 13
lvs: /run/lock/lvm/P_global:aux: open failed: Permission denied
dmsetup create attacker_probe: device-mapper version ioctl failed: Permission denied
```

No attacker-reachable daemon parser or root operation was exposed.

## multipathd

Code/config anchors:

- `/usr/lib/systemd/system/multipathd.socket:4-10`: enabled abstract listener `@/org/kernel/linux/storage/multipathd`, gated by `ConditionVirtualization=!container`
- `/usr/lib/systemd/system/multipathd.service:12-20`: same container condition, root `ExecStart=/sbin/multipathd -d -s`
- `/usr/lib/tmpfiles.d/multipath.conf:1`: `/run/multipath` is `0700 root root`

Default Docker state:

```text
multipathd.socket: inactive/dead, ConditionVirtualization=!container was not met
multipathd.service: inactive/dead, ConditionVirtualization=!container was not met
/run/multipath: drwx------ root:root
```

uid1001 tests:

```text
systemctl start multipathd.socket multipathd.service:
  Interactive authentication required

connect("\0/org/kernel/linux/storage/multipathd"):
  111 Connection refused

multipath -ll:
  need to be root
```

This lane remains negative in the Docker target because there is no live multipathd IPC. In a non-container default server this abstract socket should still be tested live; previous source review in this workspace mapped multipathd's client authorization to `SO_PEERCRED`, with non-root clients limited to list/show command families and mutation commands returning `EPERM`.

## open-iscsi, iscsid, iscsiuio, and `/run/lock/iscsi`

Code/config anchors:

- `/usr/lib/systemd/system/iscsid.socket:6`: `ListenStream=@ISCSIADM_ABSTRACT_NAMESPACE`
- `/usr/lib/systemd/system/iscsid.service:10,15-16`: root service, gated only by `ConditionVirtualization=!private-users`, with `ExecStartPre=/usr/lib/open-iscsi/startup-checks.sh` and `ExecStart=/usr/sbin/iscsid`
- `/usr/lib/systemd/system/open-iscsi.service:11-13`: root `iscsiadm` service is inactive by default unless `/etc/iscsi/nodes` or `/sys/class/iscsi_session` exists
- `/usr/lib/systemd/system/open-iscsi.service:23`: `ExecStart=/usr/sbin/iscsiadm -m node --loginall=automatic`
- `/etc/iscsi/iscsid.conf:33-38`: UID-based management IPC auth is the default; `iscsid.ipc_auth_uid = No` remains commented
- `iscsiuio.socket` and `iscsiuio.service`: not found on this target

Default state:

```text
/etc/iscsi: drwxr-xr-x root:root
/etc/iscsi/initiatorname.iscsi: -rw------- root:root
/etc/iscsi/nodes: missing
/run/lock: drwxrwxrwt root:root
/run/lock/iscsi: missing
```

uid1001 management/database tests:

```text
iscsiadm -m node:
  iscsiadm: No records found

iscsiadm -m iface -o new -I codexprobe:
  Could not make /etc/iscsi/ifaces folder(13 Permission denied)

iscsiadm -m discovery -t sendtargets -p 127.0.0.1:
  read error (-1/104), daemon died?
  Could not make /etc/iscsi/send_targets: Permission denied
```

Raw abstract-socket test:

```text
uid1001 connect("@ISCSIADM_ABSTRACT_NAMESPACE"): CONNECT ok
send 128 NUL bytes: ok
recv: Connection reset by peer

journal:
  iSCSI daemon with pid=... started!
  can not create NETLINK_ISCSI socket [Protocol not supported]
  iscsid.service: Main process exited, status=1/FAILURE
```

So uid1001 can trigger root socket activation, but in this Docker target root `iscsid` exits before a useful parser/command path. Source review captured in the earlier storage IPC note maps the normal management IPC gate to `SO_PEERCRED` uid 0 checks before request dispatch in open-iscsi 2.1.9.

The `/run/lock/iscsi` primitive still reproduces:

```text
rm -rf /run/lock/iscsi /tmp/codex-iscsi-root-created
runuser -u attacker -- mkdir -m 700 /run/lock/iscsi
runuser -u attacker -- ln -s /tmp/codex-iscsi-root-created /run/lock/iscsi/lock
/usr/sbin/iscsiadm -m node
```

Result:

```text
/run/lock/iscsi: drwx------ attacker:attacker
/run/lock/iscsi/lock -> /tmp/codex-iscsi-root-created
iscsiadm: No records found
/tmp/codex-iscsi-root-created: regular empty file -rw------- root:root
```

This is not a valid LPE in the default target. uid1001 can prepare the lock path, but cannot make the default root `open-iscsi.service` run because `/etc/iscsi/nodes` is absent and root-owned, `/sys/class/iscsi_session` is absent and not user-creatable, and socket activation starts `iscsid`, not root `iscsiadm`. The root file primitive is also empty-file creation only; no attacker-controlled content write was observed.

## systemd-fsckd

Code/config anchors:

- `/usr/lib/systemd/system/systemd-fsckd.socket:14-15`: `/run/systemd/fsck.progress`, `SocketMode=0600`
- `/usr/lib/systemd/system/systemd-fsckd.service:16`: root `ExecStart=/usr/lib/systemd/systemd-fsckd`

Default state:

```text
systemd-fsckd.socket inactive/dead
/run/systemd/fsck.progress missing
```

Boundary test after manual root activation:

```text
systemctl start systemd-fsckd.socket
/run/systemd/fsck.progress: socket srw------- root:root
uid1001 connect("/run/systemd/fsck.progress"): PermissionError: [Errno 13] Permission denied
```

Cleanup stopped the socket and removed the leftover pathname. No default uid1001-reachable fsck progress parser exists.

## `/run/initctl`

Code/config anchors:

- `/usr/lib/systemd/system/systemd-initctl.socket:17-19`: `/run/initctl`, `/dev/initctl`, `SocketMode=0600`
- `/usr/lib/systemd/system/systemd-initctl.service:16-17`: root `ExecStart=/usr/lib/systemd/systemd-initctl`, `NoNewPrivileges=yes`

uid1001 tests:

```text
/run/initctl: fifo prw------- root:root
/dev/initctl: fifo prw------- root:root
printf x > /run/initctl: Permission denied
printf x > /dev/initctl: Permission denied
telinit 2: Failed to open /run/initctl: Permission denied
telinit q: kill() failed: Operation not permitted
```

The compatibility FIFO parser is not reachable by the scoped user.

## udev control

Code/config anchors:

- `/usr/lib/systemd/system/systemd-udevd-control.socket:19-21`: sequential-packet `/run/udev/control`, `SocketMode=0600`, `PassCredentials=yes`
- `/usr/lib/systemd/system/systemd-udevd.service:25,28,31-43`: root udev service using the control/kernel sockets, with mount/address-family/syscall restrictions

uid1001 tests:

```text
udevadm control --ping:
  Failed to send a ping message: Permission denied

connect("/run/udev/control", SOCK_SEQPACKET):
  13 Permission denied

udevadm trigger --action=change /sys/devices/virtual/mem/null:
  Failed to write 'change' to .../uevent: Permission denied
```

No udev control reload, rule reload, or synthetic root helper execution was reachable through this socket.

## systemd PCRExtend and sysext varlink

Code/config anchors:

- `/usr/lib/systemd/system/systemd-pcrextend.socket:15,18-21`: gated by `ConditionSecurity=measured-uki`, `/run/systemd/io.systemd.PCRExtend`, `SocketMode=0600`, `Accept=yes`
- `/usr/lib/systemd/system/systemd-sysext.socket:16,19-22`: gated by `ConditionCapability=CAP_SYS_ADMIN`, `/run/systemd/io.systemd.sysext`, `SocketMode=0600`, `Accept=yes`

Default state and uid1001 tests:

```text
systemd-pcrextend.socket inactive/dead:
  ConditionSecurity=measured-uki was not met
  /run/systemd/io.systemd.PCRExtend missing
  varlinkctl info: No such file or directory

systemd-sysext.socket active/listening:
  /run/systemd/io.systemd.sysext srw------- root:root
  varlinkctl info as uid1001: Permission denied
  raw connect as uid1001: 13 Permission denied
```

The sysext varlink service has privileged merge/unmerge/refresh semantics, but uid1001 cannot reach the socket. PCRExtend is not instantiated in this default Docker target.

## Cleanup performed

```sh
systemctl stop systemd-fsckd.socket systemd-fsckd.service || true
rm -f /run/systemd/fsck.progress
rm -rf /run/lock/iscsi /tmp/codex-iscsi-root-created \
  /tmp/codex-iscsiadm.out /tmp/codex-iscsiadm.err
systemctl reset-failed iscsid.service iscsid.socket \
  multipathd.service multipathd.socket systemd-pcrextend.socket \
  systemd-fsckd.socket || true
systemctl start iscsid.socket || true
```

Post-cleanup:

```text
iscsid.socket active/listening
systemd-fsckd.socket inactive/dead
/run/lock/iscsi missing
/run/systemd/fsck.progress missing
/tmp/codex-iscsi-root-created missing
@ISCSIADM_ABSTRACT_NAMESPACE listening again
```

## Scanner-miss notes

- `systemctl list-sockets --all` lists inactive or condition-skipped units such as multipathd, fsckd, and PCRExtend. Confirm actual default reachability with `systemctl show`, `stat`, and `/proc/net/unix`.
- `/run/uuidd/request` is world-writable by design. Treat it as low risk only after verifying the daemon account and writable state; here it is `uuidd:uuidd`, not root.
- Abstract sockets need special handling because filesystem mode scanners cannot see DAC. The default iscsid abstract socket is attacker-reachable and root-activated, but management IPC needs peer credential review and the Docker kernel blocks `NETLINK_ISCSI`.
- Sticky `/run/lock` primitives are easy to miss. `/run/lock/iscsi` permits cross-user lock-path precreation and root empty-file creation on later root `iscsiadm`, but exploitability depends on a default root trigger and attacker-controlled content, neither of which was present.
- Unit-file `SocketMode=0600` is decisive for dmeventd, lvmpolld, fsckd, initctl, udev control, PCRExtend, and sysext. Attempts to fuzz parsers behind those endpoints are not meaningful from uid1001 unless the DAC boundary is bypassed first.
