# Negative note: default storage/IPC sockets

Date: 2026-05-16
Target: `ubuntu24-server-lpe-target`
Image: `ubuntu24-server-default-lpe:20260516-standard`
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`

## Result

No local privilege escalation was validated in this storage/IPC slice.

The in-scope services are default-installed and mostly default-enabled on the target, but the reachable paths either reject `attacker` before privileged operations, are root-only by socket mode, or run as a non-root service account. No root-owned config write, device attach, root helper execution, or root shell was achieved.

## Default install and enabled proof

Baseline evidence from `baseline/live-target-standard`:

- `open-iscsi 2.1.9-3ubuntu5.4`: `packages.txt:405`
- `lxd-installer 4ubuntu0.1`: `packages.txt:382`
- `lvm2 2.03.16-3ubuntu3.2` and `dmeventd 2:1.02.185-3ubuntu3.2`: `packages.txt:380`, `packages.txt:56`
- `multipath-tools 0.9.4-5ubuntu8.1`: `packages.txt:392`
- `uuid-runtime 2.39.3-9ubuntu6.5`: verified live with `dpkg-query -W`
- `systemd/udev 255.4-1ubuntu8.15`: `packages.txt:522`, `packages.txt:548`
- `attacker` is a normal user only: `users-groups.txt:33`, `users-groups.txt:94`
- `lxd`, `disk`, `uuidd`, `sudo`, and `adm` do not include `attacker`: `users-groups.txt:40`, `users-groups.txt:56`, `users-groups.txt:83`, `users-groups.txt:84`

Default active/enabled units:

- `dm-event.socket`, `iscsid.socket`, `lvm2-lvmpolld.socket`, `lxd-installer.socket`, `uuidd.socket`, and udev sockets were active in `systemctl-active.txt:46-58`.
- `iscsid.socket`, `dm-event.socket`, `lvm2-lvmpolld.socket`, `lxd-installer.socket`, `multipathd.socket`, and `uuidd.socket` are enabled in `systemctl-unit-files.txt:247-251`, `systemctl-unit-files.txt:267`.
- `multipathd.service` is enabled, but its socket/service are condition-gated in this container by `ConditionVirtualization=!container`.

## Socket and command reachability

Live socket modes:

```text
prw------- root root /run/dmeventd-client
prw------- root root /run/dmeventd-server
srw------- root root /run/lvm/lvmpolld.socket
srw-rw---- root lxd  /run/lxd-installer.socket
srw-rw-rw- root root /run/uuidd/request
srw------- root root /run/udev/control
```

### open-iscsi / iscsid abstract socket

Default unit/config evidence:

- `/usr/lib/systemd/system/iscsid.socket:6`: `ListenStream=@ISCSIADM_ABSTRACT_NAMESPACE`
- `/usr/lib/systemd/system/iscsid.service:15-16`: root service runs `/usr/lib/open-iscsi/startup-checks.sh` then `/usr/sbin/iscsid`
- `/etc/iscsi/iscsid.conf:33-38`: default UID-based IPC auth; `iscsid.ipc_auth_uid = No` remains commented
- `/etc/iscsi` is root-owned; `/etc/iscsi/initiatorname.iscsi` is `0600 root:root`

Attacker tests:

```sh
runuser -u attacker -- iscsiadm -m node
# iscsiadm: No records found

runuser -u attacker -- iscsiadm -m discovery -t sendtargets -p 127.0.0.1
# iscsiadm: Could not make /etc/iscsi/send_targets: Permission denied
# iscsiadm: Could not add new discovery record.

runuser -u attacker -- iscsiadm -m iface -o new -I attackeriface
# Could not make /etc/iscsi/ifaces folder(13 Permission denied)

runuser -u attacker -- iscsiadm -m node -T iqn.2026-05.local:test -p 127.0.0.1:3260 -o new
# Failed to start iscsid.socket: Interactive authentication required.
# Could not connect to iSCSI daemon; database failure
```

Raw `attacker` connect to the abstract socket did connect to systemd activation, but the container kernel lacks `NETLINK_ISCSI`, so the daemon exited before a full protocol exchange:

```text
can not create NETLINK_ISCSI socket [Protocol not supported]
```

Ubuntu source package check in a disposable container confirmed the daemon authenticates before dispatching management requests:

- `open-iscsi-2.1.9/usr/mgmt_ipc.c:391-402` obtains `SO_PEERCRED` and allows only `peercred.uid == 0`.
- `open-iscsi-2.1.9/usr/mgmt_ipc.c:518-548` accepts, checks auth, and returns `ISCSI_ERR_ACCESS` before reading/dispatching a request.
- `open-iscsi-2.1.9/usr/iscsid.c:582-587` sets `ISCSI_IPC_AUTH_UID` by default and only switches to legacy auth if config explicitly says `iscsid.ipc_auth_uid = No`.

Conclusion: default reachable enough to activate, but not exploitable by uid 1001. Privileged management IPC is root-authenticated and local database creation is blocked by `/etc/iscsi` permissions.

### lxd-installer socket

Default unit/script evidence:

- `/usr/lib/systemd/system/lxd-installer.socket:5-9`: `/run/lxd-installer.socket`, `SocketUser=root`, `SocketGroup=lxd`, `SocketMode=0660`, `Accept=true`
- `/usr/lib/systemd/system/lxd-installer@.service:5-8`: root shell service with stdin/stdout on the accepted socket
- `/usr/share/lxd-installer/lxd-installer-service:27-28`: `snap install lxd --channel="$(lxd_channel)"`, then `echo 1`
- `/usr/sbin/lxc:4-7` and `/usr/sbin/lxd:4-7`: wrapper refuses before connect if `/run/lxd-installer.socket` is not writable

Attacker tests:

```sh
runuser -u attacker -- lxc list
# Unable to trigger the installation of the LXD snap.
# Please make sure you're a member of the 'lxd' system group.

runuser -u attacker -- python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket")'
# PermissionError: [Errno 13] Permission denied
```

Conclusion: root install helper exists but is not reachable by the scoped user because `attacker` is not in `lxd`.

### LVM / dm-event / lvmpolld

Default unit evidence:

- `/usr/lib/systemd/system/dm-event.socket:7-10`: FIFO pair under `/run`, `SocketMode=0600`
- `/usr/lib/systemd/system/lvm2-lvmpolld.socket:8-10`: `/run/lvm/lvmpolld.socket`, `SocketMode=0600`
- `/run/lvm` is `0700 root:root`

Attacker tests:

```sh
runuser -u attacker -- lvm version
# device-mapper: version ioctl ... failed: Permission denied

runuser -u attacker -- pvscan --cache
# Failed to create /run/lvm/pvs_online 13
# Failed to create /run/lvm/vgs_online 13

runuser -u attacker -- lvs
# /run/lock/lvm/P_global:aux: open failed: Permission denied

runuser -u attacker -- sh -c 'printf x > /run/lvm/lvmpolld.socket'
# cannot create /run/lvm/lvmpolld.socket: Permission denied

runuser -u attacker -- sh -c 'printf x > /run/dmeventd-client'
# cannot create /run/dmeventd-client: Permission denied

runuser -u attacker -- dmsetup create attacker --table '0 1 zero'
# device-mapper: version ioctl ... failed: Permission denied
```

Conclusion: no attacker-reachable daemon control path and no direct device-mapper operation from uid 1001.

### multipathd

Default unit/config evidence:

- `/usr/lib/systemd/system/multipathd.socket:4-10`: enabled abstract socket `@/org/kernel/linux/storage/multipathd`, with `ConditionVirtualization=!container`
- `/usr/lib/systemd/system/multipathd.service:12-20`: enabled service, also `ConditionVirtualization=!container`
- `/etc/multipath.conf:1-3`: default config only sets `user_friendly_names yes`
- `/usr/lib/tmpfiles.d/multipath.conf:1`: `/run/multipath` is `0700 root:root`
- `/usr/lib/udev/rules.d/60-multipath.rules:74`: udev may run `systemd-run ... /usr/bin/udevadm trigger`, but only from root udev event context

Container reachability:

```text
multipathd.socket: ConditionVirtualization=!container was not met
```

Attacker tests in the live container:

```sh
runuser -u attacker -- multipath -ll
# need to be root

runuser -u attacker -- multipathd reconfigure
# no daemon/socket effect in container because the default unit condition is unmet
```

Ubuntu source package check:

- `multipath-tools-0.9.4/multipathd/uxlsnr.c:96-108` checks `SO_PEERCRED` and marks only uid 0 clients as root.
- `multipath-tools-0.9.4/multipathd/uxlsnr.c:134` stores the root/non-root decision per accepted client.
- `multipath-tools-0.9.4/multipathd/uxlsnr.c:492-493` denies non-root clients for any command whose primary keyword is not `VRB_LIST`.
- `multipath-tools-0.9.4/multipathd/uxlsnr.c:384-386` replies `permission deny: need to be root` for `-EPERM`.
- `multipath-tools-0.9.4/multipathd/main.c:3734-3736` also refuses non-root daemon execution with `need to be root`.

Conclusion: in a non-container default server, the abstract control socket is worth a live VM retest because it is enabled by default and has no filesystem mode. Source review indicates non-root clients are limited to list/show style operations and mutation/root operations require uid 0, so no LPE was validated here.

### uuidd

Default unit evidence:

- `/usr/lib/systemd/system/uuidd.socket:5`: `/run/uuidd/request`
- `/usr/lib/systemd/system/uuidd.service:7-20`: `ExecStart=/usr/sbin/uuidd --socket-activation`, `User=uuidd`, `Group=uuidd`, `ProtectSystem=strict`, `PrivateDevices=yes`, `PrivateUsers=yes`, `ReadWritePaths=/var/lib/libuuid/`
- `/var/lib/libuuid` is `drwxrwsr-x uuidd:uuidd`; `clock.txt` is `0660 uuidd:uuidd`

Attacker tests:

```sh
runuser -u attacker -- uuidgen
runuser -u attacker -- uuidgen -t
runuser -u attacker -- uuidd -r
runuser -u attacker -- uuidd -t
```

All commands returned UUIDs. A raw socket connect also succeeded:

```text
uuidd: CONNECTED
```

Conclusion: world-writable by design, but the daemon runs as `uuidd`, not root, and the only default writable state is `uuidd:uuidd` under `/var/lib/libuuid`. No root write or helper execution path was found.

### udev control and udev-triggered helpers

Default unit evidence:

- `/usr/lib/systemd/system/systemd-udevd-control.socket:17-22`: `/run/udev/control`, `SocketMode=0600`, `PassCredentials=yes`
- `/usr/lib/systemd/system/systemd-udevd.service:18-43`: root service, but control socket is root-only and service is sandboxed

Attacker tests:

```sh
runuser -u attacker -- udevadm control --ping
# Failed to send a ping message: Permission denied

runuser -u attacker -- udevadm control --reload
# Failed to send reload request: Permission denied

runuser -u attacker -- udevadm trigger --action=add
# Failed to write 'add' to .../uevent: Permission denied

runuser -u attacker -- python3 -c 'import socket; s=socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); s.connect("/run/udev/control")'
# PermissionError: [Errno 13] Permission denied
```

Conclusion: the control socket and sysfs uevent triggers are not reachable by uid 1001. Udev rules that run root helpers remain kernel/root event driven in this default state.

## Cleanup performed

The probing left no attacker-created LXD snap, iSCSI node/iface database, LVM device, or multipath state.

Cleanup commands run:

```sh
systemctl stop uuidd.service || true
systemctl reset-failed iscsid.socket iscsid.service || true
systemctl start iscsid.socket || true
```

Post-cleanup state:

```text
iscsid.socket active
uuidd.socket active
uuidd.service inactive
/etc/iscsi contains only initiatorname.iscsi and iscsid.conf
no /snap/bin/lxc or /snap/bin/lxd
```

## Promising unresolved edge

`multipathd.socket` is enabled by default and uses an abstract Unix socket on non-container systems. The container target cannot activate it because the packaged unit has `ConditionVirtualization=!container`. Source review shows non-root clients are restricted to list operations and privileged commands require uid 0 via `SO_PEERCRED`, but a full Ubuntu Server VM would be the right place to capture live denial strings and confirm there is no unauthenticated state-changing command exposed by the daemon.
