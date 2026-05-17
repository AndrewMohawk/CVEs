# Storage daemon IPC evidence, 2026-05-16

Target: `ubuntu24-server-lpe-target`  
Image: `ubuntu24-server-default-lpe:20260516-standard`  
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`

## Installed/default proof

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc '
id attacker
for p in open-iscsi multipath-tools mdadm lvm2 dmeventd thin-provisioning-tools uuid-runtime systemd systemd-resolved; do
  dpkg-query -W "$p" 2>/dev/null || true
done
systemctl --no-pager --plain list-unit-files "*iscsi*" "*multipath*" "*lvm*" "*mdadm*" "*mdmonitor*" "*uuidd*" "systemd-resolved*" "systemd-logind*"'
```

Evidence:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
open-iscsi 2.1.9-3ubuntu5.4
multipath-tools 0.9.4-5ubuntu8.1
mdadm 4.3-1ubuntu2.1
lvm2 2.03.16-3ubuntu3.2
dmeventd 2:1.02.185-3ubuntu3.2
thin-provisioning-tools 0.9.0-2ubuntu5.1
uuid-runtime 2.39.3-9ubuntu6.5
systemd 255.4-1ubuntu8.15
systemd-resolved 255.4-1ubuntu8.15

iscsid.service disabled enabled
lvm2-monitor.service enabled enabled
mdmonitor-oneshot.timer enabled enabled
multipathd.service enabled enabled
open-iscsi.service enabled enabled
systemd-logind.service static -
systemd-resolved.service enabled enabled
uuidd.service indirect enabled
iscsid.socket enabled enabled
lvm2-lvmpolld.socket enabled enabled
multipathd.socket enabled enabled
uuidd.socket enabled enabled
```

Active state in the Docker target:

```text
iscsid.socket: enabled / active
iscsid.service: disabled / inactive
open-iscsi.service: enabled / inactive
multipathd.socket: enabled / inactive
multipathd.service: enabled / inactive
lvm2-lvmpolld.socket: enabled / active
lvm2-monitor.service: enabled / inactive
dm-event.socket: enabled / active
mdmonitor-oneshot.timer: enabled / inactive
uuidd.socket: enabled / active
uuidd.service: indirect / inactive
systemd-resolved.service: enabled / active
systemd-logind.service: static / active
```

## Default code/config boundaries

Relevant installed unit/config paths:

```text
/usr/lib/systemd/system/iscsid.socket:6 ListenStream=@ISCSIADM_ABSTRACT_NAMESPACE
/usr/lib/systemd/system/iscsid.service:15 ExecStartPre=/usr/lib/open-iscsi/startup-checks.sh
/usr/lib/systemd/system/iscsid.service:16 ExecStart=/usr/sbin/iscsid
/etc/iscsi/iscsid.conf:33-38 documents default UID-based IPC auth; legacy `iscsid.ipc_auth_uid = No` is commented

/usr/lib/systemd/system/multipathd.socket:4-6 kernel/container conditions
/usr/lib/systemd/system/multipathd.socket:10 ListenStream=@/org/kernel/linux/storage/multipathd
/usr/lib/systemd/system/multipathd.service:12-14 same conditions, including ConditionVirtualization=!container
/usr/lib/systemd/system/multipathd.service:19-20 ExecStartPre=-/sbin/modprobe dm-multipath; ExecStart=/sbin/multipathd -d -s

/usr/lib/systemd/system/lvm2-lvmpolld.socket:8-10 /run/lvm/lvmpolld.socket, SocketMode=0600
/usr/lib/systemd/system/dm-event.socket:7-10 /run/dmeventd-{server,client}, SocketMode=0600
/usr/lib/systemd/system/lvm2-monitor.service:9 ConditionVirtualization=!container
/usr/lib/systemd/system/lvm2-monitor.service:13-15 fixed root LVM commands

/usr/lib/systemd/system/mdmonitor-oneshot.timer:11-14 daily persistent timer
/usr/lib/systemd/system/mdmonitor-oneshot.service:13-14 EnvironmentFile=-/etc/default/mdadm; ExecStart=sh -c '[ "$AUTOSCAN" != "true" ] || /sbin/mdadm --monitor --oneshot --scan'
/etc/default/mdadm:12 AUTOCHECK=true
/etc/default/mdadm:17 AUTOSCAN=true
/etc/default/mdadm:21 START_DAEMON=true
/etc/default/mdadm:25 DAEMON_OPTIONS="--syslog"
/etc/mdadm/mdadm.conf:15 HOMEHOST <system>
/etc/mdadm/mdadm.conf:18 MAILADDR root

/usr/lib/systemd/system/uuidd.socket:5 ListenStream=/run/uuidd/request
/usr/lib/systemd/system/uuidd.service:7-20 ExecStart=/usr/sbin/uuidd --socket-activation; User=uuidd; Group=uuidd; ProtectSystem=strict; ReadWritePaths=/var/lib/libuuid/

/usr/lib/systemd/system/systemd-resolved.service:23-52 runs as User=systemd-resolve with NoNewPrivileges=yes, ProtectSystem=strict, and RuntimeDirectory=systemd/resolve
```

Socket and config permissions:

```text
prw------- root:root /run/dmeventd-client
prw------- root:root /run/dmeventd-server
drwx------ root:root /run/lvm
srw------- root:root /run/lvm/lvmpolld.socket
drwx------ root:root /run/lock/lvm
drwx------ root:root /run/multipath
missing /run/multipathd.sock
drwxr-xr-x root:root /run/uuidd
srw-rw-rw- root:root /run/uuidd/request
drwxr-xr-x systemd-resolve:systemd-resolve /run/systemd/resolve
srw-rw-rw- systemd-resolve:systemd-resolve /run/systemd/resolve/io.systemd.Resolve
srw------- systemd-resolve:systemd-resolve /run/systemd/resolve/io.systemd.Resolve.Monitor
srw------- root:root /run/udev/control
drwxr-xr-x root:root /etc/iscsi
-rw------- root:root /etc/iscsi/initiatorname.iscsi
drwxr-xr-x root:root /etc/mdadm
-rw-r--r-- root:root /etc/mdadm/mdadm.conf
-rw-r--r-- root:root /etc/default/mdadm
drwxr-xr-x root:root /etc/lvm
-rw-r--r-- root:root /etc/lvm/lvm.conf
-rw-r--r-- root:root /etc/multipath.conf
```

## Attacker reachability probes

Command:

```sh
docker exec -i ubuntu24-server-lpe-target bash -s <<'EOS'
runuser -u attacker -- sh -lc 'id; groups; test -w /etc/iscsi && echo iscsi_writable || echo iscsi_not_writable; test -w /etc/mdadm/mdadm.conf && echo mdadm_conf_writable || echo mdadm_conf_not_writable; test -w /etc/lvm/lvm.conf && echo lvm_conf_writable || echo lvm_conf_not_writable; test -w /etc/multipath.conf && echo multipath_conf_writable || echo multipath_conf_not_writable'
runuser -u attacker -- iscsiadm -m node
runuser -u attacker -- iscsiadm -m discovery -t sendtargets -p 127.0.0.1
runuser -u attacker -- iscsiadm -m iface -o new -I storageipc0
runuser -u attacker -- python3 - <<'PY'
import socket
for name in [b"\0ISCSIADM_ABSTRACT_NAMESPACE", b"\0/org/kernel/linux/storage/multipathd"]:
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(2); s.connect(name); print(repr(name), "CONNECT_OK")
    except Exception as e:
        print(repr(name), type(e).__name__, str(e))
    finally:
        s.close()
PY
runuser -u attacker -- lvs
runuser -u attacker -- pvscan --cache
runuser -u attacker -- dmsetup create storageipc --table '0 1 zero'
runuser -u attacker -- python3 - <<'PY'
import socket
for path in ["/run/lvm/lvmpolld.socket","/run/uuidd/request","/run/systemd/resolve/io.systemd.Resolve","/run/systemd/resolve/io.systemd.Resolve.Monitor"]:
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(2); s.connect(path); print(path, "CONNECT_OK")
    except Exception as e:
        print(path, type(e).__name__, str(e))
    finally:
        s.close()
PY
runuser -u attacker -- sh -lc 'timeout 1 sh -c "printf x > /run/dmeventd-client"'
runuser -u attacker -- multipath -ll
runuser -u attacker -- multipathd show maps
runuser -u attacker -- multipathd reconfigure
runuser -u attacker -- mdadm --monitor --scan --oneshot --test
runuser -u attacker -- mdadm --assemble --scan
runuser -u attacker -- uuidd -r
runuser -u attacker -- uuidd -t
runuser -u attacker -- resolvectl statistics
runuser -u attacker -- resolvectl flush-caches
runuser -u attacker -- resolvectl reset-statistics
runuser -u attacker -- resolvectl dns lo 127.0.0.1
runuser -u attacker -- systemctl start multipathd.service
runuser -u attacker -- systemctl start lvm2-monitor.service
runuser -u attacker -- systemctl start mdmonitor-oneshot.service
runuser -u attacker -- systemctl set-environment LVM_SYSTEM_DIR=/home/attacker/storageipc-lvm
EOS
```

Key outputs:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
iscsi_not_writable
mdadm_conf_not_writable
lvm_conf_not_writable
multipath_conf_not_writable

iscsiadm -m node
iscsiadm: No records found

iscsiadm -m discovery -t sendtargets -p 127.0.0.1
iscsiadm: read error (-1/104), daemon died?
iscsiadm: Could not make /etc/iscsi/send_targets: Permission denied
iscsiadm: Could not add new discovery record.

iscsiadm -m iface -o new -I storageipc0
iSCSI ERROR: Could not make /etc/iscsi/ifaces folder(13 Permission denied).

b'\x00ISCSIADM_ABSTRACT_NAMESPACE' ConnectionRefusedError [Errno 111] Connection refused
b'\x00/org/kernel/linux/storage/multipathd' ConnectionRefusedError [Errno 111] Connection refused

lvs
WARNING: Running as a non-root user. Functionality may be unavailable.
/run/lock/lvm/P_global:aux: open failed: Permission denied

pvscan --cache
Failed to create /run/lvm/pvs_online 13
Failed to create /run/lvm/vgs_online 13
Failed to create /run/lvm/pvs_lookup 13

dmsetup create storageipc --table '0 1 zero'
device-mapper: version ioctl on failed: Permission denied

/run/lvm/lvmpolld.socket PermissionError [Errno 13] Permission denied
/run/uuidd/request CONNECT_OK
/run/systemd/resolve/io.systemd.Resolve CONNECT_OK
/run/systemd/resolve/io.systemd.Resolve.Monitor PermissionError [Errno 13] Permission denied

printf x > /run/dmeventd-client
cannot create /run/dmeventd-client: Permission denied

multipath -ll
need to be root

multipathd show maps
[exit=1]

multipathd reconfigure
[exit=1]

mdadm --monitor --scan --oneshot --test
[exit=0]

mdadm --assemble --scan
mdadm: must be super-user to perform this action

uuidd -r
c0468fcc-cf58-4033-8082-5af7c12b0c83

uuidd -t
007c5f16-511f-11f1-817d-fe62605aa36f

resolvectl statistics
Failed to connect to query monitoring service /run/systemd/resolve/io.systemd.Resolve.Monitor: Permission denied

resolvectl flush-caches
[exit=0]

resolvectl reset-statistics
Failed to connect to query monitoring service /run/systemd/resolve/io.systemd.Resolve.Monitor: Permission denied

resolvectl dns lo 127.0.0.1
Failed to set DNS configuration: Unit dbus-org.freedesktop.network1.service not found.

systemctl start multipathd.service
Failed to start multipathd.service: Interactive authentication required.

systemctl start lvm2-monitor.service
Failed to start lvm2-monitor.service: Interactive authentication required.

systemctl start mdmonitor-oneshot.service
Failed to start mdmonitor-oneshot.service: Interactive authentication required.

systemctl set-environment LVM_SYSTEM_DIR=/home/attacker/storageipc-lvm
Failed to set environment: Access denied
```

The iSCSI daemon could be socket-activated, but the Docker kernel lacks iSCSI netlink support:

```text
iscsid: can not create NETLINK_ISCSI socket [Protocol not supported]
iscsid.service: Failed with result 'exit-code'
```

## Cleanup evidence

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc '
systemctl reset-failed iscsid.service iscsid.socket || true
systemctl start iscsid.socket || true
systemctl stop uuidd.service || true
systemctl start uuidd.socket || true
rm -rf /home/attacker/storageipc-lvm /home/attacker/storageipc0 /tmp/storageipc* || true
systemctl is-active iscsid.socket
systemctl is-active iscsid.service || true
systemctl is-active uuidd.socket
systemctl is-active uuidd.service || true
find /home/attacker /tmp -maxdepth 1 -name "*storageipc*" -ls 2>/dev/null || true'
```

Evidence:

```text
iscsid.socket: active
iscsid.service: inactive
uuidd.socket: active
uuidd.service: inactive
leftovers:
```
