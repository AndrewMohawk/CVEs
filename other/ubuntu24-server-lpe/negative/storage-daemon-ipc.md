# Negative note: default storage daemon IPC/root sockets

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`  
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`  
Scope: open-iscsi/iscsid, multipathd, mdadm monitor, lvm/dmeventd/lvmpolld, uuidd, and directly related resolved/logind-style local privileged IPC.

## Result

No uid1001-to-root local privilege escalation was validated in this bounded surface.

The default Ubuntu Server packages are installed, and several sockets are default enabled. The attacker can reach only non-mutating or non-root service-account IPC (`uuidd`, limited `systemd-resolved` cache control), while root storage control paths are blocked by socket modes, unit conditions, peer/uid checks, root-owned config, or systemd/polkit authorization. No attacker-controlled path was consumed by a root helper, no root-owned file write was produced, and no root command execution was achieved.

## Default package/service proof

Installed versions on the target:

```text
open-iscsi 2.1.9-3ubuntu5.4
multipath-tools 0.9.4-5ubuntu8.1
mdadm 4.3-1ubuntu2.1
lvm2 2.03.16-3ubuntu3.2
dmeventd 2:1.02.185-3ubuntu3.2
thin-provisioning-tools 0.9.0-2ubuntu5.1
uuid-runtime 2.39.3-9ubuntu6.5
systemd/systemd-resolved 255.4-1ubuntu8.15
```

Default-enabled units:

```text
iscsid.socket enabled
lvm2-lvmpolld.socket enabled
dm-event.socket active
lvm2-monitor.service enabled
multipathd.socket enabled
multipathd.service enabled
open-iscsi.service enabled
mdmonitor-oneshot.timer enabled
uuidd.socket enabled
systemd-resolved.service enabled
systemd-logind.service static/active
```

## Root boundary checks

### iscsid/open-iscsi

Default boundary:

```text
/usr/lib/systemd/system/iscsid.socket:6 ListenStream=@ISCSIADM_ABSTRACT_NAMESPACE
/usr/lib/systemd/system/iscsid.service:15-16 root startup checks then /usr/sbin/iscsid
/etc/iscsi/iscsid.conf:33-38 default UID-based IPC auth; legacy compatibility option remains commented
/etc/iscsi root:root 0755; /etc/iscsi/initiatorname.iscsi root:root 0600
```

Attacker results:

```text
iscsiadm -m node -> No records found
iscsiadm -m discovery -t sendtargets -p 127.0.0.1 -> daemon died, then cannot create /etc/iscsi/send_targets: Permission denied
iscsiadm -m iface -o new -I storageipc0 -> cannot create /etc/iscsi/ifaces: Permission denied
raw abstract connect to \0ISCSIADM_ABSTRACT_NAMESPACE -> Connection refused after iscsid failed
journal -> can not create NETLINK_ISCSI socket [Protocol not supported]
```

Conclusion: the socket is default enabled, but in this Docker target the daemon cannot remain alive because the host kernel lacks `NETLINK_ISCSI`. The user cannot write the root-owned iSCSI database or cause a root login/discovery helper to consume attacker-controlled records.

### multipathd

Default boundary:

```text
/usr/lib/systemd/system/multipathd.socket:4-6 condition-gated, including ConditionVirtualization=!container
/usr/lib/systemd/system/multipathd.socket:10 ListenStream=@/org/kernel/linux/storage/multipathd
/usr/lib/systemd/system/multipathd.service:12-20 same condition gate; root ExecStartPre modprobe and /sbin/multipathd -d -s
/run/multipath root:root 0700
/etc/multipath.conf root:root 0644
```

Attacker results:

```text
raw abstract connect to \0/org/kernel/linux/storage/multipathd -> Connection refused
multipath -ll -> need to be root
multipathd show maps -> exit 1
multipathd reconfigure -> exit 1
systemctl start multipathd.service -> Interactive authentication required
```

Conclusion: in the Docker target, the default unit is installed/enabled but inactive because `ConditionVirtualization=!container` is unmet. The attacker cannot start the root service, cannot write config, and cannot reach a live privileged control socket.

### LVM/dmeventd/lvmpolld

Default boundary:

```text
/usr/lib/systemd/system/lvm2-lvmpolld.socket:8-10 /run/lvm/lvmpolld.socket, SocketMode=0600
/usr/lib/systemd/system/dm-event.socket:7-10 /run/dmeventd-server and /run/dmeventd-client, SocketMode=0600
/usr/lib/systemd/system/lvm2-monitor.service:9 ConditionVirtualization=!container
/usr/lib/systemd/system/lvm2-monitor.service:13-15 fixed root vgchange monitor commands
/run/lvm root:root 0700
/run/lock/lvm root:root 0700
```

Attacker results:

```text
lvs -> /run/lock/lvm/P_global:aux: open failed: Permission denied
pvscan --cache -> failed to create /run/lvm/pvs_online, vgs_online, pvs_lookup: Permission denied
dmsetup create storageipc --table '0 1 zero' -> device-mapper ioctl Permission denied
connect /run/lvm/lvmpolld.socket -> Permission denied
printf x > /run/dmeventd-client -> Permission denied
systemctl start lvm2-monitor.service -> Interactive authentication required
systemctl set-environment LVM_SYSTEM_DIR=/home/attacker/storageipc-lvm -> Access denied
```

Conclusion: the attacker cannot reach the privileged LVM daemons or influence the root unit environment. Running LVM tools as uid1001 only exercises unprivileged client code and fails before device-mapper/root state changes.

### mdadm monitor

Default boundary:

```text
/usr/lib/systemd/system/mdmonitor-oneshot.timer:11-14 daily persistent timer
/usr/lib/systemd/system/mdmonitor-oneshot.service:13-14 reads /etc/default/mdadm and runs /sbin/mdadm --monitor --oneshot --scan
/etc/default/mdadm root:root 0644; AUTOSCAN=true; DAEMON_OPTIONS="--syslog"
/etc/mdadm/mdadm.conf root:root 0644; HOMEHOST <system>; MAILADDR root
```

Attacker results:

```text
test -w /etc/default/mdadm -> not writable
test -w /etc/mdadm/mdadm.conf -> not writable
mdadm --monitor --scan --oneshot --test -> exit 0, no root context because run by attacker
mdadm --assemble --scan -> must be super-user to perform this action
systemctl start mdmonitor-oneshot.service -> Interactive authentication required
```

Conclusion: the root timer/service reads only root-owned configuration in the default state. The attacker can run the monitor command manually as uid1001, but cannot make systemd run it, cannot alter monitor options, and cannot assemble/control MD arrays.

### uuidd

Default boundary:

```text
/usr/lib/systemd/system/uuidd.socket:5 ListenStream=/run/uuidd/request
/run/uuidd/request root:root 0666
/usr/lib/systemd/system/uuidd.service:7-20 ExecStart=/usr/sbin/uuidd --socket-activation; User=uuidd; Group=uuidd; ProtectSystem=strict; ReadWritePaths=/var/lib/libuuid/
```

Attacker results:

```text
connect /run/uuidd/request -> CONNECT_OK
uuidd -r -> returned random UUID
uuidd -t -> returned time UUID
uuidd.service after activation -> /usr/sbin/uuidd --socket-activation running as uuidd
```

Conclusion: this socket is world reachable by design, but the daemon is not root and its writable state is limited to `/var/lib/libuuid/` under the `uuidd` account. This is not a root LPE primitive.

### systemd-resolved local IPC

Default boundary:

```text
/run/systemd/resolve/io.systemd.Resolve systemd-resolve:systemd-resolve 0666
/run/systemd/resolve/io.systemd.Resolve.Monitor systemd-resolve:systemd-resolve 0600
/usr/lib/systemd/system/systemd-resolved.service:24-52 bounded caps, NoNewPrivileges=yes, ProtectSystem=strict, User=systemd-resolve
```

Attacker results:

```text
connect /run/systemd/resolve/io.systemd.Resolve -> CONNECT_OK
connect /run/systemd/resolve/io.systemd.Resolve.Monitor -> Permission denied
resolvectl flush-caches -> exit 0
resolvectl statistics/reset-statistics -> monitor socket Permission denied
resolvectl dns lo 127.0.0.1 -> failed, no networkd bus unit
```

Conclusion: uid1001 can reach the resolver query/cache IPC, but the daemon runs as `systemd-resolve` with a strict sandbox. No root-owned path or root helper execution was reached.

## Cleanup

Performed:

```sh
systemctl reset-failed iscsid.service iscsid.socket
systemctl start iscsid.socket
systemctl stop uuidd.service
systemctl start uuidd.socket
rm -rf /home/attacker/storageipc-lvm /home/attacker/storageipc0 /tmp/storageipc*
```

Verified:

```text
iscsid.socket active
iscsid.service inactive
uuidd.socket active
uuidd.service inactive
no /home/attacker or /tmp storageipc leftovers
```

## Why this is likely missed by generic sweeps

This surface looks promising to scanners because it contains default-enabled root storage units, abstract Unix sockets, root helper commands, and world-reachable IPC. The actual boundary depends on live unit conditions, socket activation behavior, Unix peer credentials, root-owned daemon databases, and service-account sandboxing. A generic file/socket listing will over-rank the surface unless it tests the exact uid1001 reachability and follows the unit/config semantics through to root-context execution.

## Triage suggestion

No Ubuntu Security issue is supported by this Docker-target evidence. Hardening that would reduce future ambiguity: document the default non-root accessibility of `uuidd` and `systemd-resolved` sockets, keep storage control sockets root-only or peercred-gated, and preserve the `ConditionVirtualization=!container` guards for multipath/LVM monitor units in containerized server images.
