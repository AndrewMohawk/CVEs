# Negative: default root/service runtime sockets

Date: 2026-05-16
Target: `ubuntu24-server-lpe-target`
Image: `ubuntu24-server-default-lpe:20260516-standard`
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`
PoC: `/Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe/pocs/default_runtime_socket_probe.sh`
Real output: `/Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe/logs/default-runtime-socket.out`

## Result

No uid1001-to-root LPE was validated across `/run/uuidd/request`, `/run/dmeventd-client`, `/run/dmeventd-server`, `/run/lvm/lvmpolld.socket`, `/run/apport.socket`, or `/run/udev/control`.

The only generally reachable socket is `/run/uuidd/request`, and that activates `uuidd` as `uuidd:uuidd`, not root. The remaining root/service IPC endpoints are present and default-active in the container, but their filesystem modes stop uid1001 before parser, mutator, helper, fd/path injection, or root-write semantics.

## Default package proof

From the PoC log:

```text
Ubuntu 24.04.4 LTS (Noble)
apport 2.28.1-0ubuntu3.8
apport-core-dump-handler 2.28.1-0ubuntu3.8
dmeventd 2:1.02.185-3ubuntu3.2
dmsetup 2:1.02.185-3ubuntu3.2
libuuid1:arm64 2.39.3-9ubuntu6.5
lvm2 2.03.16-3ubuntu3.2
python3-apport 2.28.1-0ubuntu3.8
systemd 255.4-1ubuntu8.15
udev 255.4-1ubuntu8.15
util-linux 2.39.3-9ubuntu6.5
uuid-runtime 2.39.3-9ubuntu6.5
```

## Socket and service proof

```text
/run/uuidd/request            srw-rw-rw- root:root 0666  uuidd.socket -> uuidd.service
/run/dmeventd-client          prw------- root:root 0600  dm-event.socket -> dm-event.service
/run/dmeventd-server          prw------- root:root 0600  dm-event.socket -> dm-event.service
/run/lvm/lvmpolld.socket      srw------- root:root 0600  lvm2-lvmpolld.socket -> lvm2-lvmpolld.service
/run/apport.socket            srw------- root:root 0600  apport-forward.socket -> apport-forward@.service
/run/udev/control             srw------- root:root 0600  systemd-udevd-control.socket -> systemd-udevd.service
```

`/proc/net/unix` showed live listeners for `/run/lvm/lvmpolld.socket`, `/run/udev/control`, `/run/apport.socket`, and `/run/uuidd/request`. The dmeventd endpoints are systemd FIFOs.

Relevant unit boundaries:

```text
uuidd.service: ExecStart=/usr/sbin/uuidd --socket-activation, User=uuidd, Group=uuidd, ReadWritePaths=/var/lib/libuuid/
dm-event.service: ExecStart=/usr/sbin/dmeventd -f, root service behind 0600 FIFOs
lvm2-lvmpolld.service: ExecStart=/usr/sbin/lvmpolld -t 60 -f, root service behind /run/lvm 0700 and socket 0600
apport-forward.socket: ListenStream=/run/apport.socket, SocketMode=0600, Accept=yes, PassCredentials=true
apport-forward@.service: ExecStart=/usr/share/apport/apport
systemd-udevd-control.socket: ListenSequentialPacket=/run/udev/control, SocketMode=0600, PassCredentials=yes
```

## Unprivileged trigger results

`uuidd`: `attacker` successfully ran `/usr/sbin/uuidd --time --uuids 2` and `/usr/sbin/uuidd --random --uuids 2`. Raw malformed and path-string socket payloads connected, then received `ConnectionResetError`. Attempting to unlink `/run/uuidd/request` failed with `Permission denied`. After activation, `uuidd` ran as uid `101` and only updated `/var/lib/libuuid/clock.txt` as `uuidd:uuidd`.

`dmeventd`: `attacker` write/read attempts on `/run/dmeventd-client` and `/run/dmeventd-server` all failed with `Permission denied`. LVM/device-mapper client attempts (`lvm version`, `pvscan --cache`, `lvs`, `dmsetup version`) either hit device-mapper permission denial or `/run/lvm`/`/run/lock/lvm` permission failures before daemon control.

`lvmpolld`: raw `AF_UNIX` connect to `/run/lvm/lvmpolld.socket` returned `PermissionError: [Errno 13] Permission denied`. `lvm fullreport --config "global { use_lvmpolld=1 }"` failed on `/run/lock/lvm/P_global:aux: open failed: Permission denied`.

`apport`: `attacker` could create a normal test crash file in `/var/crash`, but `nc -U /run/apport.socket` and raw Python connect to `/run/apport.socket` failed with `Permission denied`. `apport-cli --save` only wrote an attacker-owned report under `/tmp`, not through the root forwarding socket.

`udev`: `udevadm control --ping`, `udevadm control --reload`, and `udevadm trigger --action=add --subsystem-match=block` all failed from uid1001. Raw `SOCK_SEQPACKET` connect to `/run/udev/control` returned `PermissionError: [Errno 13] Permission denied`.

## Root marker and cleanup

The PoC used `/root/codex-default-runtime-socket-root-proof` and `/tmp/codex-default-runtime-socket-root-proof` as marker paths in payloads and checked them after all triggers:

```text
ROOT_MARKER_ABSENT /root/codex-default-runtime-socket-root-proof
TMP_MARKER_ABSENT /tmp/codex-default-runtime-socket-root-proof
```

Cleanup removed or confirmed absence of the fixed probe names:

```text
removed_or_absent /root/codex-default-runtime-socket-root-proof
removed_or_absent /tmp/codex-default-runtime-socket-root-proof
removed_or_absent /var/crash/codex-default-runtime-socket.crash
removed_or_absent /tmp/codex-default-runtime-socket-apport.crash
```

## Dead-end reason

This lane is negative because no root-owned parser was reachable from uid1001 except the intentionally public uuidd protocol, and uuidd drops to a service account before handling requests. The other endpoints are root-owned mode `0600` or protected by a root-only parent directory, so uid1001 cannot reach the privileged protocol surface where credential confusion, mutators, helper execution, fd/path injection, or root-owned writes would be exercised.
