# udev hotplug helper rules: negative

Date: 2026-05-16

Surface owner: default udev/hotplug trust boundaries on `ubuntu24-server-lpe-target`, focused on installed `RUN`, `PROGRAM`, and `IMPORT{program}` helpers, default world-writable device nodes, attacker-triggerable uevents, helper command resolution, and root-side helper execution.

Result: no uid1001-to-root LPE was validated. The only live attacker-caused root udev helper execution was a Docker-specific `/dev/uinput` event that matched `/usr/lib/udev/rules.d/71-seat.rules:77` and ran `/usr/bin/loginctl lock-sessions` as root. That path is not proven stock-default on Ubuntu Server because the installed Ubuntu rules do not grant world access to `/dev/uinput`, and the helper only locks sessions; it did not write attacker-controlled root files or execute attacker-controlled code.

## Target and default proof

Target identity and attacker:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
systemd 255.4-1ubuntu8.15
udev 255.4-1ubuntu8.15
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
systemctl is-system-running: running
```

Default metapackages and relevant helper packages:

```text
ubuntu-minimal 1.539.2
ubuntu-standard 1.539.2
ubuntu-server 1.539.2
apport 2.28.1-0ubuntu3.8
bcache-tools 1.0.8-5build1
console-setup-linux 1.226ubuntu1
dmsetup 2:1.02.185-3ubuntu3.2
hdparm 9.65+ds-1build1
kpartx 0.9.4-5ubuntu8.1
lvm2 2.03.16-3ubuntu3.2
mdadm 4.3-1ubuntu2.1
multipath-tools 0.9.4-5ubuntu8.1
open-iscsi 2.1.9-3ubuntu5.4
sg3-utils 1.46-3ubuntu4
systemd 255.4-1ubuntu8.15
udev 255.4-1ubuntu8.15
udisks2 2.10.1-6ubuntu1.3
usb-modeswitch 2.6.1-3ubuntu3
```

`systemd-udevd.service`, `systemd-udevd-control.socket`, and `systemd-udevd-kernel.socket` are active. The control socket is root-only:

```text
systemd-udevd.service                    loaded active running Rule-based Manager for Device Events and Files
systemd-udevd-control.socket             loaded active running udev Control Socket
systemd-udevd-kernel.socket              loaded active running udev Kernel Socket
/run/udev/control: srw------- 600 root root
```

The service runs as root with a root-owned helper/rules state:

```text
ExecStart=/usr/lib/systemd/systemd-udevd
SocketMode=0600
ListenNetlink=kobject-uevent 1
PassCredentials=yes
/usr/lib/udev: drwxr-xr-x root root
/usr/lib/udev/rules.d: drwxr-xr-x root root
/etc/udev/rules.d: drwxr-xr-x root root
/run/udev/data: drwxr-xr-x root root
```

As `attacker`, the same paths are not writable, and `udevadm control --ping` fails with `Permission denied`.

## Helper rule inventory

Installed root-executed helper rules include:

```text
/usr/lib/udev/rules.d/40-usb_modeswitch.rules: RUN+="usb_modeswitch ..."
/usr/lib/udev/rules.d/50-apport.rules:2: RUN+="/usr/share/apport/iwlwifi_error_dump $env{DEVPATH}"
/usr/lib/udev/rules.d/50-udev-default.rules:4: ACTION=="remove", ENV{REMOVE_CMD}!="", RUN+="$env{REMOVE_CMD}"
/usr/lib/udev/rules.d/55-dm.rules:52,115,116: IMPORT{program}="/sbin/dmsetup ..." / "/usr/sbin/dmsetup ..."
/usr/lib/udev/rules.d/55-scsi-sg3_id.rules:57,62,63,70,73,74: IMPORT{program}="/usr/bin/sg_inq ..."
/usr/lib/udev/rules.d/56-dm-mpath.rules:35,105: PROGRAM/IMPORT via multipath and kpartx_id
/usr/lib/udev/rules.d/56-lvm.rules:21: IMPORT{program}="/usr/sbin/dmsetup splitname ..."
/usr/lib/udev/rules.d/60-cdrom_id.rules:16,20: RUN/IMPORT cdrom_id
/usr/lib/udev/rules.d/60-fido-id.rules:5: IMPORT{program}="fido_id"
/usr/lib/udev/rules.d/60-multipath.rules:5,34,74,89: rm, multipath, systemd-run, systemctl
/usr/lib/udev/rules.d/60-persistent-storage*.rules: ata_id, scsi_id, blkid and related helpers
/usr/lib/udev/rules.d/63-md-raid-arrays.rules:21: IMPORT{program}="/sbin/mdadm --detail ..."
/usr/lib/udev/rules.d/64-btrfs.rules:15: RUN+="/usr/bin/udevadm trigger ..."
/usr/lib/udev/rules.d/64-md-raid-assembly.rules:41,44,45: mdadm incremental/manage
/usr/lib/udev/rules.d/68-del-part-nodes.rules:31: RUN+="/usr/bin/partx -d ..."
/usr/lib/udev/rules.d/69-bcache.rules:16,22,26: probe-bcache, bcache-register, bcache-export-cached
/usr/lib/udev/rules.d/69-lvm.rules:82,85,89: lvm pvscan, systemd-run, vgchange
/usr/lib/udev/rules.d/70-iscsi-network-interface.rules:2,3: RUN+="/usr/lib/open-iscsi/net-interface-handler start|stop"
/usr/lib/udev/rules.d/71-seat.rules:72,77: udevadm trigger, loginctl lock-sessions
/usr/lib/udev/rules.d/80-udisks2.rules:20,22: /bin/sh -c mdadm export pipelines
/usr/lib/udev/rules.d/85-hdparm.rules:1: RUN+="/lib/udev/hdparm"
/usr/lib/udev/rules.d/90-console-setup.rules:1,3: cached console setup scripts
/usr/lib/udev/rules.d/90-iocost.rules:20: RUN+="iocost apply $env{DEVNAME}"
/usr/lib/udev/rules.d/95-dm-notify.rules:12: RUN+="/sbin/dmsetup udevcomplete $env{DM_COOKIE}"
/usr/lib/udev/rules.d/95-kpartx.rules:42: RUN+="/sbin/kpartx -un -p -part /dev/$name"
/usr/lib/udev/rules.d/99-systemd.rules:70: RUN+="/usr/lib/systemd/systemd-sysctl --prefix=/net/.../$name"
```

Most of these require physical hotplug or root-created block/storage state. The attacker cannot create initial-namespace block devices, device-mapper devices, loop devices, SCSI/USB hardware, vtconsole/vc devices, or initial-namespace net devices from the stock uid1001 account.

## Attacker trigger tests

Direct udev control and retriggering are blocked:

```text
$ id
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)

$ udevadm control --ping
Failed to send a ping message: Permission denied

$ udevadm trigger --action=change /sys/devices/virtual/mem/null
null: Failed to write 'change' to '/sys/devices/virtual/mem/null/uevent': Permission denied

$ echo change > /sys/devices/virtual/misc/fuse/uevent
cannot create /sys/devices/virtual/misc/fuse/uevent: Permission denied
```

Forged kobject uevent injection does not reach udev. Sending to the multicast group fails with `EPERM`; sending to pid 0 without multicast succeeds as a unicast-to-kernel send but does not create the marker and is not delivered to the udev monitor:

```text
bind ok (74743, 0)
sendto (0, 1) fail 1 Operation not permitted
sendto (0, 0) ok 158
/tmp/udev_fake_marker: absent
/root/udev_fake_marker: absent
```

Block/storage event creation gates:

```text
$ losetup -f
/dev/loop0

$ losetup -f /tmp/udev-loop.img
losetup: /tmp/udev-loop.img: failed to set up loop device: Permission denied

$ printf '0 8 zero\n' | dmsetup create udevhotplug_dm
device-mapper: version ioctl on   failed: Permission denied
Command failed.

$ mknod /tmp/udevhotplug-dev/fakeblock b 7 200
mknod: /tmp/udevhotplug-dev/fakeblock: Operation not permitted
```

Initial-namespace network device creation is blocked:

```text
$ ip tuntap add dev udevtun0 mode tun user attacker
ioctl(TUNSETIFF): Operation not permitted
```

The attacker can create a dummy interface inside a private user+network namespace:

```text
$ unshare -Urn sh -c 'id; ip link add name udevpwn0 type dummy; ip link show udevpwn0'
uid=0(root) gid=0(root) groups=0(root)
11: udevpwn0: <BROADCAST,NOARP> mtu 1500 ...
```

However, root `udevadm monitor --kernel --udev --property --subsystem-match=net` saw no kernel or udev events for that private-netns interface. The default root net helpers in `70-iscsi-network-interface.rules` and `99-systemd.rules` were therefore not reached by uid1001.

Interface-name injection was also bounded. In a private netns the kernel rejects whitespace, slash, colon, and overlength names; metacharacter-looking names such as `abc;id` and `x=y` can exist, but they do not cross to root udev and udev RUN commands are not shell-evaluated unless the rule explicitly invokes a shell.

## Docker-only uinput event

The live Docker target exposes `/dev/uinput` as `0666`:

```text
crw-rw-rw- 666 root root a:df character special file /dev/uinput
```

The prior device/proc audit did not find an installed Ubuntu rule proving that mode as stock Ubuntu Server default. The installed default rule only says `SUBSYSTEM=="input", GROUP="input"` at `/usr/lib/udev/rules.d/50-udev-default.rules:49`; no shipped rule grants world access to `/dev/uinput`.

With the Docker-only node, uid1001 can create a virtual input device named `Wiebetech LLC Wiebetech`. That generates real input uevents:

```text
KERNEL add /devices/virtual/input/input5 (input)
NAME="Wiebetech LLC Wiebetech"

KERNEL add /devices/virtual/input/input5/event0 (input)
DEVNAME=/dev/input/event0

UDEV add /devices/virtual/input/input5 (input)
ID_INPUT=1
ID_INPUT_KEY=1
TAGS=:seat:

UDEV add /devices/virtual/input/input5/event0 (input)
ID_INPUT=1
ID_INPUT_KEY=1
TAGS=:power-switch:
```

With udev debug logging enabled for the test, the root worker matched and executed the stock seat rule:

```text
/usr/lib/udev/rules.d/71-seat.rules:77 RUN '/usr/bin/loginctl lock-sessions'
Running command "/usr/bin/loginctl lock-sessions"
Starting '/usr/bin/loginctl lock-sessions'
Process '/usr/bin/loginctl lock-sessions' succeeded.
```

This is root helper execution, but it is not a valid LPE:

- `/dev/uinput` world access is Docker/host-device exposure, not proven stock Ubuntu Server default.
- The matched helper is a fixed absolute path, `/usr/bin/loginctl`, with fixed argument `lock-sessions`.
- No attacker-controlled shell, file path, or command argument reaches the helper.
- The resulting primitive is at most session locking/input-related denial of service if a relevant consumer exists; it does not create root code execution.
- The test sent no input events and created no root marker.

Cleanup after the test:

```text
/proc/bus/input/devices: no Wiebetech device
/dev/input: only root-owned mice node remained
/tmp/udev_fake_marker: absent
/root/udev_fake_marker: absent
/root/udevhotplug_marker: absent
systemctl is-system-running: running
attacker identity unchanged
```

## Helper environment and path assumptions

`systemd-udevd` runs from the system manager, not from the attacker shell. Its observed environment includes:

```text
USER=root
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
LISTEN_FDNAMES=systemd-udevd-control.socket:systemd-udevd-kernel.socket
```

The path directories and udev helper directories are root-owned and not attacker-writable:

```text
/usr/bin: drwxr-xr-x root root
/usr/sbin: drwxr-xr-x root root
/usr/lib/udev: drwxr-xr-x root root
/usr/lib/udev/rules.d: drwxr-xr-x root root
/etc/udev/rules.d: drwxr-xr-x root root
/run/udev/data: drwxr-xr-x root root
```

Unqualified helper names such as `usb_modeswitch`, `cdrom_id`, `fido_id`, `iocost`, `bcache-register`, and `kpartx_id` resolve through udev's root-owned helper/search paths or root-owned system path entries. The attacker cannot replace those helpers or add rules.

The most dangerous-looking rule is `/usr/lib/udev/rules.d/50-udev-default.rules:4`:

```text
ACTION=="remove", ENV{REMOVE_CMD}!="", RUN+="$env{REMOVE_CMD}"
```

No installed rule sets `REMOVE_CMD`, and attacker attempts to inject it through a forged netlink uevent did not reach udev. The udev database under `/run/udev/data` is root-owned and not attacker-writable, so uid1001 could not seed `REMOVE_CMD` for a later remove event.

The explicit shell rules in `80-udisks2.rules` only run on block/md devices and use udev-created temp device paths. The attacker could not create the required block/md trigger in the initial namespace. The open-iscsi net helper reads `/run/initramfs/open-iscsi.interface` and optional `/run/net-$iface.conf` files, but those paths were absent/default root state; uid1001 could not create the initial-namespace net event or the root-side state files.

## Why scanners likely miss this

A static rule scanner will flag `RUN+="$env{REMOVE_CMD}"`, unqualified helper names, `/bin/sh -c` mdadm pipelines, and root `RUN` helpers on `net` and `input` events. Those are real trust boundaries, but they only become exploitable if uid1001 can either inject udev properties, write udev's database/rules/helpers, or create a matching initial-namespace kernel event. The live tests showed those prerequisites are blocked in the stock Docker target, except for Docker-specific `/dev/uinput`, which only reaches fixed `loginctl lock-sessions`.

A generic device-node scan will also over-rank the live `0666` `/dev/uinput` node. The root udev trace is the key discriminator: it proves real helper execution, but the helper and arguments are fixed and the node mode is not backed by installed Ubuntu Server udev rules.

## Triage recommendation

No Ubuntu Security LPE finding should be filed from this surface as tested.

Hardening ideas:

- Keep `/run/udev/control`, `/run/udev/data`, `/etc/udev/rules.d`, and `/usr/lib/udev` root-owned and non-writable by ordinary users.
- Consider documenting or constraining `RUN+="$env{REMOVE_CMD}"` so downstream rules do not accidentally make attacker-controlled properties executable on remove.
- Avoid granting world access to `/dev/uinput` in server/container deployments unless input injection is explicitly required.
- For defense in depth, prefer absolute helper paths in shipped rules where practical, although no attacker-controlled PATH replacement was reachable here.
