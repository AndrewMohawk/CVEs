# devproc 2026-05-16 evidence

Target: `ubuntu24-server-lpe-target`

Result: negative. No uid1001-to-root LPE was validated from the scoped world-writable device/proc edges.

## Target identity

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
attacker : attacker
```

Package versions relevant to this surface:

```text
dmsetup        2:1.02.185-3ubuntu3.2
fuse3          3.14.0-5build1
libfuse3-3     3.14.0-5build1
linux-base     4.5ubuntu9+24.04.2
lvm2           2.03.16-3ubuntu3.2
systemd        255.4-1ubuntu8.15
udev           255.4-1ubuntu8.15
```

The kernel is Docker Desktop/LinuxKit, not a stock Ubuntu Server kernel. Device-node behavior below is therefore treated as live-target evidence only unless a stock Ubuntu udev rule proves the default server node and mode.

## Device inventory

Root-side stat output from the live target:

```text
crw-rw-rw- 666 root root a:df character special file /dev/uinput
crw-rw-rw- 666 root root a:ec character special file /dev/mapper/control
crw-rw-rw- 666 root root a:c8 character special file /dev/net/tun
crw-rw-rw- 666 root root a:e5 character special file /dev/fuse
crw-rw-rw- 666 root root a:cb character special file /dev/cuse
crw-rw-rw- 666 root root a:7d character special file /dev/vsock
crw-rw-rw- 666 root root 6c:0 character special file /dev/ppp
crw-rw-rw- 666 root root a:b7 character special file /dev/hwrng
-rw-rw-rw- 666 root root 0:0 regular empty file /proc/sys/kernel/ns_last_pid
crw------- 600 root tty e5:0 character special file /dev/hvc0
crw-rw-rw- 666 root root e5:1 character special file /dev/hvc1
crw-rw-rw- 666 root root e5:2 character special file /dev/hvc2
crw-rw-rw- 666 root root e5:3 character special file /dev/hvc3
crw-rw-rw- 666 root root e5:4 character special file /dev/hvc4
crw-rw-rw- 666 root root e5:5 character special file /dev/hvc5
crw-rw-rw- 666 root root e5:6 character special file /dev/hvc6
crw-rw-rw- 666 root root e5:7 character special file /dev/hvc7
crw-rw-rw- 666 root root f7:0 character special file /dev/usbmon0
crw-rw-rw- 666 root root f7:1 character special file /dev/usbmon1
crw-rw-rw- 666 root root f7:2 character special file /dev/usbmon2
```

Attacker access bits:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
rw /dev/uinput
rw /dev/mapper/control
rw /dev/net/tun
rw /dev/fuse
rw /dev/cuse
rw /dev/vsock
rw /dev/ppp
rw /dev/hwrng
rw /proc/sys/kernel/ns_last_pid
-- /dev/hvc0
rw /dev/hvc1
rw /dev/hvc2
rw /dev/hvc3
rw /dev/hvc4
rw /dev/hvc5
rw /dev/hvc6
rw /dev/hvc7
rw /dev/usbmon0
rw /dev/usbmon1
rw /dev/usbmon2
```

## Stock/default proof boundary

Ubuntu's installed udev rules prove stock default world-writable nodes for TUN, FUSE, and VSOCK if those kernel devices/modules exist:

```text
/usr/lib/udev/rules.d/50-udev-default.rules:109: KERNEL=="tun", MODE="0666", OPTIONS+="static_node=net/tun"
/usr/lib/udev/rules.d/50-udev-default.rules:111: KERNEL=="fuse", MODE="0666", OPTIONS+="static_node=fuse"
/usr/lib/udev/rules.d/50-udev-default.rules:118: KERNEL=="vsock", MODE="0666"
/usr/lib/udev/rules.d/60-open-vm-tools.rules:6: KERNEL=="vsock", MODE="0666"
```

The live target also has `0666` `/dev/uinput`, `/dev/cuse`, `/dev/mapper/control`, `/dev/ppp`, `/dev/hwrng`, `/dev/hvc1`-`/dev/hvc7`, and `/dev/usbmon*`, but I did not find installed Ubuntu rules proving those exact `0666` modes as stock server defaults. Treat those nodes as Docker/privileged-container or host-device exposure for this audit. `55-dm.rules` names `/dev/mapper/control` but does not set mode:

```text
/usr/lib/udev/rules.d/55-dm.rules:31: KERNEL=="device-mapper", NAME="mapper/control"
```

`99-systemd.rules` tags `hvc*` TTYs for systemd but does not make them world-writable:

```text
/usr/lib/udev/rules.d/99-systemd.rules:12: SUBSYSTEM=="tty", KERNEL=="tty[a-zA-Z]*|hvc*|xvc*|hvsi*|ttysclp*|sclp_line*|3270/tty[0-9]*", TAG+="systemd"
```

## Trigger commands and results

Probe command:

```bash
CONTAINER=ubuntu24-server-lpe-target /Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe/pocs/devproc_probe.sh
```

Privileged-operation gates as `attacker`:

```text
-- dmsetup version
device-mapper: version ioctl on   failed: Permission denied
Incompatible libdevmapper 1.02.185 (2022-05-18) and kernel driver (unknown version).
Command failed.
Library version:   1.02.185 (2022-05-18)
rc=1

-- dmsetup create devproc_dm
device-mapper: version ioctl on   failed: Permission denied
Incompatible libdevmapper 1.02.185 (2022-05-18) and kernel driver (unknown version).
Command failed.
rc=1

-- ip tuntap add
ioctl(TUNSETIFF): Operation not permitted
rc=1
Device "devproc_tun0" does not exist.
rc=1

-- ns_last_pid shell write
old=67883
rc=1
```

Direct Python open/read/ioctl probes as `attacker`:

```text
/dev/uinput: OK: open mode=rdwr
/dev/mapper/control: OK: open mode=rdwr
/dev/net/tun: OK: open mode=rdwr
/dev/fuse: OK: open mode=rdwr
/dev/cuse: OK: open mode=rdwr
/dev/vsock: OK: open mode=rdwr
/dev/ppp: FAIL: PermissionError errno=1 Operation not permitted
/dev/hwrng: OK: open mode=rdonly; read_len=16
/dev/hvc0: FAIL: PermissionError errno=13 Permission denied
/dev/hvc1: FAIL: OSError errno=19 No such device
/dev/hvc2: FAIL: OSError errno=19 No such device
/dev/hvc3: FAIL: OSError errno=19 No such device
/dev/hvc4: FAIL: OSError errno=19 No such device
/dev/hvc5: FAIL: OSError errno=19 No such device
/dev/hvc6: FAIL: OSError errno=19 No such device
/dev/hvc7: FAIL: OSError errno=19 No such device
/dev/usbmon0: OK: open mode=rdwr; read=BlockingIOError errno=11 Resource temporarily unavailable
/dev/usbmon1: OK: open mode=rdwr; read=BlockingIOError errno=11 Resource temporarily unavailable
/dev/usbmon2: OK: open mode=rdwr; read=BlockingIOError errno=11 Resource temporarily unavailable
tun TUNGETFEATURES: OK: features=0x7173
tun TUNSETIFF: FAIL: PermissionError errno=1 Operation not permitted
uinput create/destroy: OK: created virtual input device; sent no events
AF_VSOCK socket: OK: created stream socket
ns_last_pid write: FAIL: PermissionError errno=1 Operation not permitted
```

The only active primitive beyond open/read was `/dev/uinput` virtual device creation in the privileged Docker target. The probe did not send key events. This is at most an input-injection primitive against some environment with an existing trusted input consumer, not uid1001-to-root on stock Ubuntu Server. It is also not proven to be a stock Ubuntu Server default node/mode from the installed udev rules.

## Cleanup and root proof

Probe cleanup:

```text
no root marker
Device "devproc_tun0" does not exist.
Device does not exist.
Command failed.
```

Follow-up cleanup verification:

```text
grep -n "devproc-audit" /proc/bus/input/devices || true    # no output
ip link show devproc_tun0                                  # Device does not exist
dmsetup info devproc_dm                                    # Device does not exist
test -e /root/devproc_lpe_marker                           # absent
find /tmp /home/attacker -maxdepth 1 -name "devproc_*"     # no output
```

No root context was reached, no root marker was created, no TUN device or device-mapper target remained, and the temporary uinput device was destroyed.
