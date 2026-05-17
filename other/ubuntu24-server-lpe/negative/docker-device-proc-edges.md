# Docker device/proc edges: negative

Date: 2026-05-16

Surface owner: bounded audit of world-writable `/dev` nodes and proc/sys oddities in `ubuntu24-server-lpe-target`.

Result: no valid local privilege escalation. The attacker can open several `0666` device nodes in the Docker target, but all tested paths either stop at kernel capability checks, expose read/input primitives without a default root-consuming path, or are Docker/privileged-container-specific device exposure rather than proven stock Ubuntu Server defaults.

## Scope

Tested as:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Target identity:

```text
Ubuntu 24.04.4 LTS
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64
```

The kernel and several device nodes are Docker Desktop/LinuxKit or `--privileged` container artifacts. I only treated `/dev/net/tun`, `/dev/fuse`, and `/dev/vsock` as stock/default candidates because installed Ubuntu udev rules explicitly set those modes:

```text
/usr/lib/udev/rules.d/50-udev-default.rules:109: KERNEL=="tun", MODE="0666", OPTIONS+="static_node=net/tun"
/usr/lib/udev/rules.d/50-udev-default.rules:111: KERNEL=="fuse", MODE="0666", OPTIONS+="static_node=fuse"
/usr/lib/udev/rules.d/50-udev-default.rules:118: KERNEL=="vsock", MODE="0666"
```

The live-target `0666` modes for `/dev/uinput`, `/dev/cuse`, `/dev/mapper/control`, `/dev/ppp`, `/dev/hwrng`, `/dev/hvc1`-`/dev/hvc7`, and `/dev/usbmon*` were not counted as stock Ubuntu Server defaults. The installed rules only name or tag some of them, for example `/usr/lib/udev/rules.d/55-dm.rules:31` names `/dev/mapper/control` without setting mode, and `/usr/lib/udev/rules.d/99-systemd.rules:12` tags `hvc*` TTYs without granting world access.

## Findings

`/dev/net/tun`: user-openable and `TUNGETFEATURES` works, but `TUNSETIFF` fails with `Operation not permitted`. `ip tuntap add dev devproc_tun0 mode tun user attacker` also fails with `ioctl(TUNSETIFF): Operation not permitted`. No network device is created.

`/dev/fuse`: user-openable, but FUSE mount behavior was already bounded elsewhere and does not by itself create a root execution path. No root default service traversed an attacker FUSE mount in this device/proc audit.

`/dev/vsock`: user-openable and an `AF_VSOCK` stream socket can be created, but no privileged default VSOCK server or root state transition was identified in the Docker target.

`/dev/mapper/control`: user-openable in this Docker target, but `dmsetup version` and `dmsetup create devproc_dm` both fail at the device-mapper version ioctl with `Permission denied`. No device-mapper target is created.

`/proc/sys/kernel/ns_last_pid`: mode is `0666`, but attacker writes fail with `EPERM`. No PID-control primitive was available.

`/dev/uinput`: the Docker target permits uid1001 to create and destroy a virtual input device without sending events. That is an input-injection primitive in this privileged-container environment, not a stock Ubuntu Server root LPE. There is no default root GUI/console consumer in scope, and physical-console-only or preexisting-root-session effects do not satisfy the goal.

`/dev/hvc*`: `/dev/hvc0` is not attacker-accessible; `/dev/hvc1`-`/dev/hvc7` are mode `666` in Docker but open fails with `ENODEV`. No login/getty/root consumer was reachable.

`/dev/usbmon*`: user-openable in this Docker target. Nonblocking reads returned `EAGAIN`; even if traffic were present this is capture/visibility, not root execution.

`/dev/hwrng`: user can read random bytes. No write or execution path.

`/dev/ppp`: despite mode `666`, attacker open fails with `EPERM`. `ppp`/`pppd` is not installed in this target.

`/dev/cuse`: user-openable in this Docker target, but no default root service consumes attacker-created CUSE devices and no stock default `0666` proof was found.

## Reproduction

Script:

```bash
CONTAINER=ubuntu24-server-lpe-target /Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe/pocs/devproc_probe.sh
```

Key output:

```text
dmsetup create devproc_dm -> Permission denied, rc=1
ip tuntap add dev devproc_tun0 mode tun user attacker -> Operation not permitted, rc=1
tun TUNSETIFF -> PermissionError errno=1 Operation not permitted
uinput create/destroy -> OK, created virtual input device; sent no events
ns_last_pid write -> PermissionError errno=1 Operation not permitted
no root marker
```

## Cleanup

The probe removes any accidental `devproc_tun0` or `devproc_dm` state and deletes `/tmp/devproc_*` and `/home/attacker/devproc_*`. Follow-up verification showed:

```text
grep "devproc-audit" /proc/bus/input/devices    # no output
ip link show devproc_tun0                       # Device does not exist
dmsetup info devproc_dm                         # Device does not exist
/root/devproc_lpe_marker                        # absent
```

## Why this is not a valid LPE

The only meaningful primitive was Docker-exposed `/dev/uinput` virtual input creation. That does not execute code as root, does not cross to a default root service, and would require an out-of-scope trusted input consumer such as a physical console or existing privileged session. TUN and device-mapper stop at capability checks, `ns_last_pid` is write-gated despite mode `666`, HVC nodes are unusable, and the remaining devices are read/info or environment-specific.

No Ubuntu Security finding should be filed from this surface as tested. Hardening guidance for container operators is to avoid `--privileged` and explicitly deny unnecessary host devices such as `/dev/uinput`, `/dev/usbmon*`, `/dev/hwrng`, `/dev/cuse`, and `/dev/mapper/control` unless required.
