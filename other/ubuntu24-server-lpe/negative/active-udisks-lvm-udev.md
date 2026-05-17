# Negative: active UDisks loop images into root LVM udev activation

Status: no validated LPE. This path is default-reachable and interesting, but it did not cross from a normal active local user into root command execution beyond a fixed `lvm vgchange` invocation on LVM-validated volume group names.

## Target and default proof

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS.

Users:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

Packages:

```text
lvm2    2.03.16-3ubuntu3.2
polkitd 124-2ubuntu1.24.04.3
systemd 255.4-1ubuntu8.15
udev    255.4-1ubuntu8.15
udisks2 2.10.1-6ubuntu1.3
```

Default unit state:

```text
udisks2.service enabled active
lvm2-lvmpolld.socket enabled active
lvm2-monitor.service enabled inactive
```

UDisks has a default active-user loop setup action:

```text
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy:
1143 <action id="org.freedesktop.udisks2.loop-setup">
```

## Code/config path

`/usr/lib/udev/rules.d/69-lvm.rules` turns LVM PV loop-device events into root `systemd-run` jobs:

```text
44  # Loop device:
46  KERNEL!="loop[0-9]*", GOTO="next"
47  ACTION=="add", ENV{LVM_LOOP_PV_ACTIVATED}=="1", GOTO="lvm_scan"
48  ACTION=="change", ENV{LVM_LOOP_PV_ACTIVATED}!="1", TEST=="loop/backing_file", ENV{LVM_LOOP_PV_ACTIVATED}="1", GOTO="lvm_scan"
55  LABEL="lvm_scan"
82  IMPORT{program}="/usr/sbin/lvm pvscan --cache --listvg --checkcomplete --vgonline --autoactivation event --udevoutput --journal=output $env{DEVNAME}"
85  ENV{LVM_VG_NAME_COMPLETE}=="?*", RUN+="/usr/bin/systemd-run --no-block --property DefaultDependencies=no --unit lvm-activate-$env{LVM_VG_NAME_COMPLETE} /usr/sbin/lvm vgchange -aay --autoactivation event $env{LVM_VG_NAME_COMPLETE}"
```

The dangerous-looking boundary is attacker-controlled disk metadata producing `LVM_VG_NAME_COMPLETE`, which is interpolated into both the transient unit name and the final `vgchange` argument.

## Trigger

Probe:

```sh
./pocs/active_udisks_lvm_udev_probe.sh ubuntu24-server-lpe-target
```

The probe uses root only to create well-formed LVM metadata fixtures. That is not an escalation step; a real attacker can supply arbitrary disk-image bytes. The privilege boundary tested is active `selfauth` asking UDisks to attach those images as loop devices.

Active-session trigger proof:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
/dev/tty1
Seat=seat0
TTY=tty1
Active=yes
State=active

Mapped file .../lvmprobe-a+b.c_d.img as /dev/loop0.
Mapped file .../lvmprobe.service.img as /dev/loop1.
Mapped file .../lvmprobe_ok.img as /dev/loop2.
NAME="loop0" TYPE="loop" FSTYPE="LVM2_member"
NAME="loop1" TYPE="loop" FSTYPE="LVM2_member"
NAME="loop2" TYPE="loop" FSTYPE="LVM2_member"
```

Root udev/systemd did react:

```text
Started lvm-activate-lvmprobe-a\x2bb.c_d.service - /usr/sbin/lvm vgchange -aay --autoactivation event lvmprobe-a+b.c_d.
0 logical volume(s) in volume group "lvmprobe-a+b.c_d" now active

Started lvm-activate-lvmprobe.service - /usr/sbin/lvm vgchange -aay --autoactivation event lvmprobe.service.
0 logical volume(s) in volume group "lvmprobe.service" now active

Started lvm-activate-lvmprobe_ok.service - /usr/sbin/lvm vgchange -aay --autoactivation event lvmprobe_ok.
0 logical volume(s) in volume group "lvmprobe_ok" now active
```

## Why it is not an LPE

LVM volume group names are constrained before valid metadata is produced:

```text
bad space  -> invalid character
a/b        -> invalid character
a;b        -> invalid character
a\nb       -> invalid character
--property=Environment=X=Y -> parsed as an invalid vgcreate option, not a VG name
lvmprobe-a+b.c_d -> accepted
lvmprobe.service -> accepted
```

The accepted character set is `a-zA-Z0-9.-_+`. That is enough to influence a transient unit name, including a `.service` suffix and escaped `+`, but it is not enough to add new `systemd-run` options, inject shell metacharacters, create path traversal, or alter the executable. The root command stayed:

```text
/usr/sbin/lvm vgchange -aay --autoactivation event <validated-vg-name>
```

The root marker was absent:

```text
ls: cannot access '/root/active_udisks_lvm_udev_root': No such file or directory
ls: cannot access '/tmp/active_udisks_lvm_udev_root': No such file or directory
```

Impact is limited to root auto-activation attempts and transient unit-name influence for LVM metadata supplied by an active local user. I did not get root code execution, an arbitrary root file write, or privileged group membership.

## Cleanup

The probe removes the LVM VGs, detaches loop devices, clears `lvm-activate-*` failed units, removes `/home/selfauth/active-udisks-lvm-udev`, and deletes marker paths. Final health:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend -> no output
```

## Why scanners may miss it

This is a semantic cross-daemon path: UDisks grants active users loop setup, udev runs as root on the resulting block-device metadata, LVM exports a metadata-derived value, and systemd-run consumes it as both a unit-name fragment and a command argument. A scanner can flag the interpolation in `69-lvm.rules`, but it will usually not model active-seat polkit reachability and LVM's metadata-name grammar together.

## Hardening

This is not a security fix request for a proven LPE. Hardening would be to escape or hash `LVM_VG_NAME_COMPLETE` for the transient unit name and pass the VG name only as a command argument, so unit naming cannot collide or truncate around `.service` suffix behavior.
