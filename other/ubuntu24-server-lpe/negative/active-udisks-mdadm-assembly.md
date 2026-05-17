# Negative: active-seat UDisks mdadm auto-assembly

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server Docker target  
Users: `attacker` and `selfauth`, both normal non-sudo users

## Result

No root proof. Active `selfauth` can map attacker-supplied mdadm member images through UDisks, and root udev imports mdadm metadata for those loop devices, but this Docker target has no usable MD kernel support (`/sys/module/md_mod` absent and `/proc/mdstat` absent). Root `mdadm --incremental --export` attempted assembly and failed before creating `/dev/md*`, so the downstream `mdadm-last-resort@`, `mdmonitor.service`, `mdmon@`, md device-name, and md container paths did not become exploitable.

The probe did not produce root command execution, root file write, or a privileged group transition.

## Default reachability

Packages:

```text
mdadm   4.3-1ubuntu2.1
polkitd 124-2ubuntu1.24.04.3
systemd 255.4-1ubuntu8.15
udev    255.4-1ubuntu8.15
udisks2 2.10.1-6ubuntu1.3
```

Default unit/rule surface:

```text
udisks2.service enabled and active
mdadm-last-resort@.service static
mdadm-last-resort@.timer static
mdmon@.service static
mdmonitor.service static
mdmonitor-oneshot.service static
```

UDisks loop setup is active-user reachable:

```text
<action id="org.freedesktop.udisks2.loop-setup">
  <allow_active>yes</allow_active>
</action>
```

The root udev path is present:

```text
64-md-raid-assembly.rules:41 IMPORT{program}="/sbin/mdadm --incremental --export $devnode --offroot $env{DEVLINKS}"
64-md-raid-assembly.rules:42 ENV{MD_STARTED}=="*unsafe*", ENV{MD_FOREIGN}=="no", ENV{SYSTEMD_WANTS}+="mdadm-last-resort@$env{MD_DEVICE}.timer"

63-md-raid-arrays.rules:21 IMPORT{program}="/sbin/mdadm --detail --no-devices --export $devnode"
63-md-raid-arrays.rules:22 SYMLINK+="disk/by-id/md-name-$env{MD_NAME}", OPTIONS+="string_escape=replace"
63-md-raid-arrays.rules:37 ENV{MD_LEVEL}=="raid[1-9]*", ENV{SYSTEMD_WANTS}+="mdmonitor.service"
63-md-raid-arrays.rules:40-42 MD_CONTAINER -> readlink/basename -> SYSTEMD_WANTS+="mdmon@%c.service"
```

## Trigger

Probe:

```sh
./pocs/active_udisks_mdadm_assembly_probe.sh ubuntu24-server-lpe-target
```

The probe generated mdadm v1.2 member images as raw attacker-supplied bytes, including:

```text
MD_NAME=mdprobe_ok
MD_NAME=mdprobe.service
MD_NAME=mdprobe
```

The third image had a raw newline in the mdadm set name:

```text
Name : mdprobe
SYSTEMD_WANTS=active-udi
```

`mdadm --examine --export` truncated that newline-bearing name to `MD_NAME=mdprobe`, so it did not export a standalone `SYSTEMD_WANTS=` assignment.

The active-seat trigger was real:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
TTY=tty1
Seat=seat0
Active=yes
State=active

Mapped file .../mdprobe.service/a.img as /dev/loop0.
Mapped file .../mdprobe.service/b.img as /dev/loop1.
Mapped file .../mdprobe_ok/a.img as /dev/loop2.
Mapped file .../mdprobe_ok/b.img as /dev/loop3.
Mapped file .../newline_wants/a.img as /dev/loop4.
Mapped file .../newline_wants/b.img as /dev/loop5.
```

Root udev/UDisks imported the member metadata:

```text
ID_FS_TYPE=linux_raid_member
ID_FS_LABEL=mdprobe.service
UDISKS_MD_MEMBER_LEVEL=raid1
UDISKS_MD_MEMBER_NAME=mdprobe.service

ID_FS_LABEL=mdprobe_SYSTEMD_WANTS=active-udi
ID_FS_LABEL_ENC=mdprobe\x0aSYSTEMD_WANTS=active-udi
UDISKS_MD_MEMBER_NAME=mdprobe
```

## Why it did not cross privilege

The Docker target cannot instantiate MD arrays:

```text
md_mod sysfs absent
cat: /proc/mdstat: No such file or directory
```

Every root replay of the udev-equivalent incremental assembly failed:

```text
modprobe: FATAL: Module md_mod not found in directory /lib/modules/6.10.14-linuxkit
mdadm: Fail to create md127 when using /sys/module/md_mod/parameters/new_array, fallback to creation via node
mdadm: unexpected failure opening /dev/md127
mdadm_incremental_rc=1
```

Because no `/dev/md*` device was created, the assembled-array rule path did not import `MD_NAME`, `MD_DEVNAME`, or `MD_CONTAINER` from `mdadm --detail`, did not create `/dev/disk/by-id/md-name-*` or `/dev/md/*`, and did not start `mdmonitor.service`, `mdmon@*.service`, or `mdadm-last-resort@*.timer`.

The temporary marker service used only to detect metadata-driven `SYSTEMD_WANTS` injection remained inactive:

```text
active-udisks-mdadm-pwn.service loaded inactive dead
ROOT_PROOF_ABSENT /root/active_udisks_mdadm_assembly_root
ROOT_PROOF_ABSENT /run/active_udisks_mdadm_assembly_root
ROOT_PROOF_ABSENT /tmp/active_udisks_mdadm_assembly_root
```

No group transition occurred:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
sudo:x:27:ubuntu
adm:x:4:ubuntu,syslog
disk:x:6:
systemd-journal:x:999:
```

## Cleanup

The probe removed the temporary marker unit, removed `/home/selfauth/active-udisks-mdadm-assembly`, detached all loop devices backed by the test images, reset mdadm/mdmon/mdmonitor failed state, and deleted marker paths. Final health:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend -> no output
losetup -a | grep active-udisks-mdadm-assembly -> no output
```

## Conclusion

This remains a reachable root udev parsing boundary from an active local user, but no LPE was validated in the stock Ubuntu 24.04 Server Docker target. The important blockers were mdadm export truncating newline-bearing names and the target lacking MD kernel support, which prevented assembled md device-name/container metadata from reaching the mdmonitor, mdmon, last-resort, or devlink rules.
