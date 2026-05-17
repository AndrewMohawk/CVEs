# Negative: active-seat UDisks btrfs udev metadata

Status: no validated LPE.

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server Docker target. Users: `attacker` uid1001 and `selfauth` uid1002, both normal non-sudo users.

Artifacts:

```text
pocs/active_udisks_btrfs_udev_probe.sh
logs/active-udisks-btrfs-udev.out
```

## Default Proof

Relevant default package versions from the live target:

```text
btrfs-progs  6.6.3-1.1build2
polkitd      124-2ubuntu1.24.04.3
systemd      255.4-1ubuntu8.15
udev         255.4-1ubuntu8.15
udisks2      2.10.1-6ubuntu1.3
```

`udisks2.service` is enabled and active. The UDisks polkit action `org.freedesktop.udisks2.loop-setup` allows active local users, so a passworded local `selfauth` tty session can create loop devices from files it owns.

The root udev btrfs path is installed by default:

```text
/usr/lib/udev/rules.d/64-btrfs.rules:5  ENV{ID_FS_TYPE}!="btrfs", GOTO="btrfs_end"
/usr/lib/udev/rules.d/64-btrfs.rules:9  IMPORT{builtin}="btrfs ready $devnode"
/usr/lib/udev/rules.d/64-btrfs.rules:12 ENV{ID_BTRFS_READY}=="0", ENV{SYSTEMD_READY}="0"
/usr/lib/udev/rules.d/64-btrfs.rules:15 ENV{ID_BTRFS_READY}=="1", RUN+="/usr/bin/udevadm trigger -s block -p ID_BTRFS_READY=0"
```

The adjacent persistent-storage rule creates label links using the encoded label property:

```text
/usr/lib/udev/rules.d/60-persistent-storage.rules:140 ENV{ID_FS_USAGE}=="filesystem|other|crypto", ENV{ID_FS_UUID_ENC}=="?*", SYMLINK+="disk/by-uuid/$env{ID_FS_UUID_ENC}"
/usr/lib/udev/rules.d/60-persistent-storage.rules:141 ENV{ID_FS_USAGE}=="filesystem|other|crypto", ENV{ID_FS_LABEL_ENC}=="?*", SYMLINK+="disk/by-label/$env{ID_FS_LABEL_ENC}"
```

## Trigger

The probe created attacker-owned btrfs images:

```text
single.img label: bt/../SYSTEMD_WANTS=active-udisks-btrfs-pwn.service
multi-a.img/multi-b.img label: btmulti, created as a two-device btrfs filesystem
```

`btrfstune` in this package does not support `-L`, so a raw newline relabel attempt failed before any udev path:

```text
btrfstune_newline_rc=1
btrfstune: invalid option -- 'L'
```

An active tty1 `selfauth` login then ran:

```sh
udisksctl loop-setup -f /home/selfauth/active-udisks-btrfs-udev/single.img --no-user-interaction
udisksctl loop-setup -f /home/selfauth/active-udisks-btrfs-udev/multi-a.img --no-user-interaction
udisksctl loop-setup -f /home/selfauth/active-udisks-btrfs-udev/multi-b.img --no-user-interaction
```

All three loop setups succeeded.

## Results

Root udev imported the btrfs metadata:

```text
/dev/loop0 ID_FS_TYPE=btrfs
/dev/loop0 ID_BTRFS_READY=1
/dev/loop0 ID_FS_LABEL=bt/../SYSTEMD_WANTS=active-udisks-btrfs-pwn.service
/dev/loop0 ID_FS_LABEL_ENC=bt\x2f..\x2fSYSTEMD_WANTS=active-udisks-btrfs-pwn.service

/dev/loop1 ID_FS_TYPE=btrfs
/dev/loop1 ID_BTRFS_READY=1
/dev/loop1 ID_FS_LABEL=btmulti

/dev/loop2 ID_FS_TYPE=btrfs
/dev/loop2 ID_BTRFS_READY=1
/dev/loop2 ID_FS_LABEL=btmulti
```

The hostile label created only an encoded root-owned symlink under `/dev/disk/by-label`:

```text
/dev/disk/by-label/bt\x2f..\x2fSYSTEMD_WANTS=active-udisks-btrfs-pwn.service -> ../../loop0
```

No udev property named `SYSTEMD_WANTS` was imported from the label, and the marker service stayed inactive:

```text
active-udisks-btrfs-pwn.service loaded inactive dead
ROOT_PROOF_ABSENT /root/active_udisks_btrfs_udev_root
ROOT_PROOF_ABSENT /run/active_udisks_btrfs_udev_root
ROOT_PROOF_ABSENT /tmp/active_udisks_btrfs_udev_root
```

## Why It Is Not A Finding

This is a real default trust boundary: an active non-admin local user can cause root udev to parse attacker-controlled btrfs superblocks and run `64-btrfs.rules`.

The tested data did not cross into root execution or an arbitrary root write. `blkid`/udev kept the raw filesystem label as `ID_FS_LABEL` data and used the escaped `ID_FS_LABEL_ENC` for symlink creation. `64-btrfs.rules` derives only `ID_BTRFS_READY` and fixed `SYSTEMD_READY` behavior, then runs a fixed absolute `udevadm trigger` command. The attacker did not control a unit name, command argument, helper path, or root-written file contents.

## Cleanup

The probe detached all loop devices backed by `active-udisks-btrfs-udev`, removed the marker unit and temporary user files, reset failed state, and verified:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend -> 0
```

## Why Scanners May Miss It

A static udev scan will see active-user loop setup, root btrfs metadata parsing, a root `RUN+=udevadm trigger`, and metadata-derived `/dev/disk` links. The exploitable boundary depends on whether btrfs labels or readiness metadata can create new udev properties or systemd wants. The live probe shows they remain encoded data and fixed rule behavior.

## Suggested Fix

No Ubuntu Security LPE fix is supported by this result. Defense in depth is to keep using encoded label variables in persistent-storage links and keep `64-btrfs.rules` free of metadata-derived unit names or shell-evaluated helper arguments.
