# Negative: UDisks LoopSetup into udev/block-metadata root consumers

Date: 2026-05-17  
Target: `ubuntu24-server-lpe-target` (`ubuntu24-server-default-lpe:20260516-standard`)  
Log: `logs/udisks-udev-metadata-consumers-20260517.out`  
Result: no active-user to root file write or code execution was validated.

## Scope

This pass owns the UDisks -> udev/block-metadata root-consumer slice. It tested a real active local `selfauth` session using `udisksctl loop-setup` against private loop images carrying hostile filesystem labels, GPT partition names, mdadm member names, LVM VG names, bcache backing metadata, and XFS mountpoint names.

Root was used only to mint raw image fixtures, collect root-side evidence, and install a temporary `u.service` marker used to detect unexpected `SYSTEMD_WANTS` import. The tested privilege edge was the active non-admin user asking default UDisks to attach/mount those images.

The Docker target only had `/dev/loop0` through `/dev/loop7` while other concurrent probes were using several loops, so the harness temporarily created `/dev/loop8` through `/dev/loop31` device nodes. That was a container harness accommodation only; package state, UDisks policy, udev rules, and service units remained stock. The harness removed its unused added nodes and all private `udisks-udev-meta-consumers-20260517` loops/mounts during cleanup. The log's broad journal excerpt includes unrelated concurrent `udisks-missing-goto-active` activity; conclusions below use the prefixed probe evidence.

## Default proof

The live target was Ubuntu 24.04.4 LTS on the requested container. Relevant package versions:

```text
udisks2 2.10.1-6ubuntu1.3
libudisks2-0 2.10.1-6ubuntu1.3
systemd/udev 255.4-1ubuntu8.15
polkitd 124-2ubuntu1.24.04.3
util-linux 2.39.3-9ubuntu6.5
e2fsprogs 1.47.0-2.4~exp1ubuntu4.1
xfsprogs 6.6.0-1ubuntu2.1
btrfs-progs 6.6.3-1.1build2
mdadm 4.3-1ubuntu2.1
lvm2 2.03.16-3ubuntu3.2
bcache-tools 1.0.8-5build1
gdisk 1.0.10-1build1
```

`org.freedesktop.udisks2.loop-setup` and `org.freedesktop.udisks2.filesystem-mount` both have `allow_active=yes`. The trigger ran as:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
TTY=tty1
Seat=seat0
Active=yes
State=active
```

## Consumer map

The relevant default root consumers were present:

```text
60-persistent-storage.rules: blkid import; by-uuid/by-label via *_ENC; by-partuuid/by-partlabel; by-loop-inode/by-loop-ref
63-md-raid-arrays.rules: mdadm --detail --export; md-name symlinks; mdmonitor/mdmon SYSTEMD_WANTS
64-md-raid-assembly.rules: mdadm --incremental --export; mdadm-last-resort SYSTEMD_WANTS
64-btrfs.rules: btrfs ready import; udevadm trigger for newly-ready multi-device btrfs
69-bcache.rules: probe-bcache import; bcache-register RUN; bcache-export-cached import; bcache/by-* symlinks
69-lvm.rules: lvm pvscan --udevoutput import; systemd-run lvm-activate-$VG; vgchange fallback
80-udisks2.rules: mdadm --examine --export piped through MD_ -> UDISKS_MD_MEMBER_
99-systemd.rules: fixed systemd wants for trusted subsystems, no block-metadata-derived wants in this path
```

The timer/generator consumers checked were `e2scrub_all`, `fstrim`, `xfs_scrub_all` / `xfs_scrub@`, `systemd-fstab-generator`, and `systemd-gpt-auto-generator`.

## Metadata results

`blkid -o udev` did not emit attacker-controlled extra assignment lines. Newline-bearing ext4 and btrfs labels were normalized in `ID_FS_LABEL` and encoded in `ID_FS_LABEL_ENC`:

```text
ext label '\nSYSTEMD_WANTS=u':
ID_FS_LABEL=SYSTEMD_WANTS=u
ID_FS_LABEL_ENC=\x0aSYSTEMD_WANTS=u

btrfs label 'BT\nSYSTEMD_WANTS=u.service':
ID_FS_LABEL=BT_SYSTEMD_WANTS=u.service
ID_FS_LABEL_ENC=BT\x0aSYSTEMD_WANTS=u.service
```

Active UDisks mounted those as sanitized mountpoints and udev created encoded symlinks only:

```text
/media/selfauth/_SYSTEMD_WANTS=u
/media/selfauth/BT_SYSTEMD_WANTS=u.service
/dev/disk/by-label/\x0aSYSTEMD_WANTS=u -> ../../loop8
/dev/disk/by-label/BT\x0aSYSTEMD_WANTS=u.service -> ../../loop7
```

The GPT image carried a partition name containing a newline and `SYSTEMD_WANTS=u.service`. UDisks loop setup produced `loop9p1` sysfs, but this Docker target still lacked `/dev/loop9p1`; udev exported no `ID_PART_ENTRY_NAME` and created only diskseq/loop-inode links. `udevadm test` showed the kernel/partition name as `PARTNAME=pt!SYSTEMD_WANTS=u.service`, not an imported `SYSTEMD_WANTS`.

`mdadm --examine --export` truncated the newline-bearing mdadm name before udev import:

```text
Name : md
SYSTEMD_WANTS=u.service

MD_NAME=md
```

The active loop event imported only prefixed UDisks metadata:

```text
UDISKS_MD_MEMBER_NAME=md
UDISKS_MD_MEMBER_LEVEL=raid1
```

No standalone `SYSTEMD_WANTS` property appeared.

LVM name validation rejected spaces, slash, semicolon, newline, and option-looking names. The accepted name `uulvm.service` reached the root LVM udev consumer, but only as a validated VG name in fixed commands:

```text
Started lvm-activate-uulvm.service - /usr/sbin/lvm vgchange -aay --autoactivation event uulvm.service.
0 logical volume(s) in volume group "uulvm.service" now active
```

That influenced a transient unit name and a `vgchange` argument, but did not inject options, shell, paths, or a writable root file.

The bcache backing image reached root udev as `ID_FS_TYPE=bcache` with UUID metadata. `bcache-register /dev/loop6` ran and failed because the Docker kernel lacks usable bcache registration. No `CACHED_LABEL`, `CACHED_UUID`, `/dev/bcache/by-label`, or `/dev/bcache/by-uuid` path was produced from active UDisks loop setup.

The XFS label `--help` mounted at `/media/selfauth/--help`; it remained an argument-like path string, not an option injection.

## Root consumers

`systemd-fstab-generator` read root-owned `/etc/fstab`, which was the default unconfigured base-system file, and emitted only the normal `systemd-remount-fs.service` symlink. It did not consume mounted media labels or GPT names.

`e2scrub_all.service` is timer-enabled, but default service mode exits before scanning because `/etc/e2scrub.conf` leaves `periodic_e2scrub=0`:

```text
/etc/e2scrub.conf:5:# periodic_e2scrub=1
/sbin/e2scrub_all:28:periodic_e2scrub=0
```

`fstrim.service` and `fstrim.timer` are default-enabled/static but skipped in this Docker target by `ConditionVirtualization=!container`; an active user cannot use the UDisks loop path to start it.

`xfs_scrub_all.timer` is disabled by default. A forced root start while `/media/selfauth/--help` was mounted saw the mountpoint, then failed inside Ubuntu's packaged Python scheduler with `NameError: name 'path' is not defined` and later `NameError: name 'debug' is not defined`. It did not start attacker-controlled root code. The shipped `xfs_scrub@.service` template would run the scrubber as `User=nobody` with `NoNewPrivileges=yes` and `ExecStart=/usr/sbin/xfs_scrub -b -n %f`.

## Root proof and cleanup

The marker unit stayed inactive and all marker files were absent:

```text
u.service loaded inactive dead
ROOT_PROOF_ABSENT /root/udisks-udev-meta-consumers-20260517-root
ROOT_PROOF_ABSENT /run/udisks-udev-meta-consumers-20260517-root
ROOT_PROOF_ABSENT /tmp/udisks-udev-meta-consumers-20260517-root
```

The cleanup removed the marker unit, private loop devices, private mounts, LVM fixture VG, and temporary loop nodes that were not claimed by unrelated concurrent work. A post-cleanup health check returned `systemctl is-system-running -> running`; a later explicit reset/start check confirmed `udisks2.service -> active`.

## Conclusion

No Ubuntu Security LPE from this slice. The active-user UDisks LoopSetup boundary is real, and several root consumers do parse attacker-supplied block metadata. The chain stopped because filesystem labels are normalized/encoded before udev import, GPT partition-name metadata did not become a device-node property in this target, mdadm export truncates newline names and UDisks prefixes member metadata, LVM constrains VG names before root `systemd-run`, bcache registration did not create cached-device label consumers, fstab/gpt generators read root-owned boot config rather than media content, e2scrub is default-disabled in service mode, fstrim is container-condition-gated, and xfs scrub is disabled by default and non-root for the per-mount scrubber path.

No exploit PoC was created because there was no validated root file write or root code execution.
