# Negative: fsck, mount, and public temp maintenance boundaries

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server Docker target. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no uid1001-to-root LPE validated. The interesting `/usr/sbin/fsck.xfs` branch really does use `/tmp/repair_mnt`, but the stock target does not expose a normal-user path that can make a root helper follow, chmod, chown, or write an attacker-controlled `/tmp`, `/var/tmp`, or `/run/lock` path.

Full repeatable evidence: `pocs/fsck_mount_tmp_probe.sh` -> `logs/fsck-mount-tmp.out`.

## Package and default state

Relevant package versions:

```text
e2fsprogs  1.47.0-2.4~exp1ubuntu4.1
lvm2       2.03.16-3ubuntu3.2
mdadm      4.3-1ubuntu2.1
mount      2.39.3-9ubuntu6.5
systemd    255.4-1ubuntu8.15
udev       255.4-1ubuntu8.15
util-linux 2.39.3-9ubuntu6.5
xfsprogs   6.6.0-1ubuntu2.1
```

Helper ownership:

```text
/usr/sbin/fsck.xfs       root:root 0755
/usr/sbin/xfs_repair     root:root 0755
/usr/sbin/xfs_scrub_all  root:root 0755
/sbin/e2scrub_all        root:root 0755
/usr/lib/systemd/systemd-fsck root:root 0755
/sbin/fstrim             root:root 0755
/sbin/blkdeactivate      root:root 0755
/usr/bin/mount           root:root 4755
/usr/bin/umount          root:root 4755
/usr/lib/udisks2/udisksd missing
```

Default root entrypoints:

```text
systemd-fsck-root.service static inactive, ConditionResult=no
e2scrub_all.timer         enabled active waiting
e2scrub_all.service       static inactive, exits 0
fstrim.timer              enabled inactive, ConditionVirtualization=!container unmet
xfs_scrub_all.timer       disabled inactive
blk-availability.service  enabled active exited, ExecStop only
```

`/etc/fstab` is the stock unconfigured file, `/etc/e2scrub.conf` is root-owned and leaves `periodic_e2scrub=1` commented, the Docker root is overlay/erofs rather than XFS, and no fsck units are generated from fstab.

## Temp and lock paths

`/tmp`, `/var/tmp`, and `/run/lock` are attacker-writable sticky directories. The LVM lock subdirectory is not:

```text
/tmp          1777 root:root
/var/tmp      1777 root:root
/run/lock     1777 root:root
/run/lock/lvm 0700 root:root
/etc/fstab    0644 root:root
/etc/e2scrub.conf 0644 root:root
```

The risky-looking XFS branch is present:

```text
/usr/sbin/fsck.xfs:72 mkdir -p /tmp/repair_mnt
/usr/sbin/fsck.xfs:85 mount $DEV /tmp/repair_mnt $ROOTFLAGS
/usr/sbin/fsck.xfs:87 mount $DEV /tmp/repair_mnt
/usr/sbin/fsck.xfs:89 umount /tmp/repair_mnt
/usr/sbin/fsck.xfs:92 rm -d /tmp/repair_mnt
```

That branch only runs under forced fsck plus an `xfs_repair` dirty-log return. In the stock target, the root fsck paths are boot/systemd paths fed by root-owned fstab/kernel/block-device state. uid1001 cannot create `/forcefsck`, alter kernel `fsck.mode`, write fstab, create block devices, or start the root service.

## Attacker probes

As uid1001:

```text
touch /forcefsck                         -> Permission denied
systemctl start systemd-fsck-root.service -> Interactive authentication required
systemctl start fstrim.service            -> Interactive authentication required
systemctl start blk-availability.service  -> Interactive authentication required
systemctl start e2scrub_all.service       -> Interactive authentication required
systemctl start xfs_scrub_all.service     -> Interactive authentication required
/sbin/e2scrub_all                         -> e2scrub_all must be run as root
/sbin/e2scrub /tmp                        -> e2scrub must be run as root
/usr/sbin/xfs_scrub /tmp                  -> /tmp: Not a XFS mount point
mount tmpfs/bind/loop under /tmp          -> denied / loop setup failed
systemctl reboot                          -> Interactive authentication required
```

A controlled `fsck.xfs` branch harness with attacker-owned fake helpers confirmed direct execution stays uid1001. The fake `xfs_repair`, `mount`, and `umount` calls all logged `uid=1001(attacker)`, even with `/tmp/repair_mnt` precreated as an attacker symlink.

Root-started default services were also run after uid1001 precreated `/tmp/repair_mnt -> /tmp/repair_mnt_target`; the symlink and target remained unchanged. `systemd-fsck-root.service` skipped on `ConditionPathIsReadWrite=!/`, `fstrim.service` skipped on `ConditionVirtualization=!container`, `e2scrub_all.service` exited cleanly, and `xfs_scrub_all.service` found no current XFS target.

## Dead end

No root context was induced to follow, chmod, chown, overwrite, or mount over an attacker-controlled path. The remaining root maintenance helpers consume root-owned configuration, kernel-selected block metadata, or shutdown-only device state. The SUID `mount`/`umount` helpers do not provide a default user-mount path because fstab has no user entries and loop/bind/tmpfs mounts are denied to uid1001.

No `notes/fsck-mount-tmp.md` was created because no root LPE was proven.

Cleanup verified absent:

```text
/tmp/fsck-mount-tmp-probe
/var/tmp/fsck-mount-tmp-probe
/tmp/repair_mnt_target
/tmp/repair_mnt
/run/lock/fsck-mount-tmp-probe
```
