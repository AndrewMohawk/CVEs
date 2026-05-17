# Negative: active-seat UDisks NTFS/ntfs3 mount options

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server Docker target  
Probe: `pocs/active_udisks_ntfs_options_probe.sh`  
Log: `logs/active-udisks-ntfs-options.out`  
Result: no validated uid1001/selfauth-to-root LPE. `ROOT_PROOF=no`.

## Default proof

Packages:

```text
udisks2                 2.10.1-6ubuntu1.3
libudisks2-0:arm64      2.10.1-6ubuntu1.3
ntfs-3g                 1:2022.10.3-1.2ubuntu3.1
fuse3                   3.14.0-5build1
polkitd                 124-2ubuntu1.24.04.3
systemd/udev            255.4-1ubuntu8.15
```

`udisks2.service` is enabled and active, with root D-Bus service execution:

```text
/usr/lib/systemd/system/udisks2.service:
Type=dbus
BusName=org.freedesktop.UDisks2
ExecStart=/usr/libexec/udisks2/udisksd
```

The default UDisks policy allows an active local user to set up loop devices and mount filesystems:

```text
org.freedesktop.udisks2.loop-setup:       allow_active=yes
org.freedesktop.udisks2.filesystem-mount: allow_active=yes
```

The active test session was a real tty/logind seat:

```text
selfauth uid=1002 gid=1002 groups=1002
Seat=seat0
TTY=tty1
Active=yes
State=active
```

Relevant default mount-option config is documented in `/etc/udisks2/mount_options.conf.example`:

```text
ntfs:ntfs_defaults=uid=$UID,gid=$GID,windows_names
ntfs:ntfs_allow=uid=$UID,gid=$GID,umask,dmask,fmask,locale,norecover,ignore_case,windows_names,compression,nocompression,big_writes
ntfs:ntfs3_defaults=uid=$UID,gid=$GID
ntfs:ntfs3_allow=uid=$UID,gid=$GID,umask,dmask,fmask,iocharset,discard,nodiscard,sparse,nosparse,hidden,nohidden,sys_immutable,nosys_immutable,showmeta,noshowmeta,prealloc,noprealloc,hide_dot_files,nohide_dot_files,windows_names,nocase,case
ntfs_drivers=ntfs3,ntfs
```

## Trigger attempts

The active `selfauth` user created an attacker-owned NTFS image, loop-mounted it through UDisks, and mounted it:

```text
Mapped file .../ntfs-SYSTEMD_WANTS=ntfs-options-pwn.service.img as /dev/loop0.
Mounted /dev/loop0 at /media/selfauth/NTFS_PWN
/media/selfauth/NTFS_PWN /dev/loop0 ntfs3 rw,nosuid,nodev,relatime,uid=1002,gid=1002,iocharset=iso8859-1
```

The hostile backing filename did not become a loop-ref symlink or systemd unit trigger; udev exposed only encoded fixed metadata:

```text
ID_FS_TYPE=ntfs
ID_FS_LABEL=NTFS_PWN
ID_FS_UUID=741D39DA3B001C32
/dev/disk/by-label/NTFS_PWN -> ../../loop0
```

A setuid-looking payload created on the mounted NTFS filesystem stayed owned by `selfauth` and executed as `selfauth` because the mount was `nosuid,nodev`:

```text
-rwsr-xr-x selfauth:selfauth /media/selfauth/NTFS_PWN/ntfs_probe_exec.sh
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
cannot create /root/active-udisks-ntfs-options-root: Permission denied
```

UDisks option filtering blocked privilege-relevant options:

```text
uid=0,gid=0,umask=000       -> Mount option `uid=0' is not allowed
suid,exec                   -> Mount option `suid' is not allowed
dev                         -> Mount option `dev' is not allowed
permissions                 -> Mount option `permissions' is not allowed
locale=en_US.UTF-8,permissions -> Mount option `locale=en_US.UTF-8' is not allowed
allow_other                 -> Mount option `allow_other' is not allowed
```

Direct D-Bus `Filesystem.Mount` calls with the same hostile option strings hit the same server-side checks:

```text
uid=0,gid=0,suid,dev,exec,permissions -> Mount option `uid=0' is not allowed
locale=en_US.UTF-8,permissions        -> Mount option `locale=en_US.UTF-8' is not allowed
umask=000,fmask=000,dmask=000,big_writes -> Mount option `big_writes' is not allowed
```

The root-side filesystem helper methods were reachable but did not create a root primitive:

```text
org.freedesktop.UDisks2.Filesystem.Check  -> (true,)
org.freedesktop.UDisks2.Filesystem.Repair -> (true,)
```

Root proof was absent:

```text
ls: cannot access '/root/active-udisks-ntfs-options-root': No such file or directory
ls: cannot access '/run/active-udisks-ntfs-options-root': No such file or directory
ROOT_PROOF=no
```

## Cleanup

The probe unmounted `/media/selfauth/NTFS_PWN`, detached the loop device, removed `/home/selfauth/active-udisks-ntfs-options`, `/tmp/active-udisks-ntfs-options`, and probe marker files, terminated the test session, restarted `getty@tty1.service`, reset failed units, and verified final system health:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend | wc -l -> 0
```

## Why scanners may miss it

This path has a real default trust boundary: an active non-admin user can make root UDisks attach an attacker-controlled NTFS image, root udev parses its metadata, UDisks mounts it under `/media`, and root-side Check/Repair methods are callable. The exploitable condition depends on UDisks' server-side option filtering and selected filesystem driver. In the tested default state, UDisks chose `ntfs3`, forced `uid=$UID,gid=$GID,nosuid,nodev`, rejected option injection over both `udisksctl` and direct D-Bus, and did not import metadata into systemd execution.
