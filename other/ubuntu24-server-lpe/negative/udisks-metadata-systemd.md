# Negative: UDisks active-session filesystem metadata into udev/systemd/tmpfiles

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`  
Probe: `pocs/udisks_metadata_systemd_probe.sh`  
Log: `logs/udisks-metadata-systemd.out`  
Result: no active non-sudo user to root LPE found.

## Scope

This lane tested stock Ubuntu 24.04 Server UDisks active-session handling for attacker-owned ext4, vfat, and xfs loop images with hostile filesystem labels, fixed UUIDs, backing filenames containing `SYSTEMD_WANTS=udisks-meta-pwn.service`, mounted filesystem content containing systemd/tmpfiles payload paths, and root-owned setuid metadata inside an ext4 image.

## Default-install and reachability proof

The target is Ubuntu 24.04.4 LTS. Relevant package versions from the live container:

```text
udisks2 2.10.1-6ubuntu1.3
libudisks2-0:arm64 2.10.1-6ubuntu1.3
libblockdev-fs3:arm64 3.1.1-1ubuntu0.1
libblockdev-loop3:arm64 3.1.1-1ubuntu0.1
systemd 255.4-1ubuntu8.15
udev 255.4-1ubuntu8.15
polkitd 124-2ubuntu1.24.04.3
e2fsprogs 1.47.0-2.4~exp1ubuntu4.1
dosfstools 4.2-1.1build1
xfsprogs 6.6.0-1ubuntu2.1
```

`udisks2.service` is default-enabled and active:

```text
Type=dbus
BusName=org.freedesktop.UDisks2
ExecStart=/usr/libexec/udisks2/udisksd
```

The active local non-admin session was real:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
TTY=tty1
Seat=seat0
Active=yes
State=active
```

## Vulnerable-looking code/config paths checked

Filesystem labels/UUIDs flow into root udev symlinks in `/usr/lib/udev/rules.d/60-persistent-storage.rules`:

```text
140 ENV{ID_FS_USAGE}=="filesystem|other|crypto", ENV{ID_FS_UUID_ENC}=="?*", SYMLINK+="disk/by-uuid/$env{ID_FS_UUID_ENC}"
141 ENV{ID_FS_USAGE}=="filesystem|other|crypto", ENV{ID_FS_LABEL_ENC}=="?*", SYMLINK+="disk/by-label/$env{ID_FS_LABEL_ENC}"
157 ENV{ID_LOOP_BACKING_DEVICE}!="", ENV{ID_LOOP_BACKING_INODE}!="", SYMLINK+="disk/by-loop-inode/$env{ID_LOOP_BACKING_DEVICE}-$env{ID_LOOP_BACKING_INODE}$env{.PART_SUFFIX}"
163 ENV{ID_LOOP_BACKING_FILENAME_ENC}!="", SYMLINK+="disk/by-loop-ref/$env{ID_LOOP_BACKING_FILENAME_ENC}$env{.PART_SUFFIX}"
```

UDisks-specific udev imports are in `/usr/lib/udev/rules.d/80-udisks2.rules:20`. systemd udev activation consumes fixed properties in `/usr/lib/udev/rules.d/99-systemd.rules:56-84`. Mount option defaults are documented in `/etc/udisks2/mount_options.conf.example:33-79`, including `nosuid`, `nodev`, vfat `uid=$UID,gid=$GID`, and xfs allowlisted options.

The attacker cannot write the root trust roots checked: `/etc/udisks2`, `/etc/udev/rules.d`, `/usr/lib/udev/rules.d`, `/usr/lib/systemd/system`, `/etc/systemd/system`, `/media`, `/run/systemd`, `/usr/local/sbin`, or `/usr/local/bin`.

## Trigger commands

```sh
bash -n pocs/udisks_metadata_systemd_probe.sh
./pocs/udisks_metadata_systemd_probe.sh ubuntu24-server-lpe-target
```

The probe logs into `selfauth` on tty1, creates ext4/vfat/xfs images, attaches them with `udisksctl loop-setup`, mounts them with `udisksctl mount`, and inspects root-side udev/systemd/tmpfiles state before cleanup.

## Evidence

UDisks accepted active-user loop setup for all tested filesystem types. Hostile metadata was imported only as data:

```text
ID_FS_LABEL=meta/../x.mount
ID_FS_LABEL_ENC=meta\x2f..\x2fx.mount
DEVLINKS=/dev/disk/by-label/meta\x2f..\x2fx.mount ...

ID_FS_LABEL=UDMETA_PWN
ID_FS_LABEL_ENC=UDMETA\x20PWN
DEVLINKS=/dev/disk/by-label/UDMETA\x20PWN ...

ID_FS_LABEL=XFS..mount
ID_FS_LABEL_ENC=XFS..mount
UDISKS_AUTO=0
```

No `SYSTEMD_WANTS` property was imported from labels or backing filenames, and this UDisks loop path did not create `/dev/disk/by-loop-ref` for the hostile backing names.

Privilege-sensitive mount options were rejected:

```text
Mount option `suid' is not allowed
Mount option `dev' is not allowed
Mount option `uid=0' is not allowed
```

Default mounts remained constrained:

```text
/media/selfauth/meta_.._x.mount /dev/loop0 ext4 rw,nosuid,nodev,relatime,errors=remount-ro
/media/selfauth/UDMETA\x20PWN /dev/loop1 vfat rw,nosuid,nodev,relatime,uid=1002,gid=1002,...
/media/selfauth/XFS..mount /dev/loop2 xfs rw,nosuid,nodev,relatime,...
```

An ext4 image containing a root-owned setuid shell plus mounted `etc/systemd/system/udisks-meta-pwn.service` and `usr/lib/tmpfiles.d/udisks-meta-pwn.conf` did not cross into root execution:

```text
-rwsr-xr-x root:root /media/selfauth/meta_.._x.mount/suidsh
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
touch: cannot touch '/root/udisks-metadata-systemd-root': Permission denied
touch: cannot touch '/run/udisks-metadata-systemd-root': Permission denied
No files found for udisks-meta-pwn.service.
```

systemd saw transient device/mount units from `/proc/self/mountinfo`, not unit files from the mounted image:

```text
media-selfauth-meta_.._x.mount.mount loaded active mounted /media/selfauth/meta_.._x.mount
media-selfauth-UDMETA\x20PWN.mount loaded active mounted /media/selfauth/UDMETA PWN
```

Root proof stayed absent:

```text
ls: cannot access '/root/udisks-metadata-systemd-root': No such file or directory
ls: cannot access '/run/udisks-metadata-systemd-root': No such file or directory
ls: cannot access '/tmp/udisks-metadata-systemd-root': No such file or directory
```

Cleanup removed mounted media, loop devices, root markers, and temporary state. Final target health:

```text
running
0 failed units
```

## Cleanup

The PoC cleanup unmounts any probe loop devices, detaches probe loops, removes `/home/selfauth/udisks-metadata-systemd`, `/tmp/udisks-metadata-systemd`, `/root/udisks-metadata-systemd-root`, `/run/udisks-metadata-systemd-root`, `/tmp/udisks-metadata-systemd-root`, and resets failed state for `udisks2.service`, `systemd-udevd.service`, and `getty@tty1.service`.

Manual cleanup if interrupted:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'umount /dev/loop0 /dev/loop1 /dev/loop2 2>/dev/null || true; losetup -a | grep -E "udisks-metadata-systemd|SYSTEMD_WANTS=udisks-meta" | cut -d: -f1 | xargs -r -n1 losetup -d; rm -rf /home/selfauth/udisks-metadata-systemd /tmp/udisks-metadata-systemd /root/udisks-metadata-systemd-root /run/udisks-metadata-systemd-root /tmp/udisks-metadata-systemd-root /tmp/udisks-metadata-systemd-nosuid-user; systemctl reset-failed udisks2.service systemd-udevd.service getty@tty1.service'
```

## Why scanners may miss it

This was not a parser crash or static bad-permission issue. The interesting boundary is a multi-step active-session chain: polkit active-user authorization, root UDisks loop setup, root udev metadata import, systemd device/mount unit generation, and root consumers that might later scan mounted filesystem content. A generic scanner would usually flag only the writable image input or the root-owned mounted files, then miss the runtime facts that labels are encoded, mount options are constrained, and systemd/tmpfiles do not consume files from `/media/selfauth`.

## Suggested triage outcome

No Ubuntu Security bug from this lane. The hardening that mattered was: encoded udev variables for label/UUID symlinks, no user-controlled `SYSTEMD_WANTS` import from filesystem metadata, no writable root trust roots, UDisks `nosuid,nodev`, vfat `uid=$UID,gid=$GID` enforcement, and systemd using mountinfo-derived transient units rather than mounted media unit files.
