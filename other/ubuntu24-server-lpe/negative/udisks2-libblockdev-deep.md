# Negative: UDisks2/libblockdev active-user storage paths

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`  
Result: no uid1001/active-local-user to root LPE found in this lane.

## Scope

This pass covered the stock Ubuntu 24.04 Server default UDisks2/libblockdev surface using only user-created loop/image inputs:

- `org.freedesktop.UDisks2` loop setup/delete
- filesystem mount/unmount, option filtering, check, repair, resize, and format helpers
- swapspace start/stop boundaries
- LUKS unlock, lock, and passphrase helper paths
- partition table creation helpers
- block rescan/open FD-returning methods
- filesystem type probing and hostile labels/backing paths
- root-owned `/media`, `/run`, `/etc`, and `/var` effects

Prior bcache/udev metadata work is not duplicated here except where loop setup behavior overlaps.

## Default posture

Package/version proof from the target:

```text
udisks2 2.10.1-6ubuntu1.3
libudisks2-0:arm64 2.10.1-6ubuntu1.3
libblockdev3:arm64 3.1.1-1ubuntu0.1
libblockdev-fs3:arm64 3.1.1-1ubuntu0.1
libblockdev-loop3:arm64 3.1.1-1ubuntu0.1
libblockdev-part3:arm64 3.1.1-1ubuntu0.1
libblockdev-swap3:arm64 3.1.1-1ubuntu0.1
libblockdev-crypto3:arm64 3.1.1-1ubuntu0.1
polkitd 124-2ubuntu1.24.04.3
systemd 255.4-1ubuntu8.15
util-linux 2.39.3-9ubuntu6.5
e2fsprogs 1.47.0-2.4~exp1ubuntu4.1
cryptsetup-bin 2:2.7.0-1ubuntu4.2
parted 3.6-4build1
```

UDisks is default-enabled and D-Bus activatable as root:

```text
udisks2.service: Type=dbus, BusName=org.freedesktop.UDisks2
ExecStart=/usr/libexec/udisks2/udisksd
/usr/share/dbus-1/system-services/org.freedesktop.UDisks2.service: User=root, SystemdService=udisks2.service
```

Relevant polkit defaults:

```text
filesystem-mount active=yes
encrypted-unlock active=yes
encrypted-change-passphrase active=yes
loop-setup active=yes
modify-device active=yes
rescan active=yes
manage-swapspace active=auth_admin_keep
open-device active=auth_admin_keep
filesystem-fstab active=auth_admin_keep
modify-system-configuration active=auth_admin
```

There is no UDisks-specific Ubuntu rule granting extra rights. The installed rules only add sudo/admin groups as admins and unrelated packagekit/bolt/fwupd/networkd exceptions.

## Active-console model

`uid1001(attacker)` is not in an active logind session, so the plain attacker shell cannot use `allow_active=yes`:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
udisksctl loop-setup -f /tmp/udisksdeep_uid1001.img --no-user-interaction
Error setting up loop device ... NotAuthorizedCanObtain: Not authorized to perform operation
```

For active-console reachability I used the provided `selfauth` non-admin account via a real tty1 login. Polkit treated this as the local active subject:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
XDG_SESSION_ID=132
State: active
Seat: seat0; vc1
TTY: tty1
Remote: no
Service: login
Type: tty
Class: user
```

Thus the positive reachability below is valid for a normal active local non-sudo user. It is not reachable from the non-active uid1001 shell unless uid1001 has an active local session.

## Filesystem loop, helpers, and mount filtering

An active non-admin can create and delete a loop backed by their own image:

```sh
udisksctl loop-setup -f /home/selfauth/udisksdeep-ext4-clean/ext4-grow.img
udisksctl loop-delete -b /dev/loop0
```

I created an ext4 image with raw filesystem metadata containing a root-owned setuid shell:

```text
Inode: 12   Type: regular    Mode:  04755
User:     0   Group:     0   Size: 133608
```

Unprivileged active calls to root filesystem helpers succeeded on the user loop:

```text
Check {} -> (true,)
Repair @a{sv} {} -> (true,)
Resize 64M -> ()
```

The root helper trace showed helper execution through root-owned search paths:

```text
execve("/usr/local/sbin/e2fsck", ["e2fsck", "-f", "-n", "-C", "1", "/dev/loop0"], ...) = -1 ENOENT
execve("/usr/local/bin/e2fsck", ...) = -1 ENOENT
execve("/usr/sbin/e2fsck", ["e2fsck", "-f", "-n", "-C", "1", "/dev/loop0"], ...) = 0
execve("/usr/sbin/e2fsck", ["e2fsck", "-f", "-y", "-C", "1", "/dev/loop0"], ...) = 0
execve("/usr/sbin/resize2fs", ["resize2fs", "/dev/loop0", "131072s"], ...) = 0
```

Those path prefixes are not writable by `attacker`:

```text
drwxr-xr-x root:root /usr/local/sbin
drwxr-xr-x root:root /usr/local/bin
drwxr-xr-x root:root /usr/sbin
not-writable:/usr/local/sbin
not-writable:/usr/local/bin
not-writable:/usr/sbin
```

Mount option filtering blocked the privilege-relevant inverses:

```text
udisksctl mount -b /dev/loop0 -o suid
Error ... OptionNotPermitted: Mount option `suid' is not allowed

udisksctl mount -b /dev/loop0 -o dev
Error ... OptionNotPermitted: Mount option `dev' is not allowed
```

Mounting with an allowed `exec` option still produced `nosuid,nodev`:

```text
/dev/loop0 /media/selfauth/UD2SUID ext4 rw,nosuid,nodev,relatime,errors=remount-ro
root:root 755 /media
root:root 750 /media/selfauth
root:root 755 /media/selfauth/UD2SUID
-rwsr-xr-x 1 root root 133608 /media/selfauth/UD2SUID/suiddash
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
touch: cannot touch '/root/udisksdeep_suid': Permission denied
```

`x-mount.mkdir=/etc/udisksdeep` did not create an `/etc` mountpoint. In one early sequence it mounted the image under `/media/selfauth/UD2_.._ETC=1` and `udisksd` then SIGSEGVed/restarted. I did not get root write or execution from that crash; systemd restarted the daemon and UDisks cleaned up the loop. This is a possible DoS note, not an LPE.

## Format, probing, and labels

`Block.Format("ext4", {"label": "FMT/../ETC=1"})` is reachable on a user loop and runs `mke2fs` as root:

```text
Block.Format ext4 -> ()
execve("/usr/sbin/mke2fs", ["mke2fs", "-t", "ext4", "/dev/loop0", "-L", "FMT/../ETC=1"], ...) = 0
```

The resulting UDisks/udev properties encoded hostile label path separators for symlinks:

```text
IdLabel: FMT/../ETC=1
IdType: ext4
Symlinks:
  /dev/disk/by-label/FMT\x2f..\x2fETC=1
  /dev/disk/by-loop-inode/0:64-19050548
```

No `/etc`, `/var`, or `/root` file was created from label probing or formatting.

## Swap

A user-created swap image probes as swap and exposes `org.freedesktop.UDisks2.Swapspace`:

```text
IdLabel: SWP/../ETC=1
IdType: swap
Symlinks:
  /dev/disk/by-label/SWP\x2f..\x2fETC=1
Swapspace.Start method a{sv}
```

Activation is not available to the active non-admin because `manage-swapspace` remains `auth_admin_keep`:

```text
Swapspace.Start -> Error: GDBus.Error:org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain: Not authorized to perform operation
swapon --show ... no udisksdeep entry
```

## Encrypted helpers

A user-created LUKS2 image reached root UDisks crypto helper paths:

```text
IdType: crypto_LUKS
IdUsage: crypto
Encrypted.ChangePassphrase method ssa{sv}
Encrypted.Unlock method sa{sv}
```

The active user could change the passphrase, unlock, and lock their own loop:

```text
ChangePassphrase secret->secret2 -> ()
Unlock with keyfile -> Unlocked /dev/loop0 as /dev/dm-0.
/dev/mapper/luks-f3c03def-dc96-4118-8c5b-f70ecaf3f080 -> ../dm-0
Lock encrypted device -> Locked /dev/loop0.
```

This created only the expected transient `/dev/dm-0` mapper device. Cleanup removed it, and `dmsetup ls` later returned `No devices found`.

Crypttab persistence was denied:

```text
Block.AddConfigurationItem ('crypttab', ...)
Error: GDBus.Error:org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain: Not authorized to perform operation
grep udisksdeep /etc/crypttab: no output
```

## Partition helpers

Partition table formatting is reachable for a user loop:

```text
Block.Format gpt -> ()
PartitionTable.Type: "gpt"
CreatePartition method ttssa{sv}
CreatePartitionAndFormat method ttssa{sv}sa{sv}
```

Creating a partition with a hostile label did not produce a usable root path:

```text
CreatePartition hostile label ->
Error ... Error wiping newly created partition /dev/loop0p1: Failed to open the device '/dev/loop0p1': No such file or directory

/org/freedesktop/UDisks2/block_devices/loop0
/org/freedesktop/UDisks2/block_devices/loop0p1
ls: cannot access '/dev/disk/by-partlabel': No such file or directory
```

This Docker target exposes a transient UDisks object but no usable `/dev/loop0p1` node or `/dev/disk/by-partlabel` symlink for the active user to weaponize.

## Raw block access and system configuration

`Rescan` is reachable on a user loop:

```text
Block.Rescan own loop -> ()
```

FD-returning raw access methods stayed behind stronger authorization, even on the user's own loop:

```text
Block.OpenDevice rw own loop -> NotAuthorizedCanObtain
Block.OpenForBackup own loop -> NotAuthorizedCanObtain
Block.OpenForRestore own loop -> NotAuthorizedCanObtain
```

Fstab persistence was also denied:

```text
Block.AddConfigurationItem ('fstab', ...)
Error: GDBus.Error:org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain: Not authorized to perform operation
grep udisksdeep /etc/fstab: no output
ls: cannot access '/etc/udisksdeep-mnt': No such file or directory
```

## Root-owned state effects

UDisks creates root-owned state, but I did not find an injection-to-root-write primitive:

```text
/media/selfauth            root:root 0750
/media/selfauth/<label>    root:root 0755 while mounted
/run/udisks2               root:root 0700
/run/udisks2/loop          root:root 0644
/var/lib/udisks2           root:root 0700
/var/lib/udisks2/mounted-fs-persistent root:root 0644
```

After cleanup both UDisks state files were empty:

```text
-rw-r--r-- root:root 0 /run/udisks2/loop
-rw-r--r-- root:root 0 /var/lib/udisks2/mounted-fs-persistent
```

I also tested a loop backing filename containing embedded newlines and keyfile-looking text:

```text
/home/selfauth/udisksdeep-runstate2/loop-state
[evil]
uid=0
backing-file=etc-passwd.img
```

UDisks preserved that string as the `BackingFile` property and in logs, while `SetupByUID` remained `1002`. Restarting `udisksd` parsed the state and stayed active. It did not create a new state key, did not change loop ownership, and did not write `/etc`/`/var`/`/root`.

## Cleanup proof

Cleanup performed:

```sh
rm -rf /home/selfauth/udisksdeep-* /home/selfauth/udisksdeep_*.sh /tmp/udisksdeep*
rm -f /root/udisksdeep_* /run/udisksdeep_user_touch
rm -rf /etc/udisksdeep-mnt /etc/udisksdeep /var/udisksdeep
loginctl terminate-user selfauth
systemctl restart udisks2.service
```

Final state:

```text
losetup -a | grep udisksdeep: no output
dmsetup ls: No devices found
findmnt -R /media/selfauth: no mounts
/root/udisksdeep_*: absent
/etc/udisksdeep*: absent
/var/udisksdeep*: absent
/run/udisksdeep_user_touch: absent
/run/udisks2/loop size 0
/var/lib/udisks2/mounted-fs-persistent size 0
udisks2.service active
getty@tty1.service active
```

## Conclusion

The active-console UDisks path is real: a normal local non-sudo user at an active seat can drive root UDisks/libblockdev code over attacker-controlled loop images. The tested paths did not cross into root code execution or an attacker-controlled root file write. `nosuid,nodev` blocks mounted-image setuid/device escalation, dangerous mount options and raw block FD methods are denied, swap and `/etc` persistence require admin auth, hostile labels are encoded in symlink paths, partition helpers did not expose a usable partition node in this Docker target, and root helper execution resolved through root-owned directories.
