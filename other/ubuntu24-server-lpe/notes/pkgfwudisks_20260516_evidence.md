# PackageKit/fwupd/UDisks Evidence - 2026-05-16

Target: `ubuntu24-server-lpe-target` (`Ubuntu 24.04.4 LTS`, `attacker` is `uid=1001 gid=1001`, no sudo/adm/lxd/docker groups).

## Versions and default activation

`dpkg-query -W` on the target:

```text
dbus 1.14.10-4ubuntu4.1
fwupd 1.9.34-0ubuntu1~24.04.1
fwupd-signed 1.52+1.4-1
libfwupd2:arm64 1.9.34-0ubuntu1~24.04.1
libpackagekit-glib2-18:arm64 1.2.8-2ubuntu1.5
libudisks2-0:arm64 2.10.1-6ubuntu1.3
packagekit 1.2.8-2ubuntu1.5
packagekit-tools 1.2.8-2ubuntu1.5
polkitd 124-2ubuntu1.24.04.3
systemd 255.4-1ubuntu8.15
udisks2 2.10.1-6ubuntu1.3
```

Default unit state:

```text
packagekit.service static, active on D-Bus activation, runs /usr/libexec/packagekitd as root
udisks2.service enabled and active, runs /usr/libexec/udisks2/udisksd as root
fwupd.service static but inactive in this Docker target because ConditionVirtualization=!container is unmet
fwupd-refresh.timer enabled but inactive in this Docker target because ConditionVirtualization=!container is unmet
```

Config/source line anchors:

```text
/usr/lib/systemd/system/packagekit.service:10-13 Type=dbus, BusName=org.freedesktop.PackageKit, User=root, ExecStart=/usr/libexec/packagekitd
/usr/lib/systemd/system/udisks2.service:5-8 Type=dbus, BusName=org.freedesktop.UDisks2, ExecStart=/usr/libexec/udisks2/udisksd
/usr/lib/systemd/system/fwupd.service:6 ConditionVirtualization=!container
/usr/lib/systemd/system/fwupd.service:13-14 BusName=org.freedesktop.fwupd, ExecStart=/usr/libexec/fwupd/fwupd
/usr/lib/systemd/system/fwupd-refresh.timer:3 ConditionVirtualization=!container
```

## Polkit/action evidence

The attacker shell is not in a logind session:

```text
Failed to get user: User ID 1001 is not logged in or lingering
Call failed: PID <pid> does not belong to any known session
```

PackageKit transaction objects created by uid1001 report `CallerActive=false` and `Uid=1001`.

Relevant policy defaults:

```text
/usr/share/polkit-1/actions/org.freedesktop.packagekit.policy:231 package-install-untrusted
/usr/share/polkit-1/actions/org.freedesktop.packagekit.policy:330-334 allow_any=auth_admin, allow_inactive=auth_admin, allow_active=auth_admin
/usr/share/polkit-1/actions/org.freedesktop.packagekit.policy:1009 system-sources-refresh
/usr/share/polkit-1/actions/org.freedesktop.packagekit.policy:1085-1089 allow_any=auth_admin, allow_inactive=yes, allow_active=yes
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy:9 filesystem-mount
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy:90-94 allow_any=auth_admin, allow_inactive=auth_admin, allow_active=yes
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy:1143 loop-setup
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy:1217-1222 allow_any=auth_admin, allow_inactive=auth_admin, allow_active=yes
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy:2371 open-device
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy:2451-2455 allow_any=auth_admin, allow_inactive=auth_admin, allow_active=auth_admin_keep
```

`pkcheck` from the attacker shell returned:

```text
org.freedesktop.udisks2.loop-setup: Authorization requires authentication and -u wasn't passed.
org.freedesktop.udisks2.filesystem-mount: Authorization requires authentication and -u wasn't passed.
org.freedesktop.packagekit.package-install-untrusted: Authorization requires authentication and -u wasn't passed.
org.freedesktop.packagekit.system-sources-refresh: Authorization requires authentication and -u wasn't passed.
org.freedesktop.fwupd.modify-remote: Authorization requires authentication and -u wasn't passed.
```

## Method enumeration

PackageKit manager exposes:

```text
CreateTransaction, CanAuthorize, GetDaemonState, GetPackageHistory, GetTimeSinceAction,
GetTransactionList, SetProxy, SuggestDaemonQuit
```

PackageKit transaction object for uid1001 exposes local-file paths:

```text
GetDetailsLocal(as), GetFilesLocal(as), InstallFiles(t,as)
RefreshCache(b), InstallPackages(t,as), UpdatePackages(t,as), RemovePackages(t,as)
```

UDisks manager exposes:

```text
LoopSetup(h,a{sv}), MDRaidCreate, GetBlockDevices, ResolveDevice, CanCheck/Format/Repair/Resize
```

UDisks block/filesystem objects expose:

```text
Block.OpenDevice(s,a{sv}), OpenForBackup/Benchmark/Restore, Format, Rescan
Filesystem.Mount(a{sv}), Unmount, TakeOwnership, SetLabel, SetUUID, Check/Repair/Resize
```

fwupd was only an activatable bus name in the target; systemd refused activation under Docker due `ConditionVirtualization=!container`.

## Trigger tests

PackageKit local parser:

```sh
runuser -u attacker -- pkcon get-files-local /tmp/pkgfwudisks_pk.deb
runuser -u attacker -- pkcon get-details-local /tmp/pkgfwudisks_pk.deb
```

Both reached PackageKit local-file transaction code on an attacker-owned `.deb` without running maintainer scripts. The client printed GLib/PackageKit critical assertions and, in the replay probe, `pkcon` exited with `Segmentation fault` after the read-only result. This is not counted: there was no root write, no package installation, and no root-context crash proof.

PackageKit local install:

```sh
runuser -u attacker -- timeout 40 pkcon -y install-local --allow-untrusted /tmp/pkgfwudisks_pk.deb
```

The `.deb` contained:

```sh
#!/bin/sh
id > /root/pkgfwudisks_pkgkit_root
echo postinst-ran >> /root/pkgfwudisks_pkgkit_root
```

Result:

```text
Status: Waiting for authentication
Fatal error: Failed to obtain authentication.
ls: cannot access '/root/pkgfwudisks_pkgkit_root': No such file or directory
dpkg-query: no packages found matching pkgfwudisks-pk
PackageKit journal: uid 1001 is trying to obtain org.freedesktop.packagekit.package-install-untrusted auth (only_trusted:0); uid 1001 failed to obtain auth
```

UDisks loop setup on attacker-controlled image:

```sh
runuser -u attacker -- bash -lc 'dd if=/dev/zero of=/tmp/pkgfwudisks_loop.img bs=1M count=8 status=none; mkfs.ext4 -q /tmp/pkgfwudisks_loop.img; udisksctl loop-setup -f /tmp/pkgfwudisks_loop.img'
```

Result:

```text
Error creating textual authentication agent: Error opening current controlling terminal for the process (`/dev/tty'): No such device or address
Error setting up loop device for /tmp/pkgfwudisks_loop.img: GDBus.Error:org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain: Not authorized to perform operation
losetup -a | grep pkgfwudisks: no output
```

UDisks direct block methods from uid1001:

```text
Block.OpenDevice(vdb, "r"): Call failed: Not authorized to perform operation
Block.Rescan(vdb): Call failed: Not authorized to perform operation
Filesystem.Mount(vdb): Call failed: Not authorized to perform operation
Filesystem.Mount(vda1): Device /dev/vda1 is already mounted at `/etc/hostname', `/etc/hosts', `/etc/resolv.conf'.
```

fwupd activation:

```text
fwupd.service - Firmware update daemon was skipped because of an unmet condition check (ConditionVirtualization=!container).
fwupd-refresh.timer - Refresh fwupd metadata regularly was skipped because of an unmet condition check (ConditionVirtualization=!container).
```

## Cleanup

Executed:

```sh
pkill -TERM -u attacker pkcon || true
pkill -KILL -u attacker pkcon || true
rm -rf /tmp/pkgfwudisks_* /root/pkgfwudisks_* /tmp/pkmeta /tmp/pkmeta.deb /tmp/pkmeta.build /tmp/pkgfwudisks_shadow.deb
losetup -a | grep pkgfwudisks || true
dpkg-query -W pkgfwudisks-pk pkmeta || true
```

Cleanup proof:

```text
dpkg-query: no packages found matching pkgfwudisks-pk
dpkg-query: no packages found matching pkmeta
no /tmp/pkgfwudisks_* files
no /root/pkgfwudisks_* files
no pkgfwudisks/pkcon processes
```
