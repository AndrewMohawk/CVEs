# Negative: PackageKit/fwupd/UDisks D-Bus and Polkit Local Paths

Result: no valid uid1001-to-root LPE found in this bounded surface on the shared stock Ubuntu 24.04 Server Docker target.

## Scope

Target container: `ubuntu24-server-lpe-target`.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`, no sudo/adm/lxd/docker groups, no logind active session.

Owned surface:

```text
PackageKit D-Bus transactions and local .deb parser/install paths
fwupd D-Bus/polkit local operations
UDisks D-Bus/polkit local-user loop, mount, block-device, and local-file paths
```

## Default proof

Default-installed package versions:

```text
packagekit 1.2.8-2ubuntu1.5
packagekit-tools 1.2.8-2ubuntu1.5
libpackagekit-glib2-18:arm64 1.2.8-2ubuntu1.5
fwupd 1.9.34-0ubuntu1~24.04.1
fwupd-signed 1.52+1.4-1
libfwupd2:arm64 1.9.34-0ubuntu1~24.04.1
udisks2 2.10.1-6ubuntu1.3
libudisks2-0:arm64 2.10.1-6ubuntu1.3
polkitd 124-2ubuntu1.24.04.3
dbus 1.14.10-4ubuntu4.1
systemd 255.4-1ubuntu8.15
```

Default activation/reachability:

```text
packagekit.service: static D-Bus service, active on demand, root daemon at /usr/libexec/packagekitd
udisks2.service: enabled and active, root daemon at /usr/libexec/udisks2/udisksd
fwupd.service: static D-Bus service but skipped in this Docker target by ConditionVirtualization=!container
fwupd-refresh.timer: enabled but skipped in this Docker target by ConditionVirtualization=!container
```

Important config/code anchors:

```text
/usr/lib/systemd/system/packagekit.service:10-13 Type=dbus, BusName=org.freedesktop.PackageKit, User=root, ExecStart=/usr/libexec/packagekitd
/usr/lib/systemd/system/udisks2.service:5-8 Type=dbus, BusName=org.freedesktop.UDisks2, ExecStart=/usr/libexec/udisks2/udisksd
/usr/lib/systemd/system/fwupd.service:6 ConditionVirtualization=!container
/usr/lib/systemd/system/fwupd.service:13-14 BusName=org.freedesktop.fwupd, ExecStart=/usr/libexec/fwupd/fwupd
/usr/lib/systemd/system/fwupd-refresh.timer:3 ConditionVirtualization=!container
```

## Findings by component

### PackageKit

`org.freedesktop.PackageKit` is default-reachable and runs as root. A uid1001 caller can create transaction objects, and those transaction objects expose `GetDetailsLocal(as)`, `GetFilesLocal(as)`, and `InstallFiles(t,as)`.

Read-only local parser methods reached root PackageKit code on an attacker-owned `.deb`, but did not produce a privilege boundary crossing:

```sh
runuser -u attacker -- pkcon get-files-local /tmp/pkgfwudisks_pk.deb
runuser -u attacker -- pkcon get-details-local /tmp/pkgfwudisks_pk.deb
```

A deliberate `.deb` with a `postinst` that writes `id` to `/root/pkgfwudisks_pkgkit_root` did not run. The confirmed install path was blocked by polkit:

The replay probe also showed `pkcon` can print GLib/PackageKit critical assertions and exit with `Segmentation fault` after the read-only local parser result. This remains out of scope for the LPE goal because it is a client-side crash/DoS symptom with no root write, no root crash proof, and no privilege increase.

```text
Status: Waiting for authentication
Fatal error: Failed to obtain authentication.
PackageKit journal: uid 1001 is trying to obtain org.freedesktop.packagekit.package-install-untrusted auth (only_trusted:0); uid 1001 failed to obtain auth
```

Proof that no root execution occurred:

```text
ls: cannot access '/root/pkgfwudisks_pkgkit_root': No such file or directory
dpkg-query: no packages found matching pkgfwudisks-pk
```

Relevant policy:

```text
/usr/share/polkit-1/actions/org.freedesktop.packagekit.policy:231 package-install-untrusted
/usr/share/polkit-1/actions/org.freedesktop.packagekit.policy:330-334 allow_any=auth_admin, allow_inactive=auth_admin, allow_active=auth_admin
```

The apparent `install-files transaction ... success` journal line is not sufficient by itself: with `pkcon` it can correspond to the simulation/query phase. The noninteractive confirmed path still requests `package-install-untrusted` and fails.

### UDisks

`org.freedesktop.UDisks2` is default-enabled and active as root. The interesting methods are present:

```text
Manager.LoopSetup(h,a{sv})
Block.OpenDevice(s,a{sv})
Block.Rescan(a{sv})
Filesystem.Mount(a{sv})
```

However, the provided attacker shell has no logind session:

```text
Failed to get user: User ID 1001 is not logged in or lingering
Call failed: PID <pid> does not belong to any known session
```

Therefore `allow_active=yes` actions are not reachable as active local-user operations from this shell. The live transaction object also showed `CallerActive=false` in the analogous PackageKit case.

Attacker loop setup of an ext4 image:

```text
Error creating textual authentication agent: Error opening current controlling terminal for the process (`/dev/tty'): No such device or address
Error setting up loop device for /tmp/pkgfwudisks_loop.img: GDBus.Error:org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain: Not authorized to perform operation
```

Direct D-Bus attempts:

```text
Block.OpenDevice(vdb, "r"): Call failed: Not authorized to perform operation
Block.Rescan(vdb): Call failed: Not authorized to perform operation
Filesystem.Mount(vdb): Call failed: Not authorized to perform operation
```

Relevant policy:

```text
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy:9 filesystem-mount
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy:90-94 allow_any=auth_admin, allow_inactive=auth_admin, allow_active=yes
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy:1143 loop-setup
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy:1217-1222 allow_any=auth_admin, allow_inactive=auth_admin, allow_active=yes
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy:2371 open-device
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy:2451-2455 allow_any=auth_admin, allow_inactive=auth_admin, allow_active=auth_admin_keep
```

No attacker-controlled filesystem was loop-mounted, so there was no path to test setuid-in-image behavior or mount option bypass as a valid LPE from this shell.

### fwupd

`fwupd` is installed by default in the target image, and `org.freedesktop.fwupd` is listed as activatable on the system bus. In the shared Docker target, it is not actually reachable:

```text
fwupd.service - Firmware update daemon was skipped because of an unmet condition check (ConditionVirtualization=!container).
fwupd-refresh.timer - Refresh fwupd metadata regularly was skipped because of an unmet condition check (ConditionVirtualization=!container).
```

The unit contains:

```text
/usr/lib/systemd/system/fwupd.service:6 ConditionVirtualization=!container
/usr/lib/systemd/system/fwupd-refresh.timer:3 ConditionVirtualization=!container
```

Since this bounded audit is against the provided Docker target, fwupd local firmware parser/update paths were not default-reachable from uid1001 here.

## Cleanup

Removed all probe artifacts:

```sh
pkill -TERM -u attacker pkcon || true
pkill -KILL -u attacker pkcon || true
rm -rf /tmp/pkgfwudisks_* /root/pkgfwudisks_* /tmp/pkmeta /tmp/pkmeta.deb /tmp/pkmeta.build /tmp/pkgfwudisks_shadow.deb
```

Verified:

```text
dpkg-query: no packages found matching pkgfwudisks-pk
dpkg-query: no packages found matching pkmeta
no pkgfwudisks loop devices
no /tmp/pkgfwudisks_* files
no /root/pkgfwudisks_* files
```

## Why scanners may miss the interesting parts

This surface is mostly semantic rather than syntactic: the risky-looking operations are root D-Bus daemons consuming attacker file descriptors and package files, but exploitability depends on PackageKit's multi-phase transaction semantics, polkit subject activity, and whether the caller has a logind active session. A scanner can flag `allow_active=yes`, local `.deb` parsing, and root daemons, but it will likely miss that the provided non-sudo shell is `CallerActive=false` and that PackageKit's logged `install-files success` can be only a simulation phase.

## Suggested triage fixes

No Ubuntu Security issue is validated from this target state. Hardening ideas:

```text
PackageKit: make client/journal output distinguish simulation success from committed install success more clearly.
PackageKit: keep untrusted local package install behind auth_admin for all subject states.
UDisks: keep loop-setup, open-device, and mount tied to logind active sessions; do not treat arbitrary shells as active users.
fwupd: keep ConditionVirtualization=!container in containerized default targets.
```
