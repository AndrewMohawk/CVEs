# Negative: PackageKit local-file semantics

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 Server default Docker/systemd target.

Result: no local privilege escalation or root shell was achieved. A normal active uid1001 `attacker` session can make root-owned `packagekitd` parse a caller-supplied root-only `.deb` path, including through an attacker-owned symlink, and receive package metadata plus file lists. That is a metadata disclosure for valid Debian archives, but the probe did not turn it into root code execution, arbitrary file read, cache write, offline update state write, or unauthenticated install.

Artifacts:

```text
pocs/packagekit_local_file_semantics_probe.sh
logs/packagekit-local-file-semantics-20260517.out
negative/packagekit-local-file-semantics-20260517.md
```

## Default reachability

The completed run starts at:

```text
===== PackageKit local-file semantics probe run 2026-05-17T15:46:09-0400 =====
```

Default package/service surface:

```text
Ubuntu 24.04.4 LTS
packagekit                    1.2.8-2ubuntu1.5
packagekit-tools              1.2.8-2ubuntu1.5
libpackagekit-glib2-18:arm64  1.2.8-2ubuntu1.5
apt                           2.8.3
dbus                          1.14.10-4ubuntu4.1
polkitd                       124-2ubuntu1.24.04.3
systemd                       255.4-1ubuntu8.15
dpkg                          1.22.6ubuntu6.6
```

`packagekit.service` is D-Bus activated, runs as root, and owns `org.freedesktop.PackageKit`. `/run/dbus/system_bus_socket` is present and reachable. The tested interface methods are present: `GetDetailsLocal`, `GetFilesLocal`, `InstallFiles`, `Trigger`, and `GetPrepared`.

Relevant default polkit state:

```text
system-sources-refresh     active=yes
trigger-offline-update     active=yes
clear-offline-update       active=yes
package-install-untrusted  active=auth_admin
system-update              active=auth_admin_keep
```

## Active uid1001 proof

The active probe no longer uses `.bash_profile`. It launches a single command under `openvt -c 9 ... runuser -l attacker -c /tmp/packagekit-local-file-semantics/active-runner.sh`.

The caller was a real active local logind subject:

```text
uid=1001 gid=1001 groups=[1001] tty=/dev/tty9
XDG_SESSION_ID=c24
Seat=seat0
TTY=tty9
Remote=no
Type=tty
Class=user
Active=yes
State=active
```

PackageKit agreed the active-only actions were reachable, while admin-gated actions stayed gated:

```text
CAN_AUTHORIZE org.freedesktop.packagekit.system-sources-refresh -> 1
CAN_AUTHORIZE org.freedesktop.packagekit.trigger-offline-update -> 1
CAN_AUTHORIZE org.freedesktop.packagekit.clear-offline-update -> 1
CAN_AUTHORIZE org.freedesktop.packagekit.package-install-untrusted -> 3
CAN_AUTHORIZE org.freedesktop.packagekit.system-update -> 3
```

Uid1001 could not directly read or stat the root-only files:

```text
/root/packagekit_lfs_root_only.deb      Permission denied
/root/packagekit_lfs_root_secret.txt   Permission denied
/etc/shadow                            Permission denied for read
link-root-deb -> /root/...deb          Permission denied
link-root-secret -> /root/...txt       Permission denied
link-shadow -> /etc/shadow             Permission denied for read
```

## Transaction results

`GetDetailsLocal` and `GetFilesLocal` succeeded for the root-only `.deb` direct path:

```text
TX_SIGNAL details-root-deb-direct Details ({'package-id': 'pk-lfs-rootonly;1.0;all;local', ... 'summary': 'PKLFS_ROOT_ONLY_CONTROL_SENTINEL root-only local package', ... 'size': 806},)
TX_SIGNAL files-root-deb-direct Files ('pk-lfs-rootonly;1.0;all;/root/packagekit_lfs_root_only.deb', ['/', '/usr', '/usr/share', '/usr/share/pk-lfs-rootonly', '/usr/share/pk-lfs-rootonly/payload.txt'])
```

`GetFilesLocal` also followed the attacker-owned symlink to the root-only `.deb` and returned the package file list:

```text
link-root-deb -> /root/packagekit_lfs_root_only.deb
TX_SIGNAL files-root-deb-symlink Files ('pk-lfs-rootonly;1.0;all;/tmp/packagekit-local-file-semantics/link-root-deb', ['/', '/usr', '/usr/share', '/usr/share/pk-lfs-rootonly', '/usr/share/pk-lfs-rootonly/payload.txt'])
```

Non-Debian root-only files and `/etc/shadow` did not leak content. Direct and symlink forms returned only `NoSuchFile: ... not found or unsupported` for:

```text
/root/packagekit_lfs_root_secret.txt
/tmp/packagekit-local-file-semantics/link-root-secret
/etc/shadow
/tmp/packagekit-local-file-semantics/link-shadow
/tmp/packagekit-local-file-semantics/not-a-deb.txt
```

`InstallFiles(ONLY_DOWNLOAD)` behavior:

```text
attacker-owned .deb direct: success, Package signals, no install
attacker-owned .deb symlink: ErrorCode (8, 'Could not find package(s)')
attacker /proc/self/fd path: ErrorCode (8, 'Could not find package(s)')
root-only .deb direct: success, Package signals, no install
root-only .deb symlink: ErrorCode (8, 'Could not find package(s)')
root-only text/shadow/not-deb: NoSuchFile/not found or unsupported
```

After every `ONLY_DOWNLOAD` case, `/var/cache/PackageKit/downloads` remained empty and no offline/prepared update file appeared:

```text
CACHE_ENTRIES []
OFFLINE_FILE /system-update missing
OFFLINE_FILE /var/lib/PackageKit/offline-update-action missing
OFFLINE_FILE /var/lib/PackageKit/offline-update-competed missing
OFFLINE_FILE /var/lib/PackageKit/prepared-update missing
OFFLINE_FILE /var/lib/PackageKit/prepared-upgrade missing
OFFLINE_GET_PREPARED ([],)
```

Real `InstallFiles(flags=0)` for direct and symlink root-only `.deb` reached the method but failed at polkit:

```text
TX_SIGNAL installfiles-real-root-deb-direct-real ErrorCode (48, 'Failed to obtain authentication.')
TX_SIGNAL installfiles-real-root-deb-symlink-real ErrorCode (48, 'Failed to obtain authentication.')
```

No maintainer scripts ran:

```text
ROOT_MARKER_ABSENT /root/packagekit_lfs_root_marker
ROOT_MARKER_ABSENT /root/packagekit_lfs_root_marker.attacker_postinst
ROOT_MARKER_ABSENT /root/packagekit_lfs_root_marker.rootonly_postinst
dpkg-query: no packages found matching pk-lfs-attacker
dpkg-query: no packages found matching pk-lfs-rootonly
```

Offline trigger tests without prepared update did not create state:

```text
OFFLINE_TRIGGER_ERROR action='reboot' Prepared update not found: /var/lib/PackageKit/prepared-update
OFFLINE_TRIGGER_ERROR action='reboot\n/root/packagekit_lfs_root_only.deb' action ... unsupported
OFFLINE_TRIGGER_ERROR action='/tmp/packagekit-local-file-semantics/pk-lfs-attacker.deb' action ... unsupported
```

## Cleanup proof

The run completed with `ACTIVE_DRIVER_DONE` and `ACTIVE_DRIVER_COMPLETED=1`. `openvt_rc=8` was the known console deallocation return after the active runner finished, not a transaction failure.

Final cleanup removed all probe state:

```text
CLEANUP_ABSENT /tmp/packagekit-local-file-semantics
CLEANUP_ABSENT /root/packagekit_lfs_root_secret.txt
CLEANUP_ABSENT /root/packagekit_lfs_root_only.deb
CLEANUP_ABSENT /root/packagekit_lfs_root_marker
CLEANUP_ABSENT /root/packagekit_lfs_root_marker.attacker_postinst
CLEANUP_ABSENT /root/packagekit_lfs_root_marker.rootonly_postinst
CLEANUP_ABSENT /system-update
CLEANUP_ABSENT /var/lib/PackageKit/offline-update-action
CLEANUP_ABSENT /var/lib/PackageKit/offline-update-competed
CLEANUP_ABSENT /var/lib/PackageKit/prepared-update
CLEANUP_ABSENT /var/lib/PackageKit/prepared-upgrade
dpkg-query: no packages found matching pk-lfs-attacker
dpkg-query: no packages found matching pk-lfs-rootonly
```

Post-run verification found no matching probe processes, no logind sessions, all probe paths absent, `packagekit.service`, `polkit.service`, `dbus.service`, and `getty@tty9.service` active, and `systemctl is-system-running -> running`.
