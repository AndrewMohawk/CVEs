# Negative: default D-Bus/polkit APIs

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS, systemd PID 1.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no validated local privilege escalation in the default D-Bus/polkit service APIs tested here.

## Default install and reachability proof

Relevant package versions from `baseline/live-target-standard/packages.txt`:

```text
dbus                         1.14.10-4ubuntu4.1
fwupd                        1.9.34-0ubuntu1~24.04.1
netplan.io                   1.1.2-8ubuntu1~24.04.2
packagekit                   1.2.8-2ubuntu1.5
polkitd                      124-2ubuntu1.24.04.3
python3-netplan              1.1.2-8ubuntu1~24.04.2
software-properties-common   0.99.49.4
systemd                      255.4-1ubuntu8.15
udisks2                      2.10.1-6ubuntu1.3
```

Relevant system bus names from `baseline/live-target-standard/dbus-system.txt`:

```text
com.ubuntu.SoftwareProperties   (activatable)
io.netplan.Netplan              (activatable)
org.freedesktop.PackageKit      (activatable)
org.freedesktop.UDisks2         udisksd root udisks2.service
org.freedesktop.fwupd           (activatable)
org.freedesktop.hostname1       (activatable)
org.freedesktop.locale1         (activatable)
org.freedesktop.login1          systemd-logind root systemd-logind.service
org.freedesktop.network1        (activatable)
org.freedesktop.timedate1       systemd-timedated root systemd-timedated.service
```

Running/default active services from `baseline/live-target-standard/systemctl-active.txt`:

```text
dbus.service              loaded active running D-Bus System Message Bus
polkit.service            loaded active running Authorization Manager
systemd-logind.service    loaded active running User Login Management
systemd-timedated.service loaded active running Time & Date Service
udisks2.service           loaded active running Disk Manager
dbus.socket               loaded active running D-Bus System Message Bus Socket
```

## io.netplan.Netplan

Default service/config:

```text
/usr/share/dbus-1/system-services/io.netplan.Netplan.service
1 [D-BUS Service]
2 Name=io.netplan.Netplan
3 Exec=/usr/libexec/netplan/netplan-dbus
4 User=root

/usr/share/dbus-1/system.d/io.netplan.Netplan.conf
6  <policy user="root">
7    <allow own="io.netplan.Netplan"/>
10 <policy context="default">
11   <allow send_destination="io.netplan.Netplan" send_interface="io.netplan.Netplan"/>
13   <allow send_destination="io.netplan.Netplan" send_interface="io.netplan.Netplan.Config"/>
```

Exposed methods:

```text
io.netplan.Netplan.Apply    () -> b
io.netplan.Netplan.Config   () -> o
io.netplan.Netplan.Generate () -> b
io.netplan.Netplan.Info     () -> a(sv)
```

Attacker trigger results:

```sh
for m in Info Config Generate Apply; do
  busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan "$m"
done
```

Every method returned:

```text
Call failed: Access denied
```

I also checked the per-config-object edge. A root caller can create a config object:

```text
busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Config
o "/io/netplan/Netplan/config/K9BJP3"
```

That object exposes:

```text
io.netplan.Netplan.Config.Get    () -> s
io.netplan.Netplan.Config.Set    ss -> b
io.netplan.Netplan.Config.Apply  () -> b
io.netplan.Netplan.Config.Try    u -> b
io.netplan.Netplan.Config.Cancel () -> b
```

Attacker can introspect root-created config objects, but cannot call methods:

```sh
busctl --system call io.netplan.Netplan /io/netplan/Netplan/config/K9BJP3 io.netplan.Netplan.Config Set ss 10-attacker.yaml 'network:\n  version: 2\n'
busctl --system call io.netplan.Netplan /io/netplan/Netplan/config/K9BJP3 io.netplan.Netplan.Config Get
busctl --system call io.netplan.Netplan /io/netplan/Netplan/config/K9BJP3 io.netplan.Netplan.Config Cancel
```

All returned `Call failed: Access denied`.

Dead-end reason: default-reachable, root-owned, and interesting, but attacker uid 1001 cannot obtain or mutate a netplan config object and cannot run `Generate`/`Apply`. No root write or command execution primitive.

Promising unresolved edge: root-created config objects are visible/introspectable cross-caller. That is not an LPE because all state-changing methods still deny uid 1001, but it is worth revisiting if a caller identity mixup or object-owner check bypass appears.

Cleanup:

```sh
busctl --system call io.netplan.Netplan /io/netplan/Netplan/config/A197O3 io.netplan.Netplan.Config Cancel
busctl --system call io.netplan.Netplan /io/netplan/Netplan/config/K9BJP3 io.netplan.Netplan.Config Cancel
```

Post-cleanup, `busctl --system tree io.netplan.Netplan` only shows `/io/netplan/Netplan`, and `/run/netplan` contains no config staging directories.

## com.ubuntu.SoftwareProperties

Default service/config:

```text
/usr/share/dbus-1/system-services/com.ubuntu.SoftwareProperties.service
2 Name=com.ubuntu.SoftwareProperties
3 Exec=/usr/lib/software-properties/software-properties-dbus
4 User=root

/etc/dbus-1/system.d/com.ubuntu.SoftwareProperties.conf
6  <policy user="root">
7    <allow own="com.ubuntu.SoftwareProperties"/>
10 <policy context="default">
11   <allow send_destination="com.ubuntu.SoftwareProperties" send_interface="com.ubuntu.SoftwareProperties"/>
```

Policy:

```text
/usr/share/polkit-1/actions/com.ubuntu.softwareproperties.policy
11 <action id="com.ubuntu.softwareproperties.applychanges">
15 <allow_any>auth_admin</allow_any>
16 <allow_inactive>auth_admin</allow_inactive>
17 <allow_active>auth_admin_keep</allow_active>
```

Code path:

```text
/usr/lib/python3/dist-packages/softwareproperties/dbus/SoftwarePropertiesDBus.py
101-107 Revert checks com.ubuntu.softwareproperties.applychanges
119-146 Enable/Disable child sources/components check applychanges
151-162 Enable/Disable source code sources check applychanges
173-188 ReplaceSourceEntry/ChangeMainDownloadServer check applychanges
194-197 AddCdromSource checks applychanges before apt-cdrom
273-276 AddSourceFromLine checks applychanges
292-306 AddKey/AddKeyFromData check applychanges
314-328 RemoveKey/UpdateKeys check applychanges
365-369 CheckAuthorization(..., AllowUserInteraction)
378-382 raise com.ubuntu.SoftwareProperties.PermissionDeniedByPolicy when not authorized
```

Attacker trigger results:

```sh
busctl --system call com.ubuntu.SoftwareProperties / com.ubuntu.SoftwareProperties Reload
busctl --system call com.ubuntu.SoftwareProperties / com.ubuntu.SoftwareProperties AddSourceFromLine s 'deb http://127.0.0.1/ubuntu noble main'
busctl --system call com.ubuntu.SoftwareProperties / com.ubuntu.SoftwareProperties AddKey s /tmp/no-such-key
```

`Reload` returned successfully, but it is a read/reload-only method. Both mutating calls failed before writes:

```text
Call failed: com.ubuntu.softwareproperties.applychanges
```

Dead-end reason: default-reachable root DBus service, but all repository/key/config mutators enforce `auth_admin`/`auth_admin_keep`. No unauthenticated source injection, apt key injection, or root command execution.

## org.freedesktop.PackageKit

Default service/config:

```text
/usr/share/dbus-1/system-services/org.freedesktop.PackageKit.service
2 Name=org.freedesktop.PackageKit
3 Exec=/usr/libexec/packagekitd
4 User=root
5 SystemdService=packagekit.service

/usr/lib/systemd/system/packagekit.service
10 Type=dbus
11 BusName=org.freedesktop.PackageKit
12 User=root
13 ExecStart=/usr/libexec/packagekitd
```

Policy highlights:

```text
/usr/share/polkit-1/actions/org.freedesktop.packagekit.policy
125  package-install: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin_keep
231  package-install-untrusted: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin
726  package-remove: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin
1009 system-sources-refresh: allow_any/auth_admin, allow_inactive/yes, allow_active/yes
1091 system-network-proxy-configure: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/yes
1278 repair-system: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin
1371 trigger-offline-update: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/yes
1548 clear-offline-update: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/yes
```

Exposed methods include root package operations:

```text
org.freedesktop.PackageKit.CreateTransaction
org.freedesktop.PackageKit.SetProxy
org.freedesktop.PackageKit.Offline.Trigger
org.freedesktop.PackageKit.Transaction.InstallPackages
org.freedesktop.PackageKit.Transaction.InstallFiles
org.freedesktop.PackageKit.Transaction.RefreshCache
org.freedesktop.PackageKit.Transaction.RepoEnable
org.freedesktop.PackageKit.Transaction.RepoSetData
org.freedesktop.PackageKit.Transaction.RepairSystem
```

Attacker checks:

```sh
pkcon refresh force
pkcon get-updates
busctl --system call org.freedesktop.PackageKit /org/freedesktop/PackageKit org.freedesktop.PackageKit SetProxy ssssss http://127.0.0.1:9 '' '' '' '' ''
busctl --system call org.freedesktop.PackageKit /org/freedesktop/PackageKit org.freedesktop.PackageKit.Offline Trigger s reboot
busctl --system call org.freedesktop.PackageKit /org/freedesktop/PackageKit org.freedesktop.PackageKit.Offline ClearResults
```

Results:

```text
pkcon refresh force:
Status: Waiting for authentication
Fatal error: Failed to obtain authentication.

pkcon get-updates:
Finished successfully, no updates available.

SetProxy/Offline.Trigger/ClearResults:
Call failed: failed to obtain auth
```

Journal confirmation:

```text
PackageKit: uid 1001 is trying to obtain org.freedesktop.packagekit.system-sources-refresh auth
PackageKit: uid 1001 failed to obtain auth
PackageKit: get-updates transaction from uid 1001 finished with success
```

I also exercised transaction methods from a single DBus connection, because PackageKit binds transactions to the sender bus name. `RefreshCache(True)` returned asynchronously but remained in auth/finished failure state, while `GetUpdates(0)` is read-only and succeeds.

Dead-end reason: read-only query APIs are reachable. Package install/remove, local `.deb` install, proxy changes, repo changes, repair, refresh, and offline update triggers either require auth or only reach an auth-failure state. No default source control and no root package operation.

## org.freedesktop.UDisks2

Default service/config:

```text
/usr/share/dbus-1/system-services/org.freedesktop.UDisks2.service
2 Name=org.freedesktop.UDisks2
3 Exec=/usr/libexec/udisks2/udisksd
4 User=root
5 SystemdService=udisks2.service

/usr/lib/systemd/system/udisks2.service
6 Type=dbus
7 BusName=org.freedesktop.UDisks2
8 ExecStart=/usr/libexec/udisks2/udisksd
```

Relevant policy:

```text
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy
9    filesystem-mount: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/yes
97   filesystem-mount-system: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin_keep
269  filesystem-mount-other-user: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin_keep
492  filesystem-take-ownership: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin_keep
1143 loop-setup: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/yes
1226 loop-delete-others: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin_keep
1305 loop-modify-others: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin_keep
2035 modify-device: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/yes
2121 modify-device-system: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin_keep
2371 open-device: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin_keep
2457 open-device-system: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin_keep
2552 modify-system-configuration: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin
2637 read-system-configuration-secrets: allow_any/auth_admin, allow_inactive/auth_admin, allow_active/auth_admin
```

Attacker trigger:

```sh
dd if=/dev/zero of=/tmp/udisks-attacker.img bs=1M count=16 status=none
mkfs.ext4 -q -F /tmp/udisks-attacker.img
udisksctl loop-setup -f /tmp/udisks-attacker.img
udisksctl mount -b /dev/vda1
udisksctl unlock -b /dev/vda1
```

Results:

```text
loop-setup:
Error creating textual authentication agent: Error opening current controlling terminal for the process (`/dev/tty'): No such device or address
Error setting up loop device for /tmp/udisks-attacker.img: ... NotAuthorizedCanObtain: Not authorized to perform operation

/dev/vda1:
Already mounted at /etc/hostname, /etc/hosts, /etc/resolv.conf.
Object ... is not an encrypted device.
```

Read-only manager calls succeeded:

```text
GetBlockDevices -> list of block devices
CanFormat("ext4") -> (true, "")
CanCheck("ext4") -> (true, "")
```

Dead-end reason: default-running root disk manager, but attacker cannot create loop devices without polkit authorization in this non-console shell. System devices require stronger auth and existing default block devices do not provide a write/mount-to-root primitive. No loop, mount, open-device, fstab, crypttab, or system-configuration LPE.

Cleanup:

```sh
rm -f /tmp/udisks-attacker.img
```

## org.freedesktop.fwupd

Default service/config:

```text
/usr/share/dbus-1/system-services/org.freedesktop.fwupd.service
2 Name=org.freedesktop.fwupd
4 Exec=/usr/libexec/fwupd/fwupd
5 User=root
6 SystemdService=fwupd.service

/usr/lib/systemd/system/fwupd.service
6  ConditionVirtualization=!container
9  Type=dbus
13 BusName=org.freedesktop.fwupd
14 ExecStart=/usr/libexec/fwupd/fwupd
15 PrivateTmp=yes
16 ProtectHome=yes
17 ProtectSystem=full
23 ReadWritePaths=-/boot/efi -/boot/EFI -/boot/grub -/efi/EFI -/sys/firmware/efi/efivars
24 ConfigurationDirectory=fwupd
25 StateDirectory=fwupd
26 CacheDirectory=fwupd
```

Policy highlights:

```text
/usr/share/polkit-1/actions/org.freedesktop.fwupd.policy
11   update-internal-trusted: allow_any/auth_admin, allow_inactive/no, allow_active/yes
87   update-internal: allow_any/auth_admin, allow_inactive/no, allow_active/auth_admin_keep
299  update-hotplug-trusted: allow_any/auth_admin, allow_inactive/no, allow_active/yes
374  update-hotplug: allow_any/auth_admin, allow_inactive/no, allow_active/auth_admin_keep
670  modify-config: allow_any/auth_admin, allow_inactive/no, allow_active/auth_admin_keep
873  modify-remote: allow_any/auth_admin, allow_inactive/no, allow_active/auth_admin_keep
940  set-approved-firmware: allow_any/auth_admin, allow_inactive/no, allow_active/auth_admin_keep
1005 self-sign: allow_any/auth_admin, allow_inactive/no, allow_active/auth_admin_keep
1119 set-bios-settings: allow_any/auth_admin, allow_inactive/no, allow_active/auth_admin
1170 fix-host-security-attr: allow_any/auth_admin, allow_inactive/no, allow_active/auth_admin
1196 undo-host-security-attr: allow_any/auth_admin, allow_inactive/no, allow_active/auth_admin
```

Target behavior:

```text
fwupd.service - Firmware update daemon was skipped because of an unmet condition check (ConditionVirtualization=!container).
```

Attacker/root introspection attempts timed out or found no object because the target is a container and the service is condition-skipped.

Dead-end reason: default-installed and DBus-activatable in package metadata, but not reachable in this live target due the unit condition. Even on a non-container server, the interesting `allow_active=yes` paths are firmware update paths requiring active-local semantics and real firmware devices; that violates the no-special-hardware completion bar and gives no stock no-hardware root command execution primitive.

## login1, timedated, hostnamed, localed, networkd

Default systemd service files expose hardened root/system services:

```text
/usr/lib/systemd/system/systemd-logind.service
25 BusName=org.freedesktop.login1
26 CapabilityBoundingSet=CAP_SYS_ADMIN ... CAP_DAC_OVERRIDE ...
38 NoNewPrivileges=yes
47 ProtectSystem=strict
48 ReadWritePaths=/etc /run

/usr/lib/systemd/system/systemd-timedated.service
17 BusName=org.freedesktop.timedate1
18 CapabilityBoundingSet=CAP_SYS_TIME
24 NoNewPrivileges=yes
33 ProtectSystem=strict
34 ReadWritePaths=/etc

/usr/lib/systemd/system/systemd-hostnamed.service
18 BusName=org.freedesktop.hostname1
19 CapabilityBoundingSet=CAP_SYS_ADMIN
24 NoNewPrivileges=yes
34 ProtectSystem=strict
35 ReadWritePaths=/etc /run/systemd

/usr/lib/systemd/system/systemd-localed.service
18 BusName=org.freedesktop.locale1
19 CapabilityBoundingSet=
24 NoNewPrivileges=yes
35 ProtectSystem=strict
36 ReadWritePaths=/etc
37 ReadWritePaths=/usr/lib/locale
```

Policy:

```text
timedated set-time/set-timezone/set-local-rtc/set-ntp: auth_admin_keep for any/inactive/active
hostnamed setters and hardware UUID/serial/description getters: auth_admin_keep for any/inactive/active
localed setters: auth_admin_keep for any/inactive/active
networkd setters/reload/reconfigure: auth_admin or auth_admin_keep
login1 set-self-linger: allow_any/yes, allow_inactive/yes, allow_active/yes
login1 reboot/power/suspend/hibernate and reboot-parameter actions: active yes for some actions, but no root code execution primitive
```

Attacker trigger results:

```sh
busctl --system call org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 SetNTP bb false false
busctl --system call org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1 SetPrettyHostname sb 'attacker pretty' false
busctl --system call org.freedesktop.locale1 /org/freedesktop/locale1 org.freedesktop.locale1 SetLocale asb 1 LANG=C.UTF-8 false
```

All privileged writes returned:

```text
Call failed: Interactive authentication required.
```

`login1` self-linger is allowed:

```sh
busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager SetUserLinger ubb 1001 true false
ls -l /var/lib/systemd/linger
busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager SetUserLinger ubb 1001 false false
```

It created then removed a root-owned marker:

```text
-rw-r--r-- 1 root root 0 ... attacker
```

Impact is only user-service persistence for uid 1001, not privilege escalation.

Power/reboot checks:

```text
CanReboot  -> "challenge"
CanPowerOff -> "challenge"
```

`org.freedesktop.network1` is not reachable in the target:

```text
systemd-networkd.service: disabled, inactive
systemd-networkd.socket: disabled, inactive
busctl org.freedesktop.network1: Unit dbus-org.freedesktop.network1.service not found.
```

Dead-end reason: privileged setters require auth; allowed login1 actions are session/power/inhibit/self-linger semantics and do not produce root execution or root-readable/writeable data useful for escalation. Networkd DBus activation is not wired in the target default state.

Cleanup:

```sh
busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager SetUserLinger ubb 1001 false false
rm -f /tmp/udisks-attacker.img
```

Post-cleanup checks:

```text
/var/lib/systemd/linger contains no attacker file.
/tmp/udisks-attacker.img does not exist.
```

## Conclusion

No DBus/polkit service in this slice produced a valid stock Ubuntu 24.04 Server local privilege escalation from attacker uid 1001.

Most scanner-style output would flag several attractive surfaces: root DBus activators, PackageKit root package methods, UDisks loop/mount `allow_active=yes`, fwupd trusted firmware `allow_active=yes`, and netplan root config/apply methods. Manual trigger testing showed these are gated by polkit, caller/session checks, systemd unit conditions, or non-escalating semantics in the default target.

The only edge worth carrying forward is netplan's visible root-created config object namespace. It is currently not exploitable because uid 1001 receives `Access denied` on every config-object method.
