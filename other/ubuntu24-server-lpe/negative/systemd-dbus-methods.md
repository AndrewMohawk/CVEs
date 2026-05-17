# system D-Bus / systemd-adjacent LPE audit negative result

Target: `ubuntu24-server-lpe-target`  
Attacker model: uid 1001 `attacker`, groups `attacker` only, no sudo/adm/lxd, no graphical/session auth agent.

## Live default state

Baseline identity and OS:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'id attacker; cat /etc/os-release; systemctl --version | head -1'
```

Observed:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
PRETTY_NAME="Ubuntu 24.04.4 LTS"
systemd 255 (255.4-1ubuntu8.15)
```

Relevant installed package versions:

```text
dbus                         1.14.10-4ubuntu4.1
dbus-daemon                  1.14.10-4ubuntu4.1
dbus-user-session            1.14.10-4ubuntu4.1
fwupd                        1.9.34-0ubuntu1~24.04.1
netplan.io                   1.1.2-8ubuntu1~24.04.2
packagekit                   1.2.8-2ubuntu1.5
polkitd                      124-2ubuntu1.24.04.3
software-properties-common   0.99.49.4
python3-software-properties  0.99.49.4
systemd                      255.4-1ubuntu8.15
systemd-resolved             255.4-1ubuntu8.15
udisks2                      2.10.1-6ubuntu1.3
```

Reachable/default service state:

```text
dbus active, polkit active, systemd-logind active, systemd-resolved active
systemd-hostnamed/localed/timedated static + D-Bus activatable
io.netplan.Netplan active on system bus, root netplan-dbus
com.ubuntu.SoftwareProperties active on system bus, root python3
packagekit.service static + active after D-Bus activation
udisks2.service enabled + active
fwupd installed and activatable, but inactive in this container:
  fwupd.service was skipped because ConditionVirtualization=!container
```

## Polkit posture

No-session uid1001 `pkcheck` results:

```sh
runuser -u attacker -- sh -c 'for a in ...; do timeout 4 pkcheck --action-id $a --process $$ --allow-user-interaction; echo rc=$?; done'
```

Key results:

```text
com.ubuntu.softwareproperties.applychanges             rc=2 no agent
org.freedesktop.systemd1.manage-units                  rc=2 no agent
org.freedesktop.systemd1.set-environment               rc=2 no agent
org.freedesktop.login1.set-self-linger                 rc=0
org.freedesktop.login1.set-user-linger                 rc=2 no agent
org.freedesktop.locale1.set-locale                     rc=2 no agent
org.freedesktop.hostname1.set-hostname                 rc=2 no agent
org.freedesktop.timedate1.set-timezone                 rc=2 no agent
org.freedesktop.resolve1.set-dns-servers               rc=2 no agent
org.freedesktop.packagekit.system-sources-refresh      rc=2 no agent
org.freedesktop.packagekit.package-install             rc=2 no agent
org.freedesktop.udisks2.loop-setup                     rc=2 no agent
org.freedesktop.udisks2.filesystem-mount               rc=2 no agent
```

## Probes and dead ends

### systemd1

Mutating methods audited included `StartUnit`, `StartTransientUnit`, `EnableUnitFiles`, `LinkUnitFiles`, `SetUnitProperties`, `SetEnvironment`, `UnsetAndSetEnvironment`, `Reload`, `Reexecute`, `BindMountUnit`, `MountImageUnit`, `KillUnit`, and unit-file methods.

Root command attempt:

```sh
runuser -u attacker -- systemd-run --unit=systemd-dbus-lpe-test --property=Type=oneshot /bin/sh -c 'id > /tmp/systemd-dbus-root-id'
```

Result:

```text
Failed to start transient service unit: Interactive authentication required.
/tmp/systemd-dbus-root-id did not exist
```

Unit-file link/enable attempt with attacker-controlled `/tmp/systemd-dbus-lpe.service`:

```text
Failed to link unit: Interactive authentication required.
Failed to enable unit: Interactive authentication required.
/etc/systemd/system/systemd-dbus-lpe.service did not exist
```

Environment propagation:

```sh
runuser -u attacker -- busctl call --system org.freedesktop.DBus / org.freedesktop.DBus UpdateActivationEnvironment a{ss} 2 LD_PRELOAD /tmp/notreal SYSTEMD_LOG_LEVEL debug
runuser -u attacker -- busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager SetEnvironment as 1 LPE_ENV_MARKER=attacker
```

Both returned `Call failed: Access denied`; `org.freedesktop.systemd1.Manager.Environment` did not contain the marker.

Activation inheritance was also checked by activating `systemd-hostnamed` with attacker caller env `DBUS_LPE_MARKER`, `LD_PRELOAD`, and `SYSTEMD_LOG_LEVEL`; `/proc/$MainPID/environ` for the root activator contained none of those variables.

### logind

`SetUserLinger` for the caller is intentionally allowed:

```sh
runuser -u attacker -- loginctl enable-linger attacker
ls -l /var/lib/systemd/linger/attacker
runuser -u attacker -- loginctl disable-linger attacker
```

Result:

```text
-rw-r--r-- 1 root root 0 ... /var/lib/systemd/linger/attacker
after disable: no such file
```

This is a root-owned file mutation, but only enables an `attacker` user manager. No `systemd --user` root transition or root unit execution path was created.

### hostnamed / localed / timedated / resolved

Safe mutation probes:

```sh
runuser -u attacker -- busctl call --system org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1 SetStaticHostname sb "${cur}-lpeprobe" false
runuser -u attacker -- busctl call --system org.freedesktop.locale1 /org/freedesktop/locale1 org.freedesktop.locale1 SetLocale asb 1 LANG=C false
runuser -u attacker -- busctl call --system org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 SetTimezone sb UTC false
runuser -u attacker -- busctl call --system org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDNS 'ia(iay)' "$ifidx" 1 2 4 127 0 0 1
```

Results:

```text
hostnamed: Call failed: Interactive authentication required.
localed LANG=C: Call failed: Interactive authentication required.
timedated: Call failed: Interactive authentication required.
resolved non-loopback: Call failed: Interactive authentication required.
```

Before/after stat checks on `/etc/hostname`, `/etc/default/locale -> ../locale.conf`, `/etc/vconsole.conf -> default/keyboard`, `/etc/timezone`, `/etc/localtime`, `/etc/systemd/resolved.conf`, and `/run/systemd/resolve/stub-resolv.conf` showed no changed size or mtime from denied calls. `resolved` validates loopback links before auth (`Link lo is loopback device`), but the non-loopback path reaches auth and is denied.

### netplan D-Bus

Service files:

```text
/usr/share/dbus-1/system-services/io.netplan.Netplan.service
  Exec=/usr/libexec/netplan/netplan-dbus
  User=root
```

Bus policy allows sends to `io.netplan.Netplan`, but the daemon rejects uid1001 at runtime:

```sh
for m in Info Generate Apply Config; do
  runuser -u attacker -- busctl call --system io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan "$m"
done
```

All returned:

```text
Call failed: Access denied
```

Root-only introspection showed `Config` objects expose `Get`, `Set(ss)`, `Try(u)`, `Apply`, and `Cancel`. Binary strings confirm root-side temporary state under `--root-dir=%s/run/netplan/config-%s` and `--state=%s/run/netplan/config-%s`; uid1001 cannot obtain a config object, so generated-file symlink/race paths were not reachable. Root-created config object was cancelled; no `/run/netplan/config-*` residue remained.

### SoftwareProperties

`com.ubuntu.SoftwareProperties` is root D-Bus activated and active. Source review of `/usr/lib/python3/dist-packages/softwareproperties/dbus/SoftwarePropertiesDBus.py` showed write methods call `_check_policykit_privilege(..., "com.ubuntu.softwareproperties.applychanges")` before file writes/subprocesses. `Reload` is unauthenticated but only reloads sources into memory.

Probes:

```sh
runuser -u attacker -- busctl call --system com.ubuntu.SoftwareProperties / com.ubuntu.SoftwareProperties Reload
runuser -u attacker -- busctl call --system com.ubuntu.SoftwareProperties / com.ubuntu.SoftwareProperties AddSourceFromLine s 'deb http://127.0.0.1/ubuntu noble main'
runuser -u attacker -- busctl call --system com.ubuntu.SoftwareProperties / com.ubuntu.SoftwareProperties AddKey s /tmp/systemd-dbus-test-key.gpg
```

Results:

```text
Reload: returned successfully, no file change
AddSourceFromLine: Call failed: com.ubuntu.softwareproperties.applychanges
AddKey: Call failed: com.ubuntu.softwareproperties.applychanges
```

Before/after stats for `/etc/apt/sources.list`, `/etc/apt/sources.list.d`, `/etc/apt/trusted.gpg.d`, `/etc/apt/apt.conf.d/10periodic`, and `/etc/update-manager/release-upgrades` did not change.

### PackageKit

`org.freedesktop.PackageKit` is D-Bus/systemd activated as root and reachable. Transaction methods include `InstallFiles`, `InstallPackages`, `RefreshCache`, `RepoEnable`, `RepoSetData`, `RepairSystem`, `UpdatePackages`, and `UpgradeSystem`.

Findings:

```text
CreateTransaction as uid1001 succeeded.
Transaction objects are sender-bound; using a different busctl connection returned:
  sender does not match (:new vs :creator)
SetProxy as uid1001 returned:
  Call failed: failed to obtain auth
pkcon refresh as uid1001 reached "Waiting for authentication" then:
  Fatal error: Failed to obtain authentication.
pkcon install bash did not install anything; it resolved the already installed package and stopped.
```

No unauthenticated package install, repo write, proxy persistence, offline update trigger, or root execution path validated.

### fwupd

Package and D-Bus service are installed, but the default service is not reachable in this container because the unit condition excludes containers:

```text
fwupd.service - Firmware update daemon
Active: inactive (dead)
fwupd.service was skipped because of an unmet condition check (ConditionVirtualization=!container).
```

`fwupdmgr get-devices` and `busctl tree org.freedesktop.fwupd` as uid1001 timed out through activation. No fwupd D-Bus method was reachable for LPE in this target.

### udisks2

`udisks2.service` is enabled and active. Relevant methods audited: `LoopSetup`, `MDRaidCreate`, `EnableModule(s)`, `Block.OpenDevice`, `Block.Format`, `Block.AddConfigurationItem`, `Filesystem.Mount`, `Filesystem.TakeOwnership`, and `Loop.Delete`.

No-session polkit denies the desktop-style active-user permissions. Python D-Bus fd-passing probe:

```py
fd = os.open("/tmp/systemd-dbus-udisks.img", os.O_RDONLY)
mgr.LoopSetup(dbus.types.UnixFd(fd), {})
```

Result:

```text
DBusException org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain: Not authorized to perform operation
```

No loop device was created; `losetup -a` contained no test image. Since `LoopSetup` is denied, the mount/suid/nosuid path from attacker-controlled filesystem images is not reachable in this no-session server shell model.

## Cleanup

Removed or verified absent:

```text
/tmp/systemd-dbus-root-id
/tmp/systemd-dbus-link-id
/tmp/systemd-dbus-lpe.service
/tmp/systemd-dbus-udisks.img
/tmp/systemd-dbus-test-key.gpg
/etc/systemd/system/systemd-dbus-lpe.service
/var/lib/systemd/linger/attacker
/run/netplan/config-*
```

Existing unrelated `/tmp/lpe-baseline` was left untouched.

## Conclusion

No real uid1001 `attacker` to root LPE validated across the default active/reachable system D-Bus and systemd-adjacent services in this Ubuntu 24.04.4 Server container. The only unauthenticated root-owned mutation found was `login1.set-self-linger`, which is policy-allowed and scoped to the caller's own user manager, not root execution. All root execution, unit-file, package/repo, netplan generated-file, udisks loop/mount, host/time/locale/resolved, and activation-environment paths either require interactive/admin polkit authorization, are runtime denied to uid1001, or are not reachable under the container's default service conditions.
