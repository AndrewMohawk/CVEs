# netplan / systemd-networkd / software-properties D-Bus negative result

Date: 2026-05-16

Target:

```
container: ubuntu24-server-lpe-target
image: ubuntu24-server-default-lpe:20260516-standard
os: Ubuntu 24.04.4 LTS (Noble)
kernel: Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64
attacker: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
selfauth: uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

Package/version proof:

```
dbus                         1.14.10-4ubuntu4.1        install ok installed
netplan.io                   1.1.2-8ubuntu1~24.04.2    install ok installed
polkitd                      124-2ubuntu1.24.04.3      install ok installed
python3-software-properties  0.99.49.4                 install ok installed
software-properties-common   0.99.49.4                 install ok installed
systemd                      255.4-1ubuntu8.15         install ok installed
systemd-resolved             255.4-1ubuntu8.15         install ok installed
systemd-sysv                 255.4-1ubuntu8.15         install ok installed
dpkg-query: no packages found matching systemd-networkd
```

Default reachability:

```
/run/dbus/system_bus_socket: srw-rw-rw- 1 root root
io.netplan.Netplan: root-owned netplan-dbus on system bus
com.ubuntu.SoftwareProperties: root-owned python3 software-properties-dbus on system bus
org.freedesktop.network1: activatable only; systemd-networkd.service and socket inactive by default in this Docker target
```

## netplan D-Bus

The service file is root-run:

```
[D-BUS Service]
Name=io.netplan.Netplan
Exec=/usr/libexec/netplan/netplan-dbus
User=root
AssumedAppArmorLabel=unconfined
```

uid1001 can introspect object paths, but every root-affecting method is denied before method execution:

```
$ runuser -u attacker -- busctl call --system io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Config
Call failed: Access denied

$ runuser -u attacker -- busctl call --system io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Info
Call failed: Access denied

$ runuser -u attacker -- gdbus call --system --dest io.netplan.Netplan --object-path /io/netplan/Netplan --method io.netplan.Netplan.Apply
Error: GDBus.Error:org.freedesktop.DBus.Error.AccessDenied: Access to io.netplan.Netplan.Apply() not permitted.
```

Existing config-object methods are denied too:

```
/io/netplan/Netplan/config/P25NP3 Get:    Call failed: Access denied
/io/netplan/Netplan/config/P25NP3 Cancel: Call failed: Access denied
/io/netplan/Netplan/config/P25NP3 Apply:  Call failed: Access denied
/io/netplan/Netplan/config/40JCP3 Get:    Call failed: Access denied
/io/netplan/Netplan/config/40JCP3 Cancel: Call failed: Access denied
/io/netplan/Netplan/config/40JCP3 Apply:  Call failed: Access denied
```

The denial is from systemd sd-bus privilege handling, not from the XML bus policy. A monitor of uid1001 calling `Info` showed `netplan-dbus` querying the caller uid and returning the denial:

```
Sender=:1.1546 Destination=io.netplan.Netplan Path=/io/netplan/Netplan Interface=io.netplan.Netplan Member=Info
Sender=:1.11 Destination=org.freedesktop.DBus Interface=org.freedesktop.DBus Member=GetConnectionUnixUser
STRING ":1.1546";
UINT32 1001;
ErrorName=org.freedesktop.DBus.Error.AccessDenied
ErrorMessage="Access to io.netplan.Netplan.Info() not permitted."
```

Source review of the matching 1.1.2 D-Bus code showed the method vtables are registered with flags `0`, not `SD_BUS_VTABLE_UNPRIVILEGED`, so non-root callers are rejected by sd-bus. The root-only implementation would otherwise spawn `/usr/sbin/netplan` with absolute argv[0], create `/run/netplan/config-XXXXXX` as root `0700`, copy YAML using `G_FILE_COPY_NOFOLLOW_SYMLINKS`, and call root-only `netplan apply/generate/set/get`. Because uid1001 cannot invoke the vtable methods, these root file writes and reload transitions are not reachable from a normal non-sudo user.

Root control check/cleanup: a root `Config()` call created `/io/netplan/Netplan/config/P25NP3`; it was cancelled with:

```
busctl call --system io.netplan.Netplan /io/netplan/Netplan/config/P25NP3 io.netplan.Netplan.Config Cancel
b true
```

Pre-existing `/run/netplan/config-40JCP3` and `/run/netplan/config-LV1LP3` were left untouched.

## software-properties D-Bus

The service is installed and reachable:

```
[D-BUS Service]
Name=com.ubuntu.SoftwareProperties
Exec=/usr/lib/software-properties/software-properties-dbus
User=root
```

`Reload()` is callable but only reloads the daemon's in-memory sources list. A file-state hash over `/etc/apt`, `/etc/update-manager`, `/etc/netplan`, `/run/netplan`, `/run/systemd/network`, and `/run/NetworkManager` was unchanged before/after `Reload()`.

```
before=b12c3247fa51f324af3ee874ea16e131cfc38b3a89a397ca0f6b70d7b6523841
gdbus call ... com.ubuntu.SoftwareProperties.Reload
()
after=b12c3247fa51f324af3ee874ea16e131cfc38b3a89a397ca0f6b70d7b6523841
```

Mutating methods are Polkit-gated:

```
$ runuser -u attacker -- gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.AddSourceFromLine "deb http://127.0.0.1/ubuntu noble main"
Error: GDBus.Error:com.ubuntu.SoftwareProperties.PermissionDeniedByPolicy: com.ubuntu.softwareproperties.applychanges

$ runuser -u selfauth -- gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.SetUpdateInterval 7
Error: GDBus.Error:com.ubuntu.SoftwareProperties.PermissionDeniedByPolicy: com.ubuntu.softwareproperties.applychanges
```

Installed source confirms all mutating D-Bus methods call `_check_policykit_privilege(..., "com.ubuntu.softwareproperties.applychanges")`. The installed policy is `auth_admin` / `auth_admin_keep`, so the non-sudo `attacker` and passworded non-sudo `selfauth` users do not get a default local-user write primitive:

```
com.ubuntu.softwareproperties.applychanges:
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   auth_admin_keep
```

No `/etc/apt`, `/etc/update-manager`, or keyring write was observed from non-sudo calls.

## systemd-networkd D-Bus

Default Docker-target state:

```
systemd-networkd.service: inactive
systemd-networkd.socket:  inactive
org.freedesktop.network1: activatable

$ runuser -u attacker -- busctl --system introspect org.freedesktop.network1 /
Failed to introspect object / of service org.freedesktop.network1: Unit dbus-org.freedesktop.network1.service not found.
```

For semantics only, I root-started `systemd-networkd.service`, tested uid1001 calls, then stopped both service and socket. Read-only inventory methods are callable, but mutating reload/reconfigure paths require Polkit:

```
$ runuser -u attacker -- busctl call --system org.freedesktop.network1 /org/freedesktop/network1 org.freedesktop.network1.Manager ListLinks
a(iso) ...

$ runuser -u attacker -- busctl call --system org.freedesktop.network1 /org/freedesktop/network1 org.freedesktop.network1.Manager Reload
Call failed: Interactive authentication required.
```

Relevant policy defaults are admin-authenticated:

```
org.freedesktop.network1.reload:
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   auth_admin_keep

org.freedesktop.network1.reconfigure / set-dns-* / set-ntp-* / revert-*:
  implicit any:      auth_admin
  implicit inactive: auth_admin
```

Cleanup verified:

```
systemd-networkd.service: inactive
systemd-networkd.socket:  inactive
/tmp probe/source files: removed
root-created netplan config P25NP3: cancelled
```

## Conclusion

Negative. I did not validate a stock Ubuntu 24.04 Server default LPE from uid1001/uid1002 in these netplan, systemd-networkd, or software-properties D-Bus/helper surfaces. The reachable default surfaces are read-only or Polkit/admin/root gated. No root proof and no PoC artifact were created.
