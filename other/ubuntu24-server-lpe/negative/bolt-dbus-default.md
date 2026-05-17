# bolt D-Bus default daemon audit

Status: negative. No uid1001(attacker) -> root local privilege escalation found in the default `bolt` daemon surface.

## Target/default proof

Live Docker target: `ubuntu24-server-lpe-target`, stock Ubuntu Server metapackage image.

```
$ docker exec ubuntu24-server-lpe-target cat /etc/os-release
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_CODENAME=noble

$ docker exec ubuntu24-server-lpe-target dpkg-query -W -f='${binary:Package}\t${Version}\n' ubuntu-server ubuntu-standard ubuntu-minimal bolt fwupd polkitd dbus systemd
bolt	0.9.7-1
dbus	1.14.10-4ubuntu4.1
fwupd	1.9.34-0ubuntu1~24.04.1
polkitd	124-2ubuntu1.24.04.3
systemd	255.4-1ubuntu8.15
ubuntu-minimal	1.539.2
ubuntu-server	1.539.2
ubuntu-standard	1.539.2
```

`ubuntu-server` recommends `fwupd`, and `fwupd` recommends `bolt`; default apt install of the server metapackage includes recommends:

```
$ docker exec ubuntu24-server-lpe-target apt-cache depends ubuntu-server
  Recommends: fwupd

$ docker exec ubuntu24-server-lpe-target apt-cache depends fwupd
  Recommends: bolt
```

Service state:

```
$ docker exec ubuntu24-server-lpe-target systemctl status --no-pager -l bolt.service
Loaded: loaded (/usr/lib/systemd/system/bolt.service; static)
Active: active (running)
Main PID: 14400 (boltd)
Status: "authmode: enabled, force-power: unset"
```

`org.freedesktop.bolt` is owned by `/usr/libexec/boltd` as root with only `CAP_NET_ADMIN` effective/permitted:

```
$ docker exec ubuntu24-server-lpe-target busctl --system status org.freedesktop.bolt
UID=0
EUID=0
CommandLine=/usr/libexec/boltd
EffectiveCapabilities=cap_net_admin
PermittedCapabilities=cap_net_admin
```

Attacker subject:

```
$ docker exec -u attacker ubuntu24-server-lpe-target id
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

## Installed code/config paths

Package file inventory relevant to privilege boundaries:

```
/usr/bin/boltctl
/usr/libexec/boltd
/usr/lib/systemd/system/bolt.service
/usr/lib/udev/rules.d/90-bolt.rules
/usr/share/dbus-1/interfaces/org.freedesktop.bolt.xml
/usr/share/dbus-1/system-services/org.freedesktop.bolt.service
/usr/share/dbus-1/system.d/org.freedesktop.bolt.conf
/usr/share/polkit-1/actions/org.freedesktop.bolt.policy
/usr/share/polkit-1/rules.d/org.freedesktop.bolt.rules
/var/lib/boltd
```

Important line-level evidence:

- `/usr/lib/systemd/system/bolt.service`: `Type=dbus`, `BusName=org.freedesktop.bolt`, `ExecStart=/usr/libexec/boltd`, hardening options, and `ReadWritePaths=/var/lib/boltd`, `RuntimeDirectory=boltd`, `StateDirectory=boltd` at lines 6-30.
- `/usr/share/dbus-1/system-services/org.freedesktop.bolt.service`: D-Bus activation runs `/usr/libexec/boltd` as `User=root` at lines 1-5.
- `/usr/share/dbus-1/system.d/org.freedesktop.bolt.conf`: root may own the bus name at lines 9-11; default clients may send to Manager/Domain/Device/Power interfaces at lines 13-37.
- `/usr/share/polkit-1/actions/org.freedesktop.bolt.policy`: `enroll`, `authorize`, and `manage` all require `auth_admin`/`auth_admin_keep` at lines 18-48.
- `/usr/share/polkit-1/rules.d/org.freedesktop.bolt.rules`: passwordless allow only when subject is active, local, and in group `sudo` at lines 2-10.
- `/usr/lib/udev/rules.d/90-bolt.rules`: Thunderbolt subsystem devices request `bolt.service` at lines 11-16.

Default daemon state is root-owned:

```
$ docker exec ubuntu24-server-lpe-target find /var/lib/boltd /run/boltd -maxdepth 2 -ls
drwxr-xr-x root root /var/lib/boltd
-rw-r--r-- root root /var/lib/boltd/version
drwxr-xr-x root root /run/boltd
drwxr-xr-x root root /run/boltd/power
```

Attacker cannot write either daemon state root:

```
$ docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'touch /var/lib/boltd/attacker-probe 2>&1 || true; touch /run/boltd/attacker-probe 2>&1 || true'
touch: cannot touch '/var/lib/boltd/attacker-probe': Permission denied
touch: cannot touch '/run/boltd/attacker-probe': Permission denied
```

No Thunderbolt device objects exist in the Docker target and no special hardware is in scope:

```
$ docker exec ubuntu24-server-lpe-target sh -lc 'test -d /sys/bus/thunderbolt/devices && find /sys/bus/thunderbolt/devices -maxdepth 1 -mindepth 1 -printf "%f\n" || echo absent'
absent
```

## Exposed D-Bus methods/properties

Object tree:

```
$ docker exec ubuntu24-server-lpe-target busctl --system tree org.freedesktop.bolt
/org/freedesktop/bolt
```

Interfaces from `/usr/share/dbus-1/interfaces/org.freedesktop.bolt.xml` and live introspection:

- `org.freedesktop.bolt1.Manager`: readable properties `Version`, `Probing`, `DefaultPolicy`, `SecurityLevel`, `PowerState`, `Generation`; writable `AuthMode`; methods `ListDomains`, `DomainById`, `ListDevices`, `DeviceByUid`, `EnrollDevice`, `ForgetDevice`.
- `org.freedesktop.bolt1.Power`: readable `Supported`, `State`, `Timeout`; methods `ForcePower`, `ListGuards`.
- `org.freedesktop.bolt1.Device`: readable device metadata; writable `Policy`, `Label`; method `Authorize`. No default device object was present.
- `org.freedesktop.bolt1.Domain`: readable domain metadata; writable `BootACL`. No default domain object was present.

Relevant interface XML line ranges:

- Manager properties/methods: lines 6-174.
- Power `ForcePower`/`ListGuards`: lines 220-296.
- Device writable `Policy`/`Label` and `Authorize`: lines 298-456.
- Domain writable `BootACL`: lines 458-509.

## Attacker trigger attempts

Read-only enumeration works and returns no devices/domains/guards:

```
$ docker exec -u attacker ubuntu24-server-lpe-target busctl call --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Manager ListDevices
ao 0

$ docker exec -u attacker ubuntu24-server-lpe-target busctl call --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Manager ListDomains
ao 0

$ docker exec -u attacker ubuntu24-server-lpe-target busctl call --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Power ListGuards
a(ssu) 0
```

Read-only properties are visible:

```
$ docker exec -u attacker ubuntu24-server-lpe-target busctl get-property --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Manager AuthMode
s "enabled"

$ docker exec -u attacker ubuntu24-server-lpe-target busctl get-property --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Power Supported
b false
```

Mutating manager/power paths are denied before any useful root-side effect:

```
$ docker exec -u attacker ubuntu24-server-lpe-target busctl call --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Manager EnrollDevice sss fake-uid auto ''
Call failed: Access denied

$ docker exec -u attacker ubuntu24-server-lpe-target busctl call --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Manager ForgetDevice s fake-uid
Call failed: Access denied

$ docker exec -u attacker ubuntu24-server-lpe-target busctl set-property --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Manager AuthMode s disabled
Failed to set property AuthMode on interface org.freedesktop.bolt1.Manager: Access denied

$ docker exec -u attacker ubuntu24-server-lpe-target busctl call --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Power ForcePower ss attacker ''
Call failed: Access denied
```

The same result appears through the shipped client:

```
$ docker exec -u attacker ubuntu24-server-lpe-target boltctl enroll fake-uid
Bolt operation 'EnrollDevice' not allowed for user

$ docker exec -u attacker ubuntu24-server-lpe-target boltctl forget fake-uid
Failed to forget device: Bolt operation 'ForgetDevice' not allowed for user

$ docker exec -u attacker ubuntu24-server-lpe-target boltctl config global.auth-mode disabled
boltctl config: error: Setting property of 'BoltManager.auth-mode' not allowed for user

$ docker exec -u attacker ubuntu24-server-lpe-target boltctl power
Could force power controller: Bolt operation 'ForcePower' not allowed for user
```

Direct polkit checks for the bolt actions require authentication for uid1001, and the non-sudo Docker attacker has no agent/admin path:

```
$ docker exec -u attacker ubuntu24-server-lpe-target sh -lc 'for a in org.freedesktop.bolt.enroll org.freedesktop.bolt.authorize org.freedesktop.bolt.manage; do pkcheck --action-id "$a" --process $$ >/dev/null 2>&1; printf "%s exit=%s\n" "$a" "$?"; done'
org.freedesktop.bolt.enroll exit=2
org.freedesktop.bolt.authorize exit=2
org.freedesktop.bolt.manage exit=2
```

`DeviceByUid` and `DomainById` do not provide creation or arbitrary object access:

```
$ docker exec -u attacker ubuntu24-server-lpe-target busctl call --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Manager DeviceByUid s fake-uid
Call failed: device with id 'fake-uid' could not be found.

$ docker exec -u attacker ubuntu24-server-lpe-target busctl call --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Manager DomainById s fake-domain
Call failed: domain with id 'fake-domain' could not be found.
```

## Result

No root context was obtained and no root proof exists for this candidate.

The D-Bus bus policy is intentionally broad enough for clients to talk to `boltd`, so a simple scanner will flag many root-owned, writable-looking methods. The actual trust boundary is inside `boltd`'s polkit checks: all default state-changing operations available without special hardware (`EnrollDevice`, `ForgetDevice`, `AuthMode`, `ForcePower`) returned `Access denied` for uid1001. The remaining read/enumeration paths returned empty default state. File-write paths are limited to root-owned `/var/lib/boltd` and `/run/boltd`; the attacker cannot preseed or replace those files.

Cleanup: no persistent changes were made. Failed D-Bus calls and failed `touch` probes left no files under `/var/lib/boltd` or `/run/boltd`.

Suggested hardening note for triage: no vulnerability found. If reducing attack surface is desired, the D-Bus policy could be split so only read-only Manager/Power methods are broadly sendable and mutating methods require bus-level policy as defense-in-depth, but the tested default configuration already enforces the privilege boundary through polkit.
