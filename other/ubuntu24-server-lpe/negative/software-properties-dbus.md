# Negative: com.ubuntu.SoftwareProperties / software-properties D-Bus

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS. Attacker is `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`. `selfauth` is `uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)`.

## Result

No local privilege escalation was validated. The default Server image includes an activatable root system-bus service, `com.ubuntu.SoftwareProperties`, but the source/key/config mutators all reach the same Polkit gate, `com.ubuntu.softwareproperties.applychanges`, before attacker-controlled source lines, key paths, key data, or helper execution are processed.

Artifacts:

```text
pocs/software_properties_dbus_probe.sh
logs/software-properties-dbus.out
```

## Default package and reachability proof

Installed versions from the probe:

```text
software-properties-common       0.99.49.4              ii
python3-software-properties      0.99.49.4              ii
dbus                             1.14.10-4ubuntu4.1     ii
polkitd                          124-2ubuntu1.24.04.3   ii
apt                              2.8.3                  ii
python3-apt                      2.7.7ubuntu5.2         ii
python3-dbus                     1.3.2-5build3          ii
pkexec                           un
policykit-1                      un
```

Default service files:

```text
/usr/share/dbus-1/system-services/com.ubuntu.SoftwareProperties.service
  Name=com.ubuntu.SoftwareProperties
  Exec=/usr/lib/software-properties/software-properties-dbus
  User=root

/etc/dbus-1/system.d/com.ubuntu.SoftwareProperties.conf
  root may own com.ubuntu.SoftwareProperties
  default policy may send to com.ubuntu.SoftwareProperties and Introspectable
```

The attacker proved activation and method reachability:

```text
com.ubuntu.SoftwareProperties      - -  -  (activatable) - - - -
busctl --system introspect com.ubuntu.SoftwareProperties /
introspect_rc=0
com.ubuntu.SoftwareProperties 762705 python3 root :1.98347 dbus.service - -
```

The exposed methods include `AddSourceFromLine`, `ReplaceSourceEntry`, `RemoveSource`, `AddKey`, `AddKeyFromData`, `RemoveKey`, `UpdateKeys`, `AddCdromSource`, `EnableComponent`, and update/release-policy setters.

## Polkit boundary

The default policy is admin-only:

```text
com.ubuntu.softwareproperties.applychanges any=auth_admin inactive=auth_admin active=auth_admin_keep
```

The default admin identity rules are sudo/admin groups:

```text
50-default.rules: return ["unix-group:sudo"];
49-ubuntu-admin.rules: return ["unix-group:sudo", "unix-group:admin"];
```

The probe users are not in those groups:

```text
attacker : attacker
selfauth : selfauth
sudo:x:27:ubuntu
```

`pkcheck` as attacker returned `Authorization requires authentication and -u wasn't passed` with rc 2. `pkcheck --allow-user-interaction` as `selfauth` returned `Authorization requires authentication but no agent is available` with rc 2, and the D-Bus write trigger still failed with `PermissionDeniedByPolicy`.

## Trigger attempts

Read-only `Reload` is callable but did not write privileged state:

```text
gdbus call ... com.ubuntu.SoftwareProperties.Reload
()
reload_rc=0
```

All source-list write attempts failed at Polkit:

```text
AddSourceFromLine "deb [trusted=yes] file:/tmp/software-properties-dbus-probe noble main"
ReplaceSourceEntry ...
RemoveSource ...

Error: GDBus.Error:com.ubuntu.SoftwareProperties.PermissionDeniedByPolicy: com.ubuntu.softwareproperties.applychanges
```

Keyring, apt-cdrom, and config helper attempts also failed at the same gate, including an attacker-owned key path:

```text
-rw-r--r-- 1 attacker attacker ... /tmp/software-properties-dbus-probe/attacker/attacker-key.asc
AddKey /tmp/software-properties-dbus-probe/attacker/attacker-key.asc       -> PermissionDeniedByPolicy
AddKeyFromData "not a real key"                                           -> PermissionDeniedByPolicy
RemoveKey DEADBEEF                                                        -> PermissionDeniedByPolicy
UpdateKeys                                                                -> PermissionDeniedByPolicy
AddCdromSource                                                            -> PermissionDeniedByPolicy
EnableComponent universe                                                  -> PermissionDeniedByPolicy
SetUpdateInterval 1                                                       -> PermissionDeniedByPolicy
SetReleaseUpgradesPolicy 0                                                -> PermissionDeniedByPolicy
```

Direct helper invocation did not create a root path:

```text
PATH=/tmp/software-properties-dbus-probe/attacker/bin:... add-apt-repository -y -n "deb [trusted=yes] file:/tmp/software-properties-dbus-probe noble main"
Error: must run as root
addaptrepo_rc=1

/usr/lib/software-properties/software-properties-dbus --debug
org.freedesktop.DBus.Error.AccessDenied: ... not allowed to own the service "com.ubuntu.SoftwareProperties"
helper_rc=1

python3 SoftwareProperties(...).save_sourceslist()
uid 1001
PermissionError [Errno 13] Permission denied: '/etc/apt/sources.list.save'
```

## Root-owned state and cleanup

Root-owned apt state was unchanged before/after:

```text
/etc/apt/sources.list                  8ce6407d5487bed332b5fcb4aab26dacf3f516d811c26792efb0c67f06f1958b
/etc/apt/sources.list.d/ubuntu.sources 9fcfc0471807af385108d77aa63d0bdc3cc4f8e276a89f2bd9681f4bf8467a3f
```

Root proof was negative:

```text
ROOT_PROOF=no
```

Cleanup performed by the probe:

```sh
rm -rf /tmp/software-properties-dbus-probe
rm -f /tmp/software-properties-dbus-user-marker /root/software_properties_dbus_root_marker
pkill -f /usr/lib/software-properties/software-properties-dbus
systemctl is-system-running
systemctl --failed --no-legend
```

Post-cleanup `systemctl is-system-running` returned `running`, and no failed units were printed.

## Triage conclusion

This is a reachable root D-Bus service on stock Ubuntu 24.04 Server, so it is a valid local attack surface. The tested LPE paths did not cross the authorization boundary: apt source writes, PPA/source-line operations, keyring operations, apt-cdrom/helper execution, config setters, direct system-bus ownership, and direct module invocation all remained blocked or non-root for the non-sudo users.
