# netplan D-Bus deep LPE probe negative result

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server default Docker target.

Result: negative. No LPE/root proof was validated from `io.netplan.Netplan` / `/usr/libexec/netplan/netplan-dbus` as uid1001 `attacker` or uid1002 `selfauth`.

Artifacts:

```
pocs/netplan_dbus_deep_probe.sh
logs/netplan-dbus-deep.out
```

## Default package and active service proof

The probe confirmed Ubuntu 24.04.4 LTS on the Docker target with normal non-sudo users:

```
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
netplan.io              1.1.2-8ubuntu1~24.04.2    ii
libnetplan1:arm64      1.1.2-8ubuntu1~24.04.2    ii
dbus                   1.14.10-4ubuntu4.1         ii
polkitd                124-2ubuntu1.24.04.3       ii
systemd                255.4-1ubuntu8.15          ii
```

The system bus socket was world-connectable, `dbus.service` was active, and `io.netplan.Netplan` was active as root:

```
srw-rw-rw- root:root /run/dbus/system_bus_socket
PID=1528
UID=0
Exe=/usr/libexec/netplan/netplan-dbus
Unit=dbus.service
```

The installed D-Bus service definition is root-run:

```
Name=io.netplan.Netplan
Exec=/usr/libexec/netplan/netplan-dbus
User=root
AssumedAppArmorLabel=unconfined
```

## Authorization result

Both `attacker` and `selfauth` could introspect the object, but every root-affecting method returned `Call failed: Access denied`:

```
io.netplan.Netplan.Info
io.netplan.Netplan.Generate
io.netplan.Netplan.Apply
io.netplan.Netplan.Config
```

A root-created config object exposed `Get`, `Set`, `Try`, `Apply`, and `Cancel`, but both unprivileged users were denied on all of those methods, including path traversal and absolute-origin `Set` attempts:

```
Config.Get:    Call failed: Access denied
Config.Set:    Call failed: Access denied
Config.Try:    Call failed: Access denied
Config.Apply:  Call failed: Access denied
Config.Cancel: Call failed: Access denied
```

The unprivileged state digest over `/etc/netplan`, `/run/netplan`, `/run/systemd/network`, and `/run/NetworkManager` was unchanged:

```
before-unprivileged-triggers=e1e13381e8d0b5e38504328301e4c2dacf9c25a991f562429bdb0b2e1996c5e9
after-unprivileged-root-object-triggers=e1e13381e8d0b5e38504328301e4c2dacf9c25a991f562429bdb0b2e1996c5e9
after-cleanup=e1e13381e8d0b5e38504328301e4c2dacf9c25a991f562429bdb0b2e1996c5e9
```

## Temp path, symlink, race, and helper semantics

Root-control config objects were created under `/run/netplan/config-*` with root-only permissions. `attacker` and `selfauth` could not traverse, write, remove, or place symlinks there:

```
drwx------ root:root /run/netplan
drwx------ root:root /run/netplan/config-9QVGP3
touch .../attacker.yaml: Permission denied
ln .../race.yaml: Permission denied
find: '/run/netplan': Permission denied
```

Root-control `Set` wrote only inside the root-owned temp tree as a `0600` root YAML file:

```
-rw------- root:root /run/netplan/config-9QVGP3/etc/netplan/99-deep.yaml
network:
  version: 2
  ethernets:
    eth999:
      dhcp4: true
```

Root-control origin hints containing `../`, absolute paths, and shell metacharacters did not create external files or command markers. A root-created symlink inside the temp config tree was not followed to `/tmp/netplan-dbus-deep-symlink-target.yaml`.

Environment propagation did not produce a helper path primitive. Unprivileged `UpdateActivationEnvironment` calls on the system bus were denied, unprivileged `PATH`/`DBUS_TEST_NETPLAN_ROOT` Generate calls were denied, and a root-control `Generate` with fake `PATH`/`DBUS_TEST_NETPLAN_ROOT` did not execute fake helpers or create the fake root marker.

Root-control `Try(1)` on an empty config returned true, and `Cancel` removed the created object path and temp directory. Unprivileged `Apply`/`Try` remained denied, so the root reload/apply path was not attacker-reachable.

## Cleanup

The probe removed its `/tmp/netplan-dbus-deep*` files and cancelled its root-created config objects. Cleanup verification showed:

```
/root/netplan_dbus_deep_*: No such file or directory
/tmp/netplan-dbus-deep*: No such file or directory
systemctl is-system-running: running
systemctl --failed: 0 loaded units listed
```

One pre-existing netplan object, `/io/netplan/Netplan/config/OGZIP3`, was present before this probe and was left untouched.

## Conclusion

No stock Ubuntu 24.04 Server default local privilege escalation was found in `io.netplan.Netplan` / `netplan-dbus`. The default active root service is reachable for introspection, but normal non-sudo local users are blocked by method authorization before config writes, helper execution, `Generate`, `Apply`, `Try`, or cleanup operations become reachable.
