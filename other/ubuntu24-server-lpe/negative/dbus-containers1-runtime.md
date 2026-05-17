# Negative: D-Bus Containers1 runtime socket factory

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server Docker target  
Probe: `pocs/dbus_containers1_probe.sh`  
Log: `logs/dbus-containers1.out`  
Result: no validated uid1001-to-root LPE. `ROOT_PROOF=no`.

## Default proof

Packages:

```text
dbus        1.14.10-4ubuntu4.1
dbus-daemon 1.14.10-4ubuntu4.1
systemd     255.4-1ubuntu8.15
polkitd     124-2ubuntu1.24.04.3
```

The system bus is active and world-connectable:

```text
dbus.service active
dbus.socket active
/run/dbus/system_bus_socket srw-rw-rw- root:root
```

The runtime container-socket directory exists by default through `/usr/lib/tmpfiles.d/dbus.conf:11-13`:

```text
d /run/dbus/containers 0755 messagebus - - -
```

The system bus policy allows messages to the nominal `org.freedesktop.DBus.Containers1` interface at `/usr/share/dbus-1/system.conf:65-73`:

```text
<allow send_destination="org.freedesktop.DBus"
       send_interface="org.freedesktop.DBus.Containers1"/>
```

## Trigger attempts

uid1001 cannot create files or symlinks in the runtime container directory:

```text
/run/dbus/containers drwxr-xr-x messagebus:root
touch /run/dbus/containers/dbus_containers1_touch -> Permission denied
ln -s /root/dbus_containers1_root /run/dbus/containers/dbus_containers1_link -> Permission denied
```

More importantly, this dbus-daemon build does not expose `Containers1` at runtime. The `org.freedesktop.DBus.Interfaces` property lists only:

```text
org.freedesktop.DBus.Monitoring
org.freedesktop.DBus.Debug.Stats
```

Direct calls to expected container-factory methods fail before any socket-path handling:

```text
org.freedesktop.DBus.Containers1.AddServer      -> org.freedesktop.DBus does not understand message AddServer
org.freedesktop.DBus.Containers1.StopListening -> org.freedesktop.DBus does not understand message StopListening
```

No socket, symlink, or root marker was created:

```text
find /run/dbus/containers -> only the directory itself
ls /root/dbus_containers1_root -> No such file or directory
ROOT_PROOF=no
```

## Cleanup

The probe created no persistent target state. Final health was:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend | wc -l -> 0
```

## Why scanners may miss it

Static config looks exploitable: a world-readable system bus, a messagebus-owned runtime socket directory, and policy explicitly allowing sends to `org.freedesktop.DBus.Containers1`. The live daemon does not implement or advertise that interface in this default state, and uid1001 has no direct write access to `/run/dbus/containers`.
