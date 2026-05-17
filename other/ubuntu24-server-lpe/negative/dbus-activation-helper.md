# Negative: D-Bus activation helper and service activation boundaries

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default Docker target.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`, no sudo/admin groups.

Result: no validated uid1001-to-root local privilege escalation in the scoped system/session D-Bus activation, launch-helper, activation-environment, service-file, or user-controlled bus-address lane.

Rerun:

```sh
bash -n pocs/dbus_activation_helper_probe.sh
pocs/dbus_activation_helper_probe.sh ubuntu24-server-lpe-target
```

Evidence log: `logs/dbus-activation-helper.out`.

## Default install and reachability

Default packages on the target:

```text
dbus 1.14.10-4ubuntu4.1
dbus-bin 1.14.10-4ubuntu4.1
dbus-daemon 1.14.10-4ubuntu4.1
dbus-session-bus-common 1.14.10-4ubuntu4.1
dbus-system-bus-common 1.14.10-4ubuntu4.1
libdbus-1-3:arm64 1.14.10-4ubuntu4.1
python3-dbus 1.3.2-5build3
systemd 255.4-1ubuntu8.15
polkitd 124-2ubuntu1.24.04.3
```

The system bus was active via `/usr/lib/systemd/system/dbus.service` line 13:

```text
ExecStart=@/usr/bin/dbus-daemon @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
```

The socket was active via `/usr/lib/systemd/system/dbus.socket` line 9:

```text
ListenStream=/run/dbus/system_bus_socket
```

Default activatable root names included `com.ubuntu.SoftwareProperties`, `org.freedesktop.PackageKit`, `org.freedesktop.fwupd`, `org.freedesktop.hostname1`, `org.freedesktop.locale1`, `org.freedesktop.timedate1`, and `org.freedesktop.timesync1`.

## Boundary evidence

`/usr/lib/dbus-1.0/dbus-daemon-launch-helper` is setuid root but executable only by root/messagebus:

```text
-rwsr-xr-- 4754 root:messagebus /usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

The relevant system bus config is `/usr/share/dbus-1/system.conf`:

```text
24 <standard_system_servicedirs/>
27 <servicehelper>/usr/lib/dbus-1.0/dbus-daemon-launch-helper</servicehelper>
42 <listen>unix:path=/run/dbus/system_bus_socket</listen>
50 <deny own="*"/>
75-77 deny org.freedesktop.DBus.UpdateActivationEnvironment
132 <includedir>system.d</includedir>
134 <includedir>/etc/dbus-1/system.d</includedir>
```

All default `/usr/share/dbus-1/system-services/*.service` files were root-owned `0644`, all `Exec=` paths were absolute, and the root systemd-mediated services resolved to root-owned unit `ExecStart=` paths. Example direct helper activation:

```text
/usr/share/dbus-1/system-services/com.ubuntu.SoftwareProperties.service:3 Exec=/usr/lib/software-properties/software-properties-dbus
/usr/share/dbus-1/system-services/com.ubuntu.SoftwareProperties.service:4 User=root
```

Example systemd-mediated activation:

```text
/usr/share/dbus-1/system-services/org.freedesktop.hostname1.service:10 Exec=/bin/false
/usr/share/dbus-1/system-services/org.freedesktop.hostname1.service:12 SystemdService=dbus-org.freedesktop.hostname1.service
/usr/lib/systemd/system/systemd-hostnamed.service:18 BusName=org.freedesktop.hostname1
/usr/lib/systemd/system/systemd-hostnamed.service:20 ExecStart=/usr/lib/systemd/systemd-hostnamed
```

uid1001 could not write the root service/policy/config roots and could not execute the helper directly:

```text
write /usr/share/dbus-1/system-services/com.example.DbusActivationProbe.service -> Permission denied
write /etc/dbus-1/system.d/com.example.DbusActivationProbe.conf -> Permission denied
write /usr/share/dbus-1/system.conf -> Permission denied
write /var/lib/dbus/machine-id -> Permission denied
/usr/lib/dbus-1.0/dbus-daemon-launch-helper com.ubuntu.SoftwareProperties -> Permission denied
helper_rc=126
```

System bus name ownership was denied for both a reserved default service name and an arbitrary attacker name:

```text
RequestName com.ubuntu.SoftwareProperties -> Access denied
RequestName com.example.AttackerOwned -> Access denied
```

## Trigger tests

The probe planted attacker-controlled `PATH`, `TMPDIR`, fake system-service files under `~/.local/share/dbus-1/system-services`, and fake binaries named after default root service executables.

System bus activation-environment injection failed:

```text
org.freedesktop.DBus.UpdateActivationEnvironment(PATH,TMPDIR,DBUS_ACTIVATION_PROBE,DBUS_SYSTEM_BUS_ADDRESS)
Call failed: Access denied
update_activation_environment_rc=1
```

Direct D-Bus launch-helper activation still started the real root service, not the attacker shadow service or fake PATH binary:

```text
StartServiceByName com.ubuntu.SoftwareProperties -> u 1
root process: python3 /usr/lib/software-properties/software-properties-dbus
DBUS_STARTER_ADDRESS=unix:path=/run/dbus/system_bus_socket
DBUS_STARTER_BUS_TYPE=system
NO_FAKE_PATH_HITS
NO_ROOT_MARKERS
```

Systemd-mediated activation also started the real unit path, not the attacker fake binary:

```text
StartServiceByName org.freedesktop.hostname1 -> u 1
root process: /usr/lib/systemd/systemd-hostnamed
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
NO_FAKE_PATH_HITS
NO_ROOT_MARKERS
```

User-local system service files were ignored by the real system bus:

```text
StartServiceByName com.example.DbusActivationProbe
Call failed: The name com.example.DbusActivationProbe was not provided by any .service files
```

A user-owned bus launched with `/usr/share/dbus-1/system.conf` and `DBUS_SYSTEM_BUS_ADDRESS=unix:path=$HOME/.../custom-system.sock` stayed uid1001 and could not execute the root launch helper:

```text
dbus-daemon --config-file=/usr/share/dbus-1/system.conf --address=unix:path=$HOME/... --fork --nopidfile
uid=1001 attacker dbus-daemon
StartServiceByName com.ubuntu.SoftwareProperties
Error org.freedesktop.DBus.Error.Spawn.ExecFailed: Failed to execute program com.ubuntu.SoftwareProperties: Permission denied
```

Session-bus activation behaved as expected: the attacker could create a user service and update the session activation environment, but the activated process ran only as uid1001:

```text
StartServiceByName com.example.DbusActivationProbe on dbus-run-session
id=uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
DBUS_ACTIVATION_PROBE=session_env
DBUS_STARTER_BUS_TYPE=session
```

## Conclusion

This lane has real trust-boundary shape: a setuid root launch helper, default root D-Bus service files, activatable root names, activation environment semantics, and user-controlled D-Bus addresses. In the default Ubuntu Server state, uid1001 cannot write searched system service directories, cannot own system bus names, cannot update the system bus activation environment, cannot execute the helper directly, cannot cause the real system bus to search user service files, and cannot turn a user-owned fake system bus into root execution. Both forced root activation paths launched the intended absolute root executables and produced no attacker marker.

Cleanup removed the attacker service files, fake binaries, fake buses, markers, and stopped the transient `software-properties-dbus` and `systemd-hostnamed` activations. Final target health was `running` with no failed units shown in the probe log.
