# Negative: D-Bus Debug.Stats and Monitoring interfaces

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default Docker target.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`, no sudo/admin groups.

Artifacts:

```text
pocs/dbus_debug_monitor_probe.sh
/Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe/logs/dbus-debug-monitor.out
```

Result: no uid1001-to-root LPE or credential/policy confusion was validated through `org.freedesktop.DBus.Debug.Stats` or `org.freedesktop.DBus.Monitoring`. The root marker `/root/dbus_debug_monitor_root` stayed absent and final target health was `running` with zero failed units.

Rerun:

```sh
bash -n pocs/dbus_debug_monitor_probe.sh
pocs/dbus_debug_monitor_probe.sh ubuntu24-server-lpe-target
```

## Default reachability

The system bus was reachable at `/run/dbus/system_bus_socket`:

```text
srw-rw-rw- 666 root:root socket /run/dbus/system_bus_socket
dbus.service ActiveState=active SubState=running
dbus.socket  ActiveState=active SubState=running
messagebus dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
```

Default package versions:

```text
dbus                         1.14.10-4ubuntu4.1 arm64
dbus-bin                     1.14.10-4ubuntu4.1 arm64
dbus-daemon                  1.14.10-4ubuntu4.1 arm64
dbus-system-bus-common       1.14.10-4ubuntu4.1 all
libdbus-1-3:arm64            1.14.10-4ubuntu4.1 arm64
polkitd                      124-2ubuntu1.24.04.3 arm64
systemd                      255.4-1ubuntu8.15 arm64
```

Both scoped interfaces are present. Root `GetStats`, `GetConnectionStats(:1.1)`, and `GetAllMatchRules` returned successfully, proving `Debug.Stats` is compiled/enabled, not absent.

## Policy boundary

Relevant `/usr/share/dbus-1/system.conf` snippets:

```text
44 <policy context="default">
45   <allow user="*"/>
50   <deny own="*"/>
51   <deny send_type="method_call"/>
66   <allow send_destination="org.freedesktop.DBus"
67          send_interface="org.freedesktop.DBus" />
75   <deny send_destination="org.freedesktop.DBus"
76         send_interface="org.freedesktop.DBus"
77         send_member="UpdateActivationEnvironment"/>
78   <deny send_destination="org.freedesktop.DBus"
79         send_interface="org.freedesktop.DBus.Debug.Stats"/>
90 <!-- root may monitor the system bus. -->
91 <policy user="root">
92   <allow send_destination="org.freedesktop.DBus"
93          send_interface="org.freedesktop.DBus.Monitoring"/>
96 <!-- If the Stats interface was enabled at compile-time, root may use it. -->
99 <policy user="root">
100  <allow send_destination="org.freedesktop.DBus"
101         send_interface="org.freedesktop.DBus.Debug.Stats"/>
```

## uid1001 triggers

Attacker introspection succeeded for both interfaces, but all privileged methods failed:

```text
busctl --system ... Debug.Stats GetStats                    -> Access denied
busctl --system ... Debug.Stats GetConnectionStats s :1.1   -> Access denied
busctl --system ... Debug.Stats GetAllMatchRules            -> Access denied
busctl --system ... Monitoring BecomeMonitor asu 0 0        -> Access denied
dbus-send ... org.freedesktop.DBus.Monitoring.BecomeMonitor -> AccessDenied
```

`dbus-monitor --system` also failed to enable new-style monitoring:

```text
unable to enable new-style monitoring: org.freedesktop.DBus.Error.AccessDenied
```

Plain `dbus-monitor --system` then fell back to ordinary signal matching and saw broadcast signals only. The explicit eavesdrop/method-call attempt was rejected:

```text
Failed to setup match "eavesdrop=true,eavesdrop=true,type=method_call":
rejected attempt to call AddMatch by connection ... with uid 1001
```

## Dead end

The interface surface is default-reachable and root can use it, but the default system bus policy denies uid1001 method calls to `Debug.Stats` and denies `Monitoring.BecomeMonitor` to non-root. The only observed uid1001 visibility was normal broadcast signal receipt, not private method-call monitoring, match-rule disclosure, credential confusion, root execution, or a root write primitive. Cleanup removed the temporary attacker work directory and any monitor process; no marker existed to remove.
