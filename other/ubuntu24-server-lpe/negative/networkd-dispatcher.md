# Negative: networkd-dispatcher and systemd-networkd root event boundary

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS. Tested normal non-sudo users:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

Result: no validated uid1001/uid1002 -> uid0 LPE. No root proof file, root command execution, or root-controlled attacker-influenced write was produced.

Artifacts:

```sh
bash -n pocs/networkd_dispatcher_probe.sh
pocs/networkd_dispatcher_probe.sh ubuntu24-server-lpe-target
logs/networkd-dispatcher.out
```

## Default install and reachability

Installed package versions:

```text
networkd-dispatcher  2.2.4-1
systemd              255.4-1ubuntu8.15
systemd-resolved     255.4-1ubuntu8.15
netplan.io           1.1.2-8ubuntu1~24.04.2
dbus                 1.14.10-4ubuntu4.1
```

`networkd-dispatcher.service` is installed and enabled, but inactive by default. Its unit has:

```text
ConditionPathExistsGlob=|/etc/networkd-dispatcher/*/*
ConditionPathExistsGlob=|/usr/lib/networkd-dispatcher/*/*
ExecStart=/usr/bin/networkd-dispatcher $networkd_dispatcher_args
```

Both condition globs failed because the default hook trees contain only empty state directories. `systemd-networkd.service` and `systemd-networkd.socket` are installed but disabled and inactive in the target. `networkctl` works only from kernel/link fallback and prints `systemd-networkd is not running, output might be incomplete`.

## Blockers

The root script directories are root-owned `0755` and empty:

```text
/etc/networkd-dispatcher/{carrier,degraded,dormant,no-carrier,off,routable}.d
/usr/lib/networkd-dispatcher/{carrier,degraded,dormant,no-carrier,off,routable}.d
```

Both `attacker` and `selfauth` failed to write hooks, `/etc/default/networkd-dispatcher`, `/run/systemd/netif/{links,leases,lldp}`, `/etc/systemd/network`, `/etc/netplan`, and the missing `/run/networkd-dispatcher`, `/run/systemd/network`, `/run/netplan` paths. Service starts for `networkd-dispatcher.service`, `systemd-networkd.service`, and `systemd-networkd.socket` all failed with `Interactive authentication required`.

The dispatcher also rejects attacker-owned script directories through its own permission check. A direct attacker-owned `--script-dir=/tmp/ndisp-attacker-scripts` returned:

```text
invalid permissions on /tmp/ndisp-attacker-scripts/routable.d. expected mode=0o755, uid=0, gid=0; got mode=0o755, uid=1001, gid=1001
scripts_in_attacker_dir=[]
```

No `/tmp/ndisp-direct-marker` was created. Even if a link name were attacker-controlled, hooks are executed with `subprocess.Popen(script, env=script_env)`, not through a shell, and there are no default root hooks to consume `IFACE`, `STATE`, `ADDR`, or `json`.

The `org.freedesktop.network1` D-Bus path is not attacker-activatable in this default state. The system D-Bus service file points to `SystemdService=dbus-org.freedesktop.network1.service`, but that alias unit is missing while `systemd-networkd` is disabled. Both users got `Unit dbus-org.freedesktop.network1.service not found` for object manager calls and `AccessDenied` when trying to own `org.freedesktop.network1`. Fake `PropertiesChanged` signals can be emitted by the user's unique bus name, but the dispatcher subscribes to signals from `org.freedesktop.network1`; the user cannot own that name.

Initial namespace netlink changes are blocked for both users:

```text
ip link add ... type dummy -> RTNETLINK answers: Operation not permitted
ip link set lo down        -> RTNETLINK answers: Operation not permitted
```

Inside `unshare -Urn`, both users could create private dummy interfaces (`ndatt0`, `ndself0`) as namespace-root, but those links did not cross into the target initial namespace:

```text
ns_ip_add_rc=0
root_sysfs_ndatt0=absent
root_sysfs_ndself0=absent
```

The root initial namespace udev monitor, journal slice, and `/run/udev/data` had no matching `ndatt0`/`ndself0` records. Therefore userns/netns link-state changes did not reach root `systemd-networkd`, `networkd-dispatcher`, udev, netplan, DHCP lease/state files, or systemd unit machinery.

## Cleanup and conclusion

The probe only created temporary `/tmp/networkd-dispatcher-probe` and `/tmp/ndisp-attacker-scripts` state inside the container and removed it on exit. Final checks showed:

```text
/root/ndisp*: absent
/tmp/ndisp*: absent
networkd-dispatcher.service: inactive, condition unmet
systemd-networkd.service: inactive, disabled
systemd-networkd.socket: inactive, disabled
container_system_state_after=running
```

This is not an LPE in the stock target: the default root dispatcher has no hook files to execute, normal users cannot plant hooks or start the root services, `systemd-networkd` D-Bus is not reachable, `/run` state and DHCP/lease paths are not writable, and unprivileged namespace-created links do not generate initial-namespace root events.
