# Negative: D-Bus unique-name and polkit subject binding

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS.

Artifacts:

```text
pocs/agent_dbus_subject_unique_probe.sh
logs/agent_dbus_subject_unique_probe.out
```

Result: no uid1001/uid1002-to-root LPE. The root marker `/root/agent_dbus_subject_unique_root` stayed absent, the disposable root unit was not started by either well-known-name or unique-name D-Bus calls, and cleanup left the target `systemctl is-system-running -> running` with `polkit.service` active.

## Scope

This pass avoided the already-exhausted service-specific PackageKit, UDisks, netplan, software-properties, systemd, logind, and activation-helper paths and focused on two remaining semantic questions:

- Can an unprivileged caller confuse polkit by supplying forged `unix-process`, `system-bus-name`, or `unix-session` subjects?
- Can calls sent to root services by unique bus name (`:1.x`) bypass well-known-name D-Bus policy or downstream polkit checks?

## Baseline

Relevant default package versions from the run:

```text
dbus                         1.14.10-4ubuntu4.1
polkitd                      124-2ubuntu1.24.04.3
systemd                      255.4-1ubuntu8.15
packagekit                   1.2.8-2ubuntu1.5
udisks2                      2.10.1-6ubuntu1.3
netplan.io                   1.1.2-8ubuntu1~24.04.2
software-properties-common   0.99.49.4
unattended-upgrades          2.9.1+nmu4ubuntu1
```

The no-session attacker was `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`. The active-seat model user was `uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)`.

## Polkit subject binding

For uid1001, only own-subject checks matched the caller. `org.freedesktop.login1.set-self-linger` was authorized, but admin/package actions returned `authorized=False challenge=True`:

```text
CHECK own-unix-process org.freedesktop.login1.set-self-linger -> authorized=True
CHECK own-unix-process org.freedesktop.systemd1.manage-units -> authorized=False challenge=True
CHECK own-system-bus-name org.freedesktop.packagekit.package-install -> authorized=False challenge=True
```

Forged or cross-identity subjects were rejected before any authorization result:

```text
own-pid-forged-root-uid -> Only trusted callers ... can use CheckAuthorization() for subjects belonging to other identities
pid1-root-unix-process  -> Only trusted callers ... can use CheckAuthorization() for subjects belonging to other identities
systemd-unique-bus-name -> Only trusted callers ... can use CheckAuthorization() for subjects belonging to other identities
systemd-well-known-bus-name -> not a valid unique name
fake-unique-bus-name -> NameHasNoOwner
```

Temporary authorization methods did not create a bypass. No-session process and bus-name subjects returned `Can only handle PolkitUnixSession objects for now`; random revoke-by-id returned `Cannot determine session the caller is in`.

## Unique-name calls

The probe created a root-owned marker unit:

```text
/run/systemd/system/agent-dbus-subject-unique-marker.service
ExecStart=/bin/sh -c 'id > /root/agent_dbus_subject_unique_root'
```

Starting it failed through both the well-known and unique systemd names:

```text
org.freedesktop.systemd1 StartUnit -> Interactive authentication required
:1.1 StartUnit                    -> Interactive authentication required
:1.1 SetEnvironment               -> Access denied
```

Other unique-name checks kept their normal service authorization:

```text
:1.3 logind SetUserLinger(0,true,false) -> Interactive authentication required
:1.1783 netplan Config                 -> Access denied
:1.2104 SoftwareProperties AddSourceFromLine -> com.ubuntu.softwareproperties.applychanges
:1.1659 UDisks2 CanFormat(ext4)        -> (true, ""), read-only capability query
:1.6 unattended-upgrades tree/introspect -> Access denied
```

No marker was created after these calls:

```text
ls: cannot access '/root/agent_dbus_subject_unique_root': No such file or directory
```

## Active selfauth

The active TTY branch produced a real local active session:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
/dev/tty9
XDG_SESSION_ID=130
Seat=seat0
Active=yes
State=active
```

Active-session policy behaved as expected: own process/system-bus-name subjects were authorized for active `yes` actions such as `org.freedesktop.packagekit.system-sources-refresh`, but admin/root actions stayed `challenge=True`:

```text
CHECK own-unix-process org.freedesktop.packagekit.system-sources-refresh -> authorized=True
CHECK own-unix-process org.freedesktop.systemd1.manage-units -> authorized=False challenge=True
CHECK own-system-bus-name org.freedesktop.packagekit.package-install -> authorized=False challenge=True
```

The same forged/cross-identity subject checks still failed for the active user.

One crash-only behavior was reproduced: direct `CheckAuthorization` against the actual active `unix-session` subject disconnected the authority, and systemd recorded:

```text
polkit.service: Main process exited, code=killed, status=6/ABRT
polkit.service: Failed with result 'signal'
```

`polkit.service` restarted automatically, no root marker appeared, and final target health was `running`. This is a denial-of-service/crash lead, not an LPE proof.

## Cleanup

The probe removed:

```text
/tmp/agent-dbus-subject-unique
/run/systemd/system/agent-dbus-subject-unique-marker.service
/root/agent_dbus_subject_unique_root
/home/selfauth/.bash_profile test hook
```

Post-run verification:

```text
systemctl is-system-running -> running
polkit.service -> active
/tmp/agent-dbus-subject-unique -> absent
/run/systemd/system/agent-dbus-subject-unique-marker.service -> absent
/root/agent_dbus_subject_unique_root -> absent
selfauth_profile_absent
```

## Next leads

The only promising follow-up is crash triage for the active `unix-session` `CheckAuthorization` ABRT in `polkitd 124-2ubuntu1.24.04.3`: minimize it outside the broader probe, collect a core/backtrace, and compare against the earlier authentication-agent active-session crash. It currently has no root execution, root write, or authorization bypass.
