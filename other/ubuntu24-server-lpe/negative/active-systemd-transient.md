# active systemd transient units: negative

Verdict: no local privilege escalation from an active non-admin local TTY user
through systemd PID1 transient unit, manager environment, unit-file, reload, or
reexec APIs.

Artifacts:

```text
pocs/active_systemd_transient_probe.sh
logs/active-systemd-transient.out
```

Default proof:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
systemd 255 (255.4-1ubuntu8.15)
D-Bus Message Bus Daemon 1.14.10
pkaction version 124
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
polkitd 124-2ubuntu1.24.04.3
dbus 1.14.10-4ubuntu4.1
```

Relevant default policy:

```text
/usr/share/polkit-1/actions/org.freedesktop.systemd1.policy
org.freedesktop.systemd1.manage-units:      allow_active=auth_admin_keep
org.freedesktop.systemd1.manage-unit-files: allow_active=auth_admin_keep
org.freedesktop.systemd1.set-environment:   allow_active=auth_admin_keep
org.freedesktop.systemd1.reload-daemon:     allow_active=auth_admin_keep
```

The system bus policy allows normal users to send selected manager mutator
methods to PID1, where polkit makes the authorization decision:

```text
/usr/share/dbus-1/system.d/org.freedesktop.systemd1.conf
StartUnit, StartTransientUnit, SetUnitProperties, Reload, Reexecute,
EnableUnitFiles, LinkUnitFiles, and related mutators are send-allowed.
```

Trigger:

```sh
./pocs/active_systemd_transient_probe.sh ubuntu24-server-lpe-target
```

The PoC logs `selfauth` into `/dev/tty1` and verifies the session is active:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
TTY=tty1
Active=yes
State=active
```

Polkit reports the active user can be challenged but is not authorized without
admin authentication:

```text
CanAuthorize org.freedesktop.systemd1.manage-units -> authorized=0 challenged=1
CanAuthorize org.freedesktop.systemd1.manage-unit-files -> authorized=0 challenged=1
CanAuthorize org.freedesktop.systemd1.set-environment -> authorized=0 challenged=1
CanAuthorize org.freedesktop.systemd1.reload-daemon -> authorized=0 challenged=1
```

Exploit-shaped attempts:

```text
systemd-run basic root marker                    rc=124
systemd-run Environment root marker              rc=124
systemd-run WorkingDirectory                     rc=124
systemd-run RootImage user file                  rc=124
systemd-run User=root                            rc=124

StartTransientUnit ExecStart root marker         Interactive authentication required
StartTransientUnit with Environment              Interactive authentication required
StartTransientUnit with WorkingDirectory         Interactive authentication required
StartTransientUnit with RootImage user file      Interactive authentication required
StartTransientUnit with User=root                Interactive authentication required

SetEnvironment / UnsetEnvironment                AccessDenied at D-Bus policy
LinkUnitFiles user unit                          Interactive authentication required
EnableUnitFiles absolute user path               Interactive authentication required
StartUnit linked unit                            Interactive authentication required
Reload / Reexecute                               Interactive authentication required

systemctl link/enable/start user service         Interactive authentication required
systemctl set-environment                        Access denied
systemctl daemon-reload/reexec/isolate           Interactive authentication required
```

`systemd-run --system` timed out because it entered the interactive
authorization path and never reached root execution in the non-admin session.
The direct D-Bus calls returned explicit authorization failures.

Root proof:

```text
ls: cannot access '/root/active_systemd_transient_root': No such file or directory
ls: cannot access '/tmp/active_systemd_transient_root': No such file or directory

active-systemd-transient* units: 0 loaded
active-systemd-transient* unit files: 0 listed
system_health_after_cleanup: running
```

Dead-end reason:

The interesting boundary is real: unprivileged clients can send PID1 mutator
method calls over the system bus, including `StartTransientUnit` with
attacker-controlled `ExecStart`, `Environment`, `WorkingDirectory`, `RootImage`,
and `User` properties. In the default Server policy, every root execution or
unit-file operation is stopped by `auth_admin_keep`; system manager environment
mutation is additionally blocked by D-Bus policy. No transient unit was created,
no user-controlled unit file was linked into `/etc` or `/run`, and no root
marker was written.

Why scanners may miss this:

Static D-Bus allow rules make these PID1 methods look reachable, and
`StartTransientUnit` directly models root command execution. The decisive
runtime behavior is the combination of system-bus allowlist plus systemd's
polkit checks for active non-admin sessions.

Cleanup:

The PoC removes `/home/selfauth/active-systemd-transient`, restores/removes
`/home/selfauth/.bash_profile`, stops and resets all `active-systemd-transient*`
units, removes any matching unit files from `/etc/systemd/system` and
`/run/systemd/system`, unsets probe manager environment variables, terminates
`selfauth`, restarts `getty@tty1.service`, and confirms the system is `running`
with no root marker.
