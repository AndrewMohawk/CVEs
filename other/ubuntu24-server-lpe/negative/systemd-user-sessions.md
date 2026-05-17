# Negative: systemd-user-sessions nologin helper

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server Docker target. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Artifacts:

```text
pocs/systemd_user_sessions_probe.sh
logs/systemd-user-sessions.out
```

## Result

No uid1001-to-root LPE was validated. `systemd-user-sessions.service` is a real default root helper boundary, but uid1001 cannot control the helper input/output paths, cannot restart the root unit, and direct helper execution stays unprivileged.

## Default proof

Packages from the live target:

```text
systemd                  255.4-1ubuntu8.15
libpam-modules:arm64     1.5.3-5ubuntu5.5
login                    1:4.13+dfsg1-4ubuntu3.2
```

The service is loaded and active-exited by default:

```text
/usr/lib/systemd/system/systemd-user-sessions.service
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/lib/systemd/systemd-user-sessions start
ExecStop=/usr/lib/systemd/systemd-user-sessions stop

LoadState=loaded
ActiveState=active
SubState=exited
UnitFileState=static
User=, Group=   # root
```

The root helper is installed as a normal root-owned executable:

```text
-rwxr-xr-x 755 root:root /usr/lib/systemd/systemd-user-sessions
```

The login stack consumes the nologin state:

```text
/etc/pam.d/login:17 auth requisite pam_nologin.so
```

`/run` and `/etc` are root-owned `0755`, and neither `/run/nologin` nor `/etc/nologin` exists in the default running state.

## Trigger attempts

As uid1001:

```text
printf attacker > /run/nologin
  -> Permission denied

ln -sf /root/systemd_user_sessions_probe_root /run/nologin
  -> Permission denied

systemctl restart systemd-user-sessions.service
  -> Interactive authentication required

/usr/lib/systemd/systemd-user-sessions stop
  -> Failed to create /run/nologin: Permission denied

/usr/lib/systemd/systemd-user-sessions start
  -> exit 0, but no privileged state change
```

A controlled root canary confirmed the helper semantics: root `stop` creates a fixed `/run/nologin` regular file (`0644 root:root`) containing the standard "System is going down" message, and root `start` removes it. That root-created marker is not a root proof; it only documents what the unit would do if root/systemd invoked it.

## Why this is not a finding

The only mutable path is fixed as `/run/nologin`, under root-owned `/run`. A normal local user cannot pre-create, replace, symlink, remove, or race the file through default permissions. Restarting or stopping the root unit is polkit/systemd-admin gated. Running the helper directly as uid1001 does not retain root privilege and fails on the only privileged write.

The default local login consumer (`pam_nologin`) reads the file as policy data; it does not execute attacker-controlled content. No root-owned attacker-selected write, root command execution, group privilege increase, or `uid=0` context was reached from `attacker`.

## Cleanup

The probe ran `systemd-user-sessions start`, removed `/root/systemd_user_sessions_probe_root`, `/tmp/systemd_user_sessions_probe_root`, and temporary stderr files under `/tmp`, reset failed state for `systemd-user-sessions.service`, and verified:

```text
/run/nologin absent
systemctl is-system-running -> running
systemctl --failed --no-legend -> no output
```

## Why scanners may miss it

This boundary is semantic: a root oneshot mutates login admission state while PAM consumes the result. Static unit scanners can flag the root `ExecStop` helper and `/run/nologin` mutation, but exploitability depends on systemd authorization and the root-owned `/run` path preventing normal users from seeding symlink or replacement state.

## Suggested fix

No LPE fix is justified from this target state. Defense in depth would be to keep `/run/nologin` creation as a regular file under root-owned `/run` and retain admin authorization for `systemd-user-sessions.service` restarts/stops.
