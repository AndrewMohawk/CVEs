# Negative: polkit authentication-agent subject spoofing

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server Docker target  
Probe: `pocs/polkit_agent_subject_spoof_probe.sh`  
Log: `logs/polkit-agent-subject-spoof.out`  
Result: no validated uid1001-to-root LPE. `ROOT_PROOF=no`.

## Default proof

Packages and users:

```text
polkitd                    124-2ubuntu1.24.04.3
libpolkit-agent-1-0:arm64  124-2ubuntu1.24.04.3
libpolkit-gobject-1-0      124-2ubuntu1.24.04.3
dbus                       1.14.10-4ubuntu4.1
systemd                    255.4-1ubuntu8.15
packagekit                 1.2.8-2ubuntu1.5
attacker: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
selfauth: uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
ubuntu: uid=1000(ubuntu) groups include sudo, but account is locked
```

The default polkit authority exposes the authentication-agent subject methods:

```text
RegisterAuthenticationAgent            (sa{sv})ss
RegisterAuthenticationAgentWithOptions (sa{sv})ssa{sv}
UnregisterAuthenticationAgent          (sa{sv})s
CheckAuthorization                     (sa{sv})sa{ss}us
CancelCheckAuthorization               s
```

The focused target actions are default admin-auth gated:

```text
org.freedesktop.systemd1.manage-units        any=auth_admin inactive=auth_admin active=auth_admin_keep
org.freedesktop.systemd1.manage-unit-files   any=auth_admin inactive=auth_admin active=auth_admin_keep
org.freedesktop.packagekit.package-install   any=auth_admin inactive=auth_admin active=auth_admin_keep
```

## Trigger attempts

The probe created live same-uid, cross-uid, root, and locked-admin subject candidates and tried to register custom authentication agents for them from uid1001 and from an active `selfauth` tty session.

uid1001 could register an agent only for its own process or another same-uid `attacker` process:

```text
REGISTER_OK label=attacker:own-process
REGISTER_OK label=attacker:same-uid-other-attacker-pid
REGISTER_FAIL label=attacker:other-normal-selfauth-pid error=User of caller and user of subject differs.
REGISTER_FAIL label=attacker:spoof-root-pid1 error=User of caller and user of subject differs.
REGISTER_FAIL label=attacker:spoof-root-sleeper error=User of caller and user of subject differs.
REGISTER_FAIL label=attacker:spoof-ubuntu-admin-sleeper error=User of caller and user of subject differs.
REGISTER_FAIL label=attacker:own-pid-forged-root-uid error=User of caller and user of subject differs.
REGISTER_FAIL label=attacker:fake-session-c1 error=Cannot determine session the caller is in
```

The active `selfauth` session showed the same cross-user boundary:

```text
REGISTER_OK label=selfauth-active:own-process
REGISTER_OK label=selfauth-active:same-uid-other-selfauth-pid
REGISTER_FAIL label=selfauth-active:other-normal-attacker-pid error=User of caller and user of subject differs.
REGISTER_FAIL label=selfauth-active:spoof-root-pid1 error=User of caller and user of subject differs.
REGISTER_FAIL label=selfauth-active:spoof-root-sleeper error=User of caller and user of subject differs.
REGISTER_FAIL label=selfauth-active:spoof-ubuntu-admin-sleeper error=User of caller and user of subject differs.
REGISTER_FAIL label=selfauth-active:own-pid-forged-root-uid error=User of caller and user of subject differs.
REGISTER_FAIL label=selfauth-active:fake-session-c1 error=Passed session and the session the caller is in differs.
```

For auth-admin checks, the probe observed cookies and attempted helper responses with `selfauth`'s known password and the locked `ubuntu` admin identity. Both failed:

```text
HELPER tag=live-selfauth-password user=selfauth rc=1 ... The authenticated identity is wrong
HELPER tag=live-ubuntu-locked-with-selfauth-password user=ubuntu rc=1 ... pam_authenticate failed
HELPER tag=post-cancel-reuse-selfauth user=selfauth rc=1 ... No session for cookie
HELPER tag=post-cancel-reuse-ubuntu-locked user=ubuntu rc=1 ... pam_authenticate failed
```

No root unit was started:

```text
ROOT_PROOF=no
ls: cannot access '/root/polkit_agent_subject_spoof_root': No such file or directory
polkit-agent-subject-spoof.service: inactive (dead)
```

## Crash-only behavior

One `RegisterAuthenticationAgent`/auth-check sequence against the actual active session caused `polkitd` to abort:

```text
polkit.service: Main process exited, code=killed, status=6/ABRT
polkit.service: Failed with result 'signal'
```

That is not counted as LPE. The crash disconnected the auth check without starting the root marker unit or creating `/root/polkit_agent_subject_spoof_root`. The service was restarted/reset during cleanup and the final target state returned to `systemctl is-system-running -> running`.

## Cleanup

The probe removed `/run/systemd/system/polkit-agent-subject-spoof.service`, killed owned sleeper/agent processes, removed `/tmp/polkit-agent-subject-spoof`, restarted/reset `polkit.service` as needed, and verified the root marker was absent.

## Why scanners may miss it

Static D-Bus/polkit enumeration shows a powerful-looking local interface: unprivileged callers can register authentication agents for subject objects and receive auth cookies for admin actions. The exploitable boundary is semantic: polkit binds the agent subject to the caller's real uid/session, rejects cross-user/root/admin subject spoofing, and invalidates cookies after cancellation or failed sessions.
