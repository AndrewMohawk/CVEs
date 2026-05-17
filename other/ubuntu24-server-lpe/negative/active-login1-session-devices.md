# active login1 session/device methods

Result: no validated root LPE. A passworded, non-sudo, active TTY user can become the controller of its own logind session and call selected session mutators, but the default Ubuntu Server Docker target did not expose a root execution path, an attacker-controlled root write, or a brokered privileged device fd that could be turned into root.

## Target proof

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`.

Package versions from the live target:

```text
dbus                         1.14.10-4ubuntu4.1
kbd                          2.6.4-2ubuntu2
libpam-systemd:arm64         255.4-1ubuntu8.15
login                        1:4.13+dfsg1-4ubuntu3.2
polkitd                      124-2ubuntu1.24.04.3
systemd                      255.4-1ubuntu8.15
util-linux                   2.39.3-9ubuntu6.5
```

Active local session proof from `logs/active-login1-devices-probe.out`:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
/dev/tty1
XDG_SESSION_ID='11'
Seat=seat0
TTY=tty1
Remote=no
Type=tty
Class=user
Active=yes
State=active
```

`selfauth` is a normal user with only its primary group. It exists only to model active-local polkit/logind semantics; it is not in `sudo`, `adm`, `lxd`, `docker`, `input`, `tty`, or other privileged groups.

## Default reachability

`systemd-logind.service` is active by default and owns `org.freedesktop.login1`. The system bus policy allows normal callers to send the relevant session methods to logind:

```text
/usr/share/dbus-1/system.d/org.freedesktop.login1.conf:285-339
  org.freedesktop.login1.Session Terminate, Activate, Lock, Unlock,
  SetIdleHint, SetLockedHint, Kill, TakeControl, ReleaseControl,
  SetType, TakeDevice, ReleaseDevice, PauseDeviceComplete, SetBrightness
```

The service has the capabilities and device allow-list needed to broker tty/vcs/input fds if logind has assigned those devices to a session:

```text
/usr/lib/systemd/system/systemd-logind.service:25-33
  BusName=org.freedesktop.login1
  CapabilityBoundingSet=... CAP_SYS_TTY_CONFIG ...
  DeviceAllow=char-/dev/console rw
  DeviceAllow=char-input rw
  DeviceAllow=char-tty rw
  DeviceAllow=char-vcs rw
  ExecStart=/usr/lib/systemd/systemd-logind
```

The target's relevant device nodes were not directly openable by `selfauth` except for its own tty:

```text
open /dev/tty1 O_RDWR OK
open /dev/tty0 O_RDWR FAIL Permission denied
open /dev/vcs1 O_RDWR FAIL Permission denied
open /dev/vcsa1 O_RDWR FAIL Permission denied
open /dev/input/mice O_RDWR FAIL Permission denied
```

## Trigger

Probe script:

```sh
ubuntu24-server-lpe/pocs/active_login1_devices_probe.sh ubuntu24-server-lpe-target
```

The script creates an active `/dev/tty1` login for `selfauth` with `openvt`, uses `python3-dbus` from that session to call `TakeControl`, `TakeDevice`, `SetLockedHint`, `SetType`, and related methods, records output in `logs/active-login1-devices-probe.out`, and cleans the transient TTY session.

## Observed behavior

Own-session control is reachable:

```text
session_path=/org/freedesktop/login1/session/_311
TakeControl(False) OK
SetLockedHint OK
SetType OK
Activate OK
Lock OK
```

The type/locked-hint changes did not cross a privilege boundary. They only changed logind session metadata for the caller's own session and did not create root-controlled content, start a root unit, or authorize a new admin action.

Logind did not broker fds for the tested tty/vcs/input nodes:

```text
TAKE /dev/tty1 maj=4 min=1
  FAIL System.Error.ENODEV: No such device
TAKE /dev/tty0 maj=4 min=0
  FAIL System.Error.ENODEV: No such device
TAKE /dev/vcs1 maj=7 min=1
  FAIL System.Error.ENODEV: No such device
TAKE /dev/vcsa1 maj=7 min=129
  FAIL System.Error.ENODEV: No such device
TAKE /dev/vcsu1 maj=7 min=65
  FAIL System.Error.ENODEV: No such device
TAKE /dev/input/mice maj=13 min=63
  FAIL System.Error.ENODEV: No such device
```

`TIOCSTI` is enabled for the caller's own tty in this container:

```text
dev.tty.legacy_tiocsti = 1
TIOCSTI stdin OK
```

That is not a root escalation by itself. The tested state has no default root shell on the attacker's controlling tty, no default root consumer of attacker-injected terminal input, and no sudo/su/root-password path available to the normal user.

Root-proof markers remained absent:

```text
/tmp/active-login1-root exists=False
/root/active-login1-root exists=False
```

## Cleanup

The probe performs:

```sh
rm -rf /tmp/active-login1-devices
rm -f /home/selfauth/.bash_profile /home/selfauth/active-login1-devices-probe.py
systemctl start getty@tty1.service
loginctl terminate-user selfauth
```

Final target health after cleanup:

```text
systemctl is-system-running: running
systemctl --failed: 0 loaded units listed
```

## Why scanners may miss the interesting primitive

The interesting behavior is stateful and seat-dependent. A static D-Bus method enumerator sees `TakeControl`, `TakeDevice`, and `SetType` as callable root-service methods, but the reachable effect depends on an active logind session, controller ownership, udev/logind device assignment, and session metadata semantics. In the default target the callable methods remained self-session metadata changes or `ENODEV` fd-broker denials, not a root primitive.

## Suggested triage conclusion

No Ubuntu Security LPE report from this candidate. A useful hardening regression would assert that unprivileged session controllers cannot use `SetType` or `SetLockedHint` to satisfy unrelated polkit/admin decisions, and that `TakeDevice` only returns fds for devices explicitly assigned to that active session.
