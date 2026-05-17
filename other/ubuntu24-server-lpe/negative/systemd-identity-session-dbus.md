# systemd identity/session D-Bus services: no uid1001 -> root LPE

## Verdict

No local privilege escalation was found in the default Ubuntu 24.04 Server
systemd identity/session D-Bus surface. The audited services are default
installed and default reachable, but uid1001 cannot use them to obtain a root
file write primitive with attacker-controlled path/content or root code
execution.

The only successful state-changing operation from `uid=1001(attacker)` was
`org.freedesktop.login1.Manager.SetUserLinger(1001, true, false)`, exposed by
policy as `org.freedesktop.login1.set-self-linger`. It creates the fixed
root-owned marker `/var/lib/systemd/linger/attacker` and can remove it again,
but the file name is resolved from the caller's UID/account, not caller-supplied
path data, and it does not execute attacker-controlled code as root.

## Target proof

Container target:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
Linux fd448ecbc136 6.10.14-linuxkit ... aarch64 GNU/Linux
systemctl is-system-running: running
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Relevant default package versions:

```text
dbus                         1.14.10-4ubuntu4.1
libpam-systemd:arm64         255.4-1ubuntu8.15
polkitd                      124-2ubuntu1.24.04.3
systemd                      255.4-1ubuntu8.15
systemd-sysv                 255.4-1ubuntu8.15
systemd-timesyncd            255.4-1ubuntu8.15
console-setup                1.226ubuntu1
keyboard-configuration       1.226ubuntu1
locales                      2.39-0ubuntu8.7
```

Default reachability:

```text
org.freedesktop.login1       pid 273, root, systemd-logind.service
org.freedesktop.systemd1     pid 1, root, init.scope
org.freedesktop.hostname1    activatable
org.freedesktop.locale1      activatable
org.freedesktop.timedate1    activatable
org.freedesktop.PolicyKit1   polkitd
```

`systemd-logind.service` is active by default. `systemd-hostnamed.service`,
`systemd-timedated.service`, and `systemd-localed.service` are static D-Bus
activated root services.

## Code/config paths checked

Service definitions:

- `/usr/lib/systemd/system/systemd-logind.service:24-58` owns `org.freedesktop.login1`, runs `/usr/lib/systemd/systemd-logind`, and grants only fixed `ReadWritePaths=/etc /run` plus `StateDirectory=systemd/linger`.
- `/usr/lib/systemd/system/systemd-hostnamed.service:17-35` owns `org.freedesktop.hostname1`, runs `/usr/lib/systemd/systemd-hostnamed`, and can write `/etc` and `/run/systemd`.
- `/usr/lib/systemd/system/systemd-timedated.service:16-35` owns `org.freedesktop.timedate1`, runs `/usr/lib/systemd/systemd-timedated`, and can write `/etc`.
- `/usr/lib/systemd/system/systemd-localed.service:17-37` owns `org.freedesktop.locale1`, runs `/usr/lib/systemd/systemd-localed`, and can write `/etc` and `/usr/lib/locale`.
- `/usr/share/dbus-1/system-services/org.freedesktop.{login1,hostname1,timedate1,locale1,systemd1}.service` all use `Exec=/bin/false` with systemd activation, so uid1001 cannot replace an executable path through D-Bus service activation.

D-Bus/polkit boundaries:

- `/usr/share/dbus-1/system.d/org.freedesktop.login1.conf:24-83` allows uid1001 to send `List*`, `Inhibit`, and `SetUserLinger`; `:120-259` allows shutdown/reboot/session methods to reach logind, where polkit enforces authorization.
- `/usr/share/polkit-1/actions/org.freedesktop.login1.policy:127-143` allows self-linger but requires `auth_admin_keep` for other users.
- `/usr/share/polkit-1/actions/org.freedesktop.login1.policy:168-229` marks power/reboot actions as `allow_active=yes` but `allow_any/allow_inactive=auth_admin_keep`.
- `/usr/share/polkit-1/actions/org.freedesktop.hostname1.policy:19-46`, `org.freedesktop.timedate1.policy:21-58`, and `org.freedesktop.locale1.policy:21-38` require `auth_admin_keep` for state-changing identity/time/locale writes.
- `/usr/share/polkit-1/actions/org.freedesktop.systemd1.policy:32-59` requires admin auth for unit management and manager environment changes.
- `/usr/share/dbus-1/system.d/org.freedesktop.systemd1.conf:203-359` lets callers reach mutating manager methods, but they are polkit-gated by systemd.

Root-owned state paths are not attacker-writable:

```text
root:root 644 /etc/hostname
root:root 644 /etc/locale.conf
root:root 644 /etc/default/keyboard
root:root 644 /etc/systemd/timesyncd.conf
root:root 755 /var/lib/systemd/linger
root:root 755 /run/systemd/users
root:root 755 /run/systemd/sessions
```

## Unprivileged trigger results

Commands were run with `runuser -u attacker -- ...` from a plain non-sudo shell.

Read-only/default methods work:

```sh
busctl --system call org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1 Describe
busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager ListSessions
busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
```

Observed output included `ListSessions -> a(susso) 0` and
`CanPowerOff/CanReboot/CanHalt -> s "challenge"`, proving the Docker attacker
has no active logind seat that can exercise the `allow_active=yes` power path.

No-auth inhibitors are reachable but only create held file descriptors:

```sh
busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager Inhibit ssss shutdown attacker audit-delay delay
busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager Inhibit ssss idle attacker audit-idle block
```

Both returned `h 4`. `shutdown/block` and `handle-power-key/block` returned
`Call failed: Access denied`. The successful cases are availability controls,
not root writes or root execution.

Power/reboot/session mutation did not produce a usable primitive:

```text
Reboot(false):                Interactive authentication required
PowerOff(false):              Interactive authentication required
ScheduleShutdown(reboot,...): Interactive authentication required
SetRebootParameter("codex"):  Reboot parameter not supported in containers
SetWallMessage(..., false):   Interactive authentication required
LockSessions/UnlockSessions:  Interactive authentication required
ActivateSession("c999"):      No session 'c999' known
```

Self-linger is reachable but does not cross into root execution:

```sh
runuser -u attacker -- busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager SetUserLinger ubb 1001 true false
ls -l /var/lib/systemd/linger/attacker
runuser -u attacker -- busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager SetUserLinger ubb 0 true false
runuser -u attacker -- busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager SetUserLinger ubb 1001 false false
```

Observed:

```text
-rw-r--r-- 1 root root 0 ... /var/lib/systemd/linger/attacker
SetUserLinger(0,true,false): Interactive authentication required
```

In this Docker target, enabling linger did not even start `user@1001.service`;
attempts to talk to `/run/user/1001/bus` failed with `No such file or
directory`. Even if a user manager starts on a full booted host, it runs as
UID 1001, not root.

Identity/time/locale root writes are denied:

```text
hostname1 SetHostname/SetStaticHostname/SetPrettyHostname/SetIconName/SetChassis/SetDeployment/SetLocation:
  Interactive authentication required

timedate1 SetTimezone/SetLocalRTC/SetNTP/SetTime(current_time):
  Interactive authentication required

locale1 SetLocale(LANG=C)/SetX11Keyboard(de)/SetVConsoleKeyboard(...):
  Interactive authentication required
```

State stayed unchanged:

```text
hostnamectl --static: fd448ecbc136
/etc/locale.conf: LANG=C.UTF-8
/etc/default/keyboard: XKBLAYOUT="us", XKBMODEL="pc105"
timedatectl: Etc/UTC, LocalRTC=no, NTP=no
```

System manager root execution/environment attempts are denied:

```text
systemctl start cron.service --no-ask-password:
  Interactive authentication required
systemd-run --system --wait --collect /usr/bin/id:
  Interactive authentication required
systemctl --system set-environment CODEX_DBUS_TEST=1:
  Access denied
busctl org.freedesktop.systemd1.Manager.SetEnvironment:
  Access denied
org.freedesktop.DBus.UpdateActivationEnvironment:
  Access denied
```

No `CODEX_*` variables remained in the system manager environment.

## Cleanup

Cleanup performed:

```sh
loginctl disable-linger attacker || true
systemctl stop user@1001.service || true
busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CancelScheduledShutdown || true
```

Final verification:

```text
systemctl is-system-running: running
/var/lib/systemd/linger/attacker: absent
/var/lib/systemd/linger/root: absent
ScheduledShutdown: (st) "" 18446744073709551615
attacker identity: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

## Why scanners may miss the interesting parts

The only non-obvious boundary here is semantic rather than syntactic:
`SetUserLinger` is D-Bus-callable by everyone, but logind maps the request to
the caller's own UID and a fixed root-owned marker path. Similarly, some
shutdown/reboot actions are `allow_active=yes`, but a non-sudo Docker shell has
no active local seat and receives `challenge`/auth failures. A generic SAST or
method enumerator can flag these as "root service write methods reachable by
users" without proving attacker-controlled path/content or root execution.

## Suggested hardening/regression tests

- Keep `hostname1`, `timedate1`, `locale1`, and `systemd1` mutators at
  `auth_admin_keep`; do not relax them to `allow_active=yes` on Server.
- Add regression tests that `Properties.Set` cannot bypass login1
  `SetWallMessage`/`EnableWallMessages` authorization.
- Add regression tests that uid1001 can only toggle its own linger marker and
  cannot create `/var/lib/systemd/linger/root` or arbitrary linger filenames.
- Keep system bus `UpdateActivationEnvironment` denied for unprivileged users;
  these systemd D-Bus services are root-activated and should not inherit
  attacker-controlled activation environment.

No `notes/` or `pocs/` finding artifact was created because there is no
validated uid1001-to-root privilege escalation in this slice.
