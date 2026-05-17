# Negative: Active-seat PackageKit proxy, refresh, offline-update paths

Result: no root LPE found in the active-local-session PackageKit surface on `ubuntu24-server-lpe-target`.

## Scope and target state

Target:

```text
Ubuntu 24.04.4 LTS
packagekit 1.2.8-2ubuntu1.5
polkitd 124-2ubuntu1.24.04.3
PackageKit backend: apt
```

The live target has `attacker` as `uid=1001` and `selfauth` as `uid=1002`:

```text
attacker:x:1001:1001::/home/attacker:/bin/bash
selfauth:x:1002:1002::/home/selfauth:/bin/bash
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

PackageKit policy allows these actions for an active local subject:

```text
org.freedesktop.packagekit.system-sources-refresh: allow_active yes, allow_inactive yes
org.freedesktop.packagekit.system-network-proxy-configure: allow_active yes, allow_inactive auth_admin
org.freedesktop.packagekit.trigger-offline-update: allow_active yes, allow_inactive auth_admin
org.freedesktop.packagekit.clear-offline-update: allow_active yes, allow_inactive auth_admin
```

## Active tty proof

The pty login path was not enough for the auth-sensitive checks: it had no seat and returned `CanAuthorize=3`/interactive, with RefreshCache and SetProxy failing auth. The valid test path was `openvt -c 1 -s -f -w -- /bin/login -f selfauth`, which created an active local seat session:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
/dev/tty1
Id=105
User=1002
Name=selfauth
Seat=seat0
TTY=tty1
Remote=no
Type=tty
Class=user
Active=yes
State=active
```

From that session, PackageKit reported no-auth authorization for the scoped active actions and interactive-only auth for install/update:

```text
system-sources-refresh -> dbus.UInt32(1)
system-network-proxy-configure -> dbus.UInt32(1)
trigger-offline-update -> dbus.UInt32(1)
clear-offline-update -> dbus.UInt32(1)
package-install-untrusted -> dbus.UInt32(3)
system-update -> dbus.UInt32(3)
```

An active `RefreshCache(true)` transaction ran as uid 1002 and succeeded:

```text
TX /75_bcdacbec uid=1002 active=1
CALL /75_bcdacbec.RefreshCache args=(dbus.Boolean(True),)
OK /75_bcdacbec.RefreshCache -> None
SIGNAL /75_bcdacbec Finished exit=1 runtime=2140
PackageKit journal: uid 1002 obtained auth for org.freedesktop.packagekit.system-sources-refresh
PackageKit journal: refresh-cache transaction /75_bcdacbec from uid 1002 finished with success after 2140ms
```

## SetProxy and PAC

`SetProxy` accepts newline-bearing strings from an active local `selfauth` session:

```text
CALL SetProxy newline/http and pac args=('127.0.0.1:38777\nAPT_CONFIG=/tmp/pk-owned.conf\nDPKG_COLORS=always', '', '', '', 'localhost\nexample', 'file:///tmp/pk.pac\nDIRECT')
OK SetProxy newline/http and pac -> None
```

The malicious strings did not become new environment variables or files. They were consumed as proxy text by APT, causing root PackageKit's refresh to attempt the specified loopback proxy and fail normally:

```text
E: http://ports.ubuntu.com/ubuntu-ports noble InRelease is not (yet) available (Could not connect to 127.0.0.1:38777 (127.0.0.1). - connect (111: Connection refused))
```

A live loopback proxy confirmed the root APT backend uses the attacker-selected HTTP proxy for repository fetches:

```text
PROXY_ACCEPT addr=('127.0.0.1', 37488) data=b'GET http://ports.ubuntu.com/ubuntu-ports/dists/noble/InRelease HTTP/1.1\r\nHost: ports.ubuntu.com...
PROXY_ACCEPT addr=('127.0.0.1', 37492) data=b'GET http://ports.ubuntu.com/ubuntu-ports/dists/noble-updates/InRelease HTTP/1.1\r\nHost: ports.ubuntu.com...
PROXY_ACCEPT addr=('127.0.0.1', 37502) data=b'GET http://ports.ubuntu.com/ubuntu-ports/dists/noble-backports/InRelease HTTP/1.1\r\nHost: ports.ubuntu.com...
PROXY_SEEN_COUNT=3
```

APT treated the proxy response as untrusted repository metadata, not code:

```text
E: The repository 'http://ports.ubuntu.com/ubuntu-ports noble-updates InRelease' is no longer signed.
W: Updating from such a repository can't be done securely, and is therefore disabled by default.
```

Source review matches the behavior. `SetProxy` stores values per uid/session in the PackageKit transaction DB (`src/pk-engine.c:440-489`), transactions retrieve that session state (`src/pk-transaction.c:1940-1986`), and the Ubuntu APT backend only maps HTTP/FTP proxy text into process environment variables (`backends/apt/apt-job.cpp:70-89`). PAC is stored but not consumed by the APT backend in this path.

One hardening-relevant quirk was observed: after an active session set a proxy, a later tty1 session with no matching current proxy DB row still hit the old `127.0.0.1:38778` proxy during `RefreshCache`. Restarting `packagekit.service` cleared this stale backend state, and a root `pkcon refresh force` then fetched the normal `ports.ubuntu.com` InRelease files successfully. This is a proxy persistence/DoS footgun, not uid1002-to-root execution.

## Transaction hints and frontend socket

`SetHints` accepts freeform `locale=` content, including newline text, but the value remains one hint value. There was no root file creation for `LD_PRELOAD` or `APT_CONFIG` style substrings.

`frontend-socket` is validated as an existing absolute path:

```text
ERR /75_bcdacbec.SetHints: DBusException: org.freedesktop.PackageKit.Transaction.NotSupported: frontend-socket does not exist
```

With a real Unix socket, `SetHints` succeeded, but `RefreshCache` never connected to it:

```text
socket_exists=True mode=0o775
TX /78_deddacea uid=1002 active=1
SetHints existing frontend socket OK
Finished exit=2 runtime=8268
FRONTEND_SEEN_COUNT=0
```

Source review matches this: `frontend-socket` is only passed into debconf/conffile handling for interactive package install/update code (`backends/apt/apt-job.cpp:1888-1907` and `backends/apt/apt-job.cpp:2568-2584`), not `RefreshCache`.

## Offline update methods

An offline-only active tty1 run with root-seeded state proved `selfauth` can call `ClearResults`, `Trigger("reboot")`, and `Cancel`, but only against fixed PackageKit paths:

```text
uid=1002 tty=/dev/tty1 XDG_SESSION_ID=107
Seat=seat0
TTY=tty1
Active=yes
CanAuthorize trigger-offline-update -> dbus.UInt32(1)
CanAuthorize clear-offline-update -> dbus.UInt32(1)
```

Initial seeded files:

```text
ls: cannot access '/system-update': No such file or directory
ls: cannot access '/var/lib/PackageKit/offline-update-action': No such file or directory
-rw-r--r-- 1 root root  67 May 16 14:05 /var/lib/PackageKit/offline-update-competed
-rw-r--r-- 1 root root 123 May 16 14:05 /var/lib/PackageKit/prepared-update
```

`ClearResults` deleted only the fixed result file:

```text
CALL Offline.ClearResults args=()
OK Offline.ClearResults -> None
ls: cannot access '/var/lib/PackageKit/offline-update-competed': No such file or directory
-rw-r--r-- 1 root root 123 May 16 14:05 /var/lib/PackageKit/prepared-update
```

`Trigger("reboot")` created only the fixed `/system-update` symlink and fixed action file:

```text
CALL Offline.Trigger(reboot) args=('reboot',)
OK Offline.Trigger(reboot) -> None
UpdateTriggered -> dbus.Boolean(True)
TriggerAction -> dbus.String('reboot')
lrwxrwxrwx 1 root root 35 May 16 14:05 /system-update -> /var/lib/PackageKit/prepared-update
-rw-r--r-- 1 root root 6 May 16 14:05 /var/lib/PackageKit/offline-update-action
cat /var/lib/PackageKit/offline-update-action: reboot
```

`Cancel` removed those fixed trigger/action paths and left only the prepared file:

```text
CALL Offline.Cancel args=()
OK Offline.Cancel -> None
UpdateTriggered -> dbus.Boolean(False)
TriggerAction -> dbus.String('unset')
ls: cannot access '/system-update': No such file or directory
ls: cannot access '/var/lib/PackageKit/offline-update-action': No such file or directory
-rw-r--r-- 1 root root 123 May 16 14:05 /var/lib/PackageKit/prepared-update
```

Source review matches this. `Trigger` and `Cancel` are polkit-gated with `trigger-offline-update`, and `ClearResults` is gated with `clear-offline-update` (`src/pk-engine.c:1606-1705`). The root file operations are fixed-path deletes/writes/symlink creation in `pk-offline-private.c:138-160` and `pk-offline-private.c:217-255`.

## Cleanup

Cleaned the target state after testing:

```sh
rm -f /system-update \
  /var/lib/PackageKit/offline-update-action \
  /var/lib/PackageKit/offline-update-competed \
  /var/lib/PackageKit/prepared-update \
  /var/lib/PackageKit/prepared-upgrade \
  /tmp/pkfrontend-active.sock \
  /tmp/pkgkit_active_audit.py \
  /tmp/pkgkit_active_runner.sh
systemctl restart packagekit
pkcon refresh force
```

Cleanup proof:

```text
packagekit.service active
pkcon refresh force fetched normal ports.ubuntu.com InRelease files
ls: cannot access '/system-update': No such file or directory
ls: cannot access '/var/lib/PackageKit/offline-update-action': No such file or directory
ls: cannot access '/var/lib/PackageKit/offline-update-competed': No such file or directory
ls: cannot access '/var/lib/PackageKit/prepared-update': No such file or directory
ls: cannot access '/var/lib/PackageKit/prepared-upgrade': No such file or directory
ls: cannot access '/tmp/pkfrontend-active.sock': No such file or directory
```

## Conclusion

No root LPE was validated. The active local user can:

```text
refresh package metadata as root through PackageKit
set PackageKit's per-session proxy strings, including newlines/PAC strings
force root APT metadata fetches through an attacker-controlled proxy
set transaction hints that affect locale/background/interactive/frontend-socket state
clear/schedule/cancel fixed-path offline-update state
```

Those primitives did not cross into root command execution, arbitrary root file write, package installation, source-list modification, or attacker-controlled offline-update target selection. The only notable hardening issue is stale APT proxy state persisting in the long-lived PackageKit backend until daemon restart.
