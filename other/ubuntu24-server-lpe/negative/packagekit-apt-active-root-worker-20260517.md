# Negative: PackageKit/APT active-user root-worker paths

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default Docker/systemd target.

Result: no validated local privilege escalation. An active non-admin local user can drive root PackageKit/APT refresh work, set proxy strings that reach APT, set newline-bearing transaction hints, parse/download-only local `.deb` metadata, and schedule fixed-path offline updates when a prepared update already exists. In the tested default state, those primitives did not become root command execution, root file write, source-list mutation, maintainer-script execution, or attacker-controlled offline-update target selection.

Artifacts:

```text
pocs/packagekit_apt_active_root_worker_probe.sh
logs/packagekit-apt-active-root-worker-20260517.out
```

## Default proof

Relevant stock packages:

```text
apt 2.8.3
dbus 1.14.10-4ubuntu4.1
debconf 1.5.86ubuntu1
dpkg 1.22.6ubuntu6.6
packagekit 1.2.8-2ubuntu1.5
packagekit-tools 1.2.8-2ubuntu1.5
libpackagekit-glib2-18 1.2.8-2ubuntu1.5
polkitd 124-2ubuntu1.24.04.3
systemd 255.4-1ubuntu8.15
```

PackageKit is a default root D-Bus service:

```ini
Type=dbus
BusName=org.freedesktop.PackageKit
User=root
ExecStart=/usr/libexec/packagekitd
```

The active test subject was a real local tty session:

```text
uid=1002 gid=1002 tty=/dev/tty8
Seat=seat0
Active=yes
```

From that active session:

```text
system-sources-refresh -> 1
system-network-proxy-configure -> 1
trigger-offline-update -> 1
clear-offline-update -> 1
trigger-offline-upgrade -> 3
package-install-untrusted -> 3
system-update -> 3
system-sources-configure -> 3
```

## SetProxy, SetHints, and APT helpers

`SetProxy` accepted newline-bearing HTTP/HTTPS, `no_proxy`, and PAC strings. The root-owned PackageKit database is mode `0644`; the active user could read the proxy row after setting it:

```text
DB_ROW proxy (...,
  'http://127.0.0.1:35141/\nAPT_CONFIG=/tmp/pkapt-worker.conf\nPKAPT_PROXY_SPLIT=1\nAcquire::http::Proxy::ports.ubuntu.com=...',
  ...,
  'localhost\nPKAPT_NO_PROXY_SPLIT=1',
  'file:///tmp/packagekit-apt-active-root-worker/proxy.pac\nPKAPT_PAC_SPLIT=1',
  1002,
  '/org/freedesktop/logind/session-64')
```

`RefreshCache(true)` used that proxy as root APT state and fetched all four default Ubuntu repository `InRelease` files from the attacker listener:

```text
PROXY_COUNT count=4 lines=[
  noble/InRelease,
  noble-updates/InRelease,
  noble-backports/InRelease,
  noble-security/InRelease]
```

APT treated the fake proxy response as unsigned repository metadata:

```text
Clearsigned file isn't valid, got 'NOSPLIT'
The repository ... is no longer signed.
```

The root process monitor captured APT method children with attacker strings in single NUL-separated environment entries:

```text
cmd='/usr/lib/apt/methods/http ' uid=0
ENV_ITEM b'LANG=C.UTF-8\nAPT_CONFIG=/tmp/pkapt-worker.conf\nPYTHONPATH=/tmp/packagekit-apt-active-root-worker/py\nPKAPT_LOCALE_SPLIT=1'
ENV_ITEM b'LANGUAGE=C.UTF-8\nAPT_CONFIG=/tmp/pkapt-worker.conf\nPYTHONPATH=/tmp/packagekit-apt-active-root-worker/py\nPKAPT_LOCALE_SPLIT=1'
ENV_ITEM b'http_proxy=http://127.0.0.1:35141/\nAPT_CONFIG=/tmp/pkapt-worker.conf\nPKAPT_PROXY_SPLIT=1\nAcquire::http::Proxy::ports.ubuntu.com=...'
SEPARATE_FLAGS
```

The same appeared in the `_apt` sandboxed method child (`uid=42`). No separate `APT_CONFIG`, `PYTHONPATH`, `Acquire::*`, or `PKAPT_*` environment variable was created, and the malicious APT hook file did not run.

`SetHints` also accepted:

```text
locale=C.UTF-8\nAPT_CONFIG=/tmp/pkapt-worker.conf\nPYTHONPATH=/tmp/packagekit-apt-active-root-worker/py\nPKAPT_LOCALE_SPLIT=1
frontend-socket=/tmp/packagekit-apt-active-root-worker/frontend\nPKAPT_FRONTEND_SPLIT=1
```

`RefreshCache`, `GetUpdates`, and local download-only install did not connect to the frontend socket:

```text
FRONTEND_COUNT count=0 events=[]
```

## Transactions

`GetUpdates` completed successfully but returned no update package IDs in the current default cache, so no `UpdatePackages(ONLY_DOWNLOAD, ...)` package download path was available in this run:

```text
TX_DONE get-updates done=True packages=[] package_count=0
NO_UPDATE_PACKAGES_FOR_ONLY_DOWNLOAD
```

`InstallFiles(ONLY_DOWNLOAD, [attacker_deb])` parsed the local package and emitted package progress signals, but did not run the package `postinst`:

```text
TX_SIGNAL installfiles-only-download-local Package (... 'packagekit-apt-active-root-worker;1.0;all;+manual:local' ...)
TX_SIGNAL installfiles-only-download-local Finished (1, 4316)
```

The real local install stayed behind PackageKit/polkit authorization:

```text
TX_SIGNAL installfiles-real-local ErrorCode (48, 'Failed to obtain authentication.')
```

Root proof markers stayed absent:

```text
/root/packagekit_apt_active_root_worker_root.pre absent
/root/packagekit_apt_active_root_worker_root.post absent
/root/packagekit_apt_active_root_worker_root.dpkgpre absent
/root/packagekit_apt_active_root_worker_root.dpkgpost absent
/root/packagekit_apt_active_root_worker_root.postinst absent
/root/packagekit_apt_active_root_worker_root.pythonpath absent
```

## Offline Trigger

Default state had no prepared update:

```text
UpdatePrepared=False
GetPrepared -> []
Trigger("reboot") -> Prepared update not found: /var/lib/PackageKit/prepared-update
```

No offline files were created in default state:

```text
/system-update missing
/var/lib/PackageKit/offline-update-action missing
/var/lib/PackageKit/prepared-update missing
```

The probe then root-seeded `/var/lib/PackageKit/prepared-update` only to verify fixed-path trigger semantics. This was not a default-state exploit precondition. With that seed, active `selfauth` could call `Trigger`, but unsupported action strings were rejected:

```text
Trigger("reboot\nAPT_CONFIG=/tmp/pkapt-worker.conf\nPKAPT_OFFLINE_SPLIT=1") -> action ... unsupported
Trigger("power-off/../../root") -> action ... unsupported
Trigger("") -> action unsupported
```

Valid actions created only fixed paths and fixed content:

```text
Trigger("reboot"):
  /system-update -> /var/lib/PackageKit/prepared-update
  /var/lib/PackageKit/offline-update-action = "reboot"

Trigger("power-off"):
  /system-update -> /var/lib/PackageKit/prepared-update
  /var/lib/PackageKit/offline-update-action = "power-off"
```

`TriggerUpgrade("reboot")` was not active-user reachable:

```text
TriggerUpgrade -> failed to obtain auth
```

## Cleanup Proof

Post-run target cleanup verified:

```text
ABSENT /tmp/packagekit-apt-active-root-worker
ABSENT /tmp/pkapt-worker.conf
ABSENT /root/packagekit_apt_active_root_worker_root*
ABSENT /system-update
ABSENT /var/lib/PackageKit/offline-update-action
ABSENT /var/lib/PackageKit/prepared-update
ABSENT /var/lib/PackageKit/prepared-upgrade
proxy_rows []
systemctl is-system-running -> running
```

## Verdict

Negative for LPE. The active-user root-worker boundary is real: `selfauth` can make root PackageKit/APT perform repository refresh through an attacker proxy and can pass newline-bearing locale/proxy/frontend strings into root-owned transaction state. In stock Ubuntu 24.04 Server, those strings remained data, APT signature checks blocked fake repository metadata, APT config/hook injection did not split out of single environment values, unauthenticated local `.deb` handling did not execute maintainer scripts, and offline trigger paths stayed fixed and action-filtered.

Hardening items worth keeping:

```text
- Reject or normalize control characters in SetProxy values and SetHints locale/frontend-socket values.
- Avoid storing proxy credentials or control-character payloads in a world-readable transactions.db.
- Add regression tests proving empty SetProxy clears backend proxy state before the next transaction.
- Keep offline Trigger action filtering and fixed /system-update target tests covered.
```
