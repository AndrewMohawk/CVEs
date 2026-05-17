# Negative: PackageKit active-session proxy/config injection

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default Docker/systemd target.

Result: no validated local privilege escalation. The active local `selfauth` user can set PackageKit proxy strings used by the root PackageKit/APT refresh path, including newlines, shell-ish text, PAC text, and proxy credentials. The tested values stayed data: the attacker `APT_CONFIG` and `Acquire::*` strings did not split into independent environment/config entries, the fake proxy responses were treated as unsigned repository metadata, `frontend-socket` was not used by refresh/get-updates/update-download paths, and the real update path stayed authorization-blocked.

Artifacts:

```text
pocs/packagekit_active_proxy_injection_probe.sh
logs/packagekit-active-proxy-injection.out
```

## Default proof

Installed default packages:

```text
apt                       2.8.3
dbus                      1.14.10-4ubuntu4.1
libpackagekit-glib2-18    1.2.8-2ubuntu1.5
packagekit                1.2.8-2ubuntu1.5
packagekit-tools          1.2.8-2ubuntu1.5
polkitd                   124-2ubuntu1.24.04.3
systemd                   255.4-1ubuntu8.15
```

`apt-cache show packagekit` includes `Task: ... server, ubuntu-server-raspi ...`, and the default service is D-Bus activatable root code:

```text
/usr/lib/systemd/system/packagekit.service
Type=dbus
BusName=org.freedesktop.PackageKit
User=root
ExecStart=/usr/libexec/packagekitd
```

Policy/interface paths:

```text
/usr/share/polkit-1/actions/org.freedesktop.packagekit.policy:1009-1089
  system-sources-refresh allow_inactive=yes allow_active=yes
/usr/share/polkit-1/actions/org.freedesktop.packagekit.policy:1091-1168
  system-network-proxy-configure is active-user reachable
/usr/share/dbus-1/interfaces/org.freedesktop.PackageKit.xml:378
  SetProxy(proxy_http, proxy_https, proxy_ftp, proxy_socks, no_proxy, pac)
/usr/share/dbus-1/interfaces/org.freedesktop.PackageKit.Transaction.xml:887
  RefreshCache(force)
/usr/share/dbus-1/interfaces/org.freedesktop.PackageKit.Transaction.xml:665
  GetUpdates(filter)
/usr/share/dbus-1/interfaces/org.freedesktop.PackageKit.Transaction.xml:1424
  UpdatePackages(transaction_flags, package_ids)
```

The active test shell was a real tty login:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
/dev/tty1
State: active
CAN_AUTHORIZE org.freedesktop.packagekit.system-network-proxy-configure -> 1
CAN_AUTHORIZE org.freedesktop.packagekit.system-sources-refresh -> 1
CAN_AUTHORIZE org.freedesktop.packagekit.system-update -> 3
CAN_AUTHORIZE org.freedesktop.packagekit.package-install -> 3
```

## Trigger

Run:

```sh
cd /Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe
bash -n pocs/packagekit_active_proxy_injection_probe.sh
./pocs/packagekit_active_proxy_injection_probe.sh ubuntu24-server-lpe-target
```

The probe used active `selfauth` to call:

```text
SetProxy("127.0.0.1:<port>\nAPT_CONFIG=/tmp/packagekit-active-proxy-injection/evil-apt.conf\nPKPROBE_NEWLINE_SPLIT=1\nAcquire::http::Proxy::ports.ubuntu.com ...", ...)
RefreshCache(true)
SetProxy("pkuser:pkpass@127.0.0.1:<port>", ...)
RefreshCache(true)
SetProxy("", "", "", "", "", "")
RefreshCache(true)
SetHints(["frontend-socket=/tmp/...sock", "interactive=true"])
RefreshCache(false), GetUpdates(0), UpdatePackages(ONLY_DOWNLOAD,...), UpdatePackages(0,...)
```

## Observed behavior

The root APT refresh path used the attacker proxy and fetched the four default Ubuntu ports repositories from the fake proxy:

```text
PROXY_COUNT newline-config=4 acquire-alt=0
PROXY_HIT label=newline-config ... noble/InRelease
PROXY_HIT label=newline-config ... noble-updates/InRelease
PROXY_HIT label=newline-config ... noble-backports/InRelease
PROXY_HIT label=newline-config ... noble-security/InRelease
```

The root-side `/proc` monitor saw the malicious text inside one proxy environment value, not as separate attacker-controlled `APT_CONFIG` or `Acquire::*` entries:

```text
ENV_ITEM b'http_proxy=http://127.0.0.1:34061\nAPT_CONFIG=/tmp/packagekit-active-proxy-injection/evil-apt.conf\nPKPROBE_NEWLINE_SPLIT=1\nAcquire::http::Proxy::ports.ubuntu.com ...'
SEPARATE_APT_CONFIG=0 SEPARATE_ACQUIRE=0
```

Later `APT_CONFIG=/tmp/apt.conf.*` snapshots were APT's own transient files under `_apt`/apt-key verification, not the attacker `evil-apt.conf`.

The fake proxy response body contained APT config and hook text, but APT treated it as invalid/unsigned repository metadata:

```text
Clearsigned file isn't valid, got 'NOSPLIT'
The repository ... is no longer signed.
```

User-info proxy credentials were forwarded to the proxy as proxy credentials:

```text
AUTH_PROXY_COUNT=4
AUTH_PROXY_HEADERS=['Proxy-Authorization: Basic cGt1c2VyOnBrcGFzcw==', ...]
```

One stale-state bug was reproduced: after `SetProxy("", "", "", "", "", "")` returned success, the next refresh still used the previous credentialed proxy:

```text
SET_PROXY_OK label=clear-empty
STALE_AFTER_CLEAR_PROXY_HITS=4
```

That is a default-reachable proxy persistence/privacy/DoS issue, but it did not become root execution or root file write.

The frontend socket was never contacted:

```text
FRONTEND_COUNT refresh-newline=0
FRONTEND_COUNT refresh-clear=0
FRONTEND_COUNT getupdates=0
FRONTEND_COUNT update-only-download=0
FRONTEND_COUNT update-real=0
```

The real update path remained blocked:

```text
TX_SIGNAL label=frontend-update-real signal=ErrorCode data=(48, 'Failed to obtain authentication.')
```

Root proof stayed negative:

```text
NO_ROOT_PAYLOAD_MARKER
NO_ROOT_PAYLOAD_MARKER_POST
NO_TMP_WORKDIR_POST
systemctl is-system-running -> running
systemctl --failed --no-legend -> 0 lines
```

## Cleanup

The probe performs this cleanup:

```sh
loginctl terminate-user selfauth || true
systemctl start getty@tty1.service || true
rm -f /home/selfauth/packagekit_active_proxy_injection_runner.sh
rm -f /home/selfauth/.bash_profile
rm -f /root/packagekit_active_proxy_injection_root
rm -rf /tmp/packagekit-active-proxy-injection
systemctl restart packagekit.service || true
```

Post-run verification:

```text
ABSENT /tmp/packagekit-active-proxy-injection
ABSENT /home/selfauth/packagekit_active_proxy_injection_runner.sh
ABSENT /root/packagekit_active_proxy_injection_root
```

## Verdict

Negative for LPE. The reachable primitive is real and worth hardening: an active non-sudo user can make root PackageKit/APT and some root APT hook children inherit attacker-supplied proxy environment values, including embedded newlines and proxy credentials. In the tested default state, those values remained environment data, fake repository responses remained data, root config roots were not writable, and no root marker was created.

## Why scanners may miss it

This needs a real active logind tty subject, not just a pseudo-tty shell. The interesting boundary also spans D-Bus authorization, PackageKit proxy state, APT backend environment construction, APT method sandbox users, apt-key transient config, and root post-invoke hook inheritance. A fuzzer can see `SetProxy` accepts strings, but the exploitability question depends on whether those strings split into config/environment entries or reach shell/dpkg/debconf execution.

## Suggested fixes

- Reject or normalize control characters, especially `\r` and `\n`, in `SetProxy` arguments before they reach any backend.
- Treat empty `SetProxy` values as an explicit backend proxy reset and add a regression test proving the next transaction does not reuse stale proxy credentials.
- Prefer scoped APT `Acquire::*` configuration objects over process-wide proxy environment where possible.
- Sanitize proxy environment variables before invoking unrelated root APT post-invoke helpers.
- Keep `frontend-socket` ignored for refresh/query/download-only roles and covered by regression tests.
