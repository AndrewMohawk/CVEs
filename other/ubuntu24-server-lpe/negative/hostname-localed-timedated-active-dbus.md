# hostname/localed/timedated/timesync/network D-Bus negative

Date: 2026-05-16

## Verdict

No root LPE was validated from the default Ubuntu 24.04.4 Server D-Bus identity,
locale, time, timesync, networkd, or netplan surfaces. The root services and
root-owned config-write methods exist, but default policy either requires admin
authentication or the service is not reachable in this Docker server target.
Malformed newline/path traversal payloads were rejected before writes, and
valid changed values from `attacker` and `selfauth` were denied. No
`dbus-identity-*` root-proof artifacts were created.

## Target and package proof

Probe artifact:

```sh
bash ubuntu24-server-lpe/pocs/host_locale_time_probe.sh ubuntu24-server-lpe-target
```

Observed target:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_ID="24.04"
VERSION_CODENAME=noble
Linux 4f5b414436ae 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

Default package versions:

```text
console-setup                 1.226ubuntu1
dbus                          1.14.10-4ubuntu4.1
keyboard-configuration        1.226ubuntu1
locales                       2.39-0ubuntu8.7
netplan.io                    1.1.2-8ubuntu1~24.04.2
polkitd                       124-2ubuntu1.24.04.3
systemd                       255.4-1ubuntu8.15
systemd-timesyncd             255.4-1ubuntu8.15
```

## Default activation and reachability

The systemd identity services are static D-Bus activatable root services:

```text
org.freedesktop.hostname1     (activatable)
org.freedesktop.locale1       (activatable)
org.freedesktop.timedate1     (activatable)
org.freedesktop.timesync1     (activatable)
org.freedesktop.network1      (activatable)
io.netplan.Netplan            root netplan-dbus, or activatable before first use
```

Service-file proof:

```sh
docker exec ubuntu24-server-lpe-target bash -lc \
  'for f in /usr/share/dbus-1/system-services/org.freedesktop.hostname1.service \
            /usr/share/dbus-1/system-services/org.freedesktop.locale1.service \
            /usr/share/dbus-1/system-services/org.freedesktop.timedate1.service \
            /usr/share/dbus-1/system-services/org.freedesktop.timesync1.service \
            /usr/share/dbus-1/system-services/org.freedesktop.network1.service \
            /usr/share/dbus-1/system-services/io.netplan.Netplan.service; do
      echo "### $f"; sed -n "1,25p" "$f"; done'
```

Observed: `hostname1`, `locale1`, `timedate1`, `timesync1`, and `network1`
use `Exec=/bin/false` plus `SystemdService=dbus-org.freedesktop.*.service`.
Netplan uses `Exec=/usr/libexec/netplan/netplan-dbus` and `User=root`.

Default unit state after cleanup:

```text
systemd-hostnamed.service     inactive
systemd-localed.service       inactive
systemd-timedated.service     inactive
systemd-timesyncd.service     inactive, enabled, ConditionResult=no
systemd-networkd.service      inactive, disabled, ConditionResult=no
systemd-networkd.socket       inactive, disabled, ConditionResult=no
systemctl is-system-running   running
```

`timesync1` did not become a usable default D-Bus target in the container:
`SetRuntimeNTPServers` as both users timed out under `timeout 8` with
`exit_status=124`. `network1` activation failed with:

```text
Call failed: Unit dbus-org.freedesktop.network1.service not found.
```

## Policy semantics

Relevant defaults:

```text
org.freedesktop.hostname1.set-*       any/inactive/active auth_admin_keep
org.freedesktop.locale1.set-*         any/inactive/active auth_admin_keep
org.freedesktop.timedate1.set-*       any/inactive/active auth_admin_keep
org.freedesktop.timesync1.set-runtime-servers
                                      any/inactive auth_admin, active auth_admin_keep
org.freedesktop.network1.* mutators   any/inactive auth_admin, active auth_admin_keep
```

Admin identities are sudo/admin groups, and neither test user is in them:

```text
sudo:x:27:ubuntu
attacker:x:1001:
selfauth:x:1002:selfauth
/usr/share/polkit-1/rules.d/49-ubuntu-admin.rules: unix-group:sudo, unix-group:admin
/usr/share/polkit-1/rules.d/50-default.rules: unix-group:sudo
```

The live container reported no logind session for `selfauth`; even if it were
active on a local seat, these actions are `auth_admin*`, not `auth_self*`, so a
passworded non-sudo self-auth user does not get the write primitive by default.

## State-changing call results

Representative commands from the probe:

```sh
runuser -u attacker -- busctl --system call org.freedesktop.hostname1 \
  /org/freedesktop/hostname1 org.freedesktop.hostname1 SetStaticHostname \
  sb codex-dbus-probe false

runuser -u selfauth -- busctl --system call org.freedesktop.locale1 \
  /org/freedesktop/locale1 org.freedesktop.locale1 SetLocale \
  asb 1 LANG=C true

runuser -u attacker -- busctl --system call org.freedesktop.timedate1 \
  /org/freedesktop/timedate1 org.freedesktop.timedate1 SetTime \
  xbb "$now_usec" false false

runuser -u attacker -- busctl --system call io.netplan.Netplan \
  /io/netplan/Netplan io.netplan.Netplan Config
```

Observed authorization failures:

```text
hostname SetStaticHostname valid:      Interactive authentication required.
hostname SetPrettyHostname valid:      Interactive authentication required.
hostname SetLocation ../../tmp/lpe:    Interactive authentication required.
locale SetLocale LANG=C:               Interactive authentication required.
locale SetX11Keyboard valid:           Interactive authentication required.
timedate SetTimezone Africa/Abidjan:   Interactive authentication required.
timedate SetLocalRTC:                  Interactive authentication required.
timedate SetTime current timestamp:    Interactive authentication required.
timedate SetNTP:                       Interactive authentication required.
netplan Config/Generate/Apply:         Access denied
network1 Reload:                       Unit dbus-org.freedesktop.network1.service not found.
timesync SetRuntimeNTPServers:         timeout exit_status=124
```

No-op current-state calls for `SetLocale LANG=C.UTF-8` and
`SetTimezone Etc/UTC` returned success for both users, but they did not change
any file hash. Changed valid values (`LANG=C`, `Africa/Abidjan`) were denied.

Injection/path validation results:

```text
SetPrettyHostname "codex pretty\nX=/tmp/lpe":
  Invalid pretty hostname 'codex pretty
  X=/tmp/lpe'

SetLocale "LANG=C.UTF-8\nX=/tmp/lpe":
  Locale C.UTF-8
  X=/tmp/lpe is not valid, refusing.

SetX11Keyboard "us\nX=/tmp/lpe":
  Invalid X11 keyboard layout.

SetVConsoleKeyboard "../../tmp/lpe":
  Failed to check keymap ../../tmp/lpe: Invalid argument

SetTimezone "../../tmp/lpe":
  Invalid or not installed time zone '../../tmp/lpe'
```

## Root-owned state before/after

The probe compared root-owned state paths before and after all unprivileged
calls:

```text
/etc/hostname                 daa99b0fc19375555ed5b390e6304cbe9ccd9ee752e60b20eb4b37dea36a69cd
/etc/machine-info             absent
/etc/locale.conf              89dd29db91ea608d72b5b4d3d3f5816cc2d3c1dd730741dc41b20ce12f1c2b3b
/etc/default/locale           symlink -> ../locale.conf, same hash
/etc/default/keyboard         9d2d64b5b738ef55ecc80e236cd00caba19d3afe1921c74fa7d73c9477ebe6eb
/etc/localtime                symlink -> /usr/share/zoneinfo/Etc/UTC, hash 8b85846791ab2c8a5463c83a5be3c043e2570d7448434d41398969ed47e3e6f2
/etc/systemd/timesyncd.conf   e6734751f8aaf19fddfff891ad246387f5f59bd9ff1a5f0cac2c34bc81941c62
/etc/netplan                  755 root:root, no files
```

Hashes and metadata were identical after the probes. No `/etc/machine-info`,
netplan YAML, timesync config, keyboard config, hostname change, timezone
change, or locale change was produced.

## Environment and helper execution

The default root service units use fixed absolute `ExecStart` paths and do not
inherit caller-supplied D-Bus environment:

```text
systemd-hostnamed   ExecStart=/usr/lib/systemd/systemd-hostnamed   Environment=  ReadWritePaths=/etc /run/systemd
systemd-localed     ExecStart=/usr/lib/systemd/systemd-localed     Environment=  ReadWritePaths=/etc /usr/lib/locale
systemd-timedated   ExecStart=/usr/lib/systemd/systemd-timedated   Environment=  ReadWritePaths=/etc
systemd-timesyncd   ExecStart=/usr/lib/systemd/systemd-timesyncd   Environment=SYSTEMD_NSS_RESOLVE_VALIDATE=0 User=systemd-timesync
systemd-networkd    ExecStart=/usr/lib/systemd/systemd-networkd    Environment= User=systemd-network
```

Because the caller cannot reach the mutating paths with changed valid values,
there was no observed attacker-controlled root helper environment, argv path,
config include path, symlink target, or code-consuming value.

## Cleanup

Cleanup commands run:

```sh
docker exec ubuntu24-server-lpe-target bash -lc \
  'systemctl stop systemd-hostnamed.service systemd-localed.service systemd-timedated.service 2>/dev/null || true;
   systemctl is-active systemd-hostnamed.service systemd-localed.service systemd-timedated.service \
     systemd-timesyncd.service systemd-networkd.service systemd-networkd.socket 2>&1 || true;
   sha256sum /etc/hostname /etc/locale.conf /etc/default/keyboard /etc/localtime /etc/systemd/timesyncd.conf;
   test ! -e /etc/machine-info && echo /etc/machine-info absent;
   find /etc/netplan -maxdepth 2 -printf "%m %u:%g %p\n" | sort;
   systemctl is-system-running 2>&1 || true'
```

Observed cleanup state:

```text
inactive
inactive
inactive
inactive
inactive
inactive
/etc/machine-info absent
755 root:root /etc/netplan
running
```

## Why scanners might miss this

Method enumeration alone looks suspicious because root-owned D-Bus services
advertise methods that can write `/etc/hostname`, `/etc/machine-info`,
`/etc/locale.conf`, `/etc/default/keyboard`, `/etc/localtime`, runtime NTP
servers, and network configuration. The exploitable boundary is semantic:
changed values are Polkit admin-gated, no-op current values may return success
without writing, invalid newline/path payloads die in validators, `timesync1`
and `network1` are not default-reachable in this server container, and netplan
rejects normal users at the service method boundary.
