# Negative: user-session package helpers

Date: 2026-05-16

Scope: stock Ubuntu 24.04 Server default install in `ubuntu24-server-lpe-target`, local uid1001 `attacker`, no sudo/admin groups.

## Verdict

No uid1001 -> root local privilege escalation was validated in the default user-session package helper boundary.

The interesting primitive is real but not exploitable in this state: uid1001 can create a PackageKit transaction and set `frontend-socket` to an existing attacker-controlled Unix socket, and PackageKit also accepts a `user-id=0` hint. However, root/package-mutating operations (`RefreshCache`, `InstallPackages`, `UpdatePackages`, `SetProxy`) fail polkit authorization before the APT backend connects to the frontend socket. Query-only operations do not use the frontend socket. No root process connected to attacker-controlled IPC during the probes.

## Default install and reachability

Target baseline:

```text
Ubuntu 24.04.4 LTS noble
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
systemd state: running
```

Relevant default packages:

```text
apt                         2.8.3
dbus-user-session           1.14.10-4ubuntu4.1
debconf                     1.5.86ubuntu1
dirmngr                     2.4.4-2ubuntu17.4
gpg-agent                   2.4.4-2ubuntu17.4
keyboxd                     2.4.4-2ubuntu17.4
packagekit                  1.2.8-2ubuntu1.5
packagekit-tools            1.2.8-2ubuntu1.5
polkitd                     124-2ubuntu1.24.04.3
systemd                     255.4-1ubuntu8.15
ubuntu-minimal              1.539.2
ubuntu-standard             1.539.2
ubuntu-server               1.539.2
```

Default service/socket proof:

```text
/usr/lib/systemd/system/packagekit.service:10 Type=dbus
/usr/lib/systemd/system/packagekit.service:11 BusName=org.freedesktop.PackageKit
/usr/lib/systemd/system/packagekit.service:12 User=root
/usr/lib/systemd/system/packagekit.service:13 ExecStart=/usr/libexec/packagekitd

/usr/lib/systemd/user/pk-debconf-helper.socket:5 ListenStream=%t/pk-debconf-socket
/usr/lib/systemd/user/pk-debconf-helper.service:4 RefuseManualStart=true
/usr/lib/systemd/user/pk-debconf-helper.service:7 ExecStart=/usr/libexec/pk-debconf-helper

/usr/lib/systemd/user/dbus.socket:5 ListenStream=%t/bus
/usr/lib/systemd/user/gpg-agent.socket:6 ListenStream=%t/gnupg/S.gpg-agent
/usr/lib/systemd/user/dirmngr.socket:6 ListenStream=%t/gnupg/S.dirmngr
/usr/lib/systemd/user/keyboxd.socket:6 ListenStream=%t/gnupg/S.keyboxd
```

The user sockets are enabled by default under `sockets.target.wants`:

```text
/usr/lib/systemd/user/sockets.target.wants/dbus.socket -> ../dbus.socket
/etc/systemd/user/sockets.target.wants/gpg-agent.socket -> /usr/lib/systemd/user/gpg-agent.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-ssh.socket -> /usr/lib/systemd/user/gpg-agent-ssh.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-extra.socket -> /usr/lib/systemd/user/gpg-agent-extra.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-browser.socket -> /usr/lib/systemd/user/gpg-agent-browser.socket
/etc/systemd/user/sockets.target.wants/dirmngr.socket -> /usr/lib/systemd/user/dirmngr.socket
/etc/systemd/user/sockets.target.wants/keyboxd.socket -> /usr/lib/systemd/user/keyboxd.socket
/etc/systemd/user/sockets.target.wants/pk-debconf-helper.socket -> /usr/lib/systemd/user/pk-debconf-helper.socket
```

Raw uid1001 shells do not have a user runtime by default:

```text
XDG_RUNTIME_DIR=
DBUS_SESSION_BUS_ADDRESS=
systemctl --user: Failed to connect to bus: No medium found
/run/user/1001 absent
```

uid1001 can enable its own lingering user manager in the default state:

```sh
runuser -u attacker -- loginctl enable-linger attacker
runuser -u attacker -- env XDG_RUNTIME_DIR=/run/user/1001 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus systemctl --user list-sockets --all
```

This creates only attacker-owned user services/sockets:

```text
/run/user/1001/bus                        dbus.socket
/run/user/1001/gnupg/S.dirmngr            dirmngr.socket
/run/user/1001/gnupg/S.gpg-agent          gpg-agent.socket
/run/user/1001/gnupg/S.keyboxd            keyboxd.socket
/run/user/1001/pk-debconf-socket          pk-debconf-helper.socket
```

This is attacker-reachable but not a privilege increase: `user@1001.service` runs as uid1001.

## Root/package boundary evidence

APT hooks present by default:

```text
/etc/apt/apt.conf.d/20packagekit:5  DPkg::Post-Invoke
/etc/apt/apt.conf.d/20packagekit:6  gdbus call --system --dest org.freedesktop.PackageKit ... StateHasChanged cache-update
/etc/apt/apt.conf.d/20packagekit:10 APT::Update::Post-Invoke-Success
/etc/apt/apt.conf.d/20packagekit:11 gdbus call --system --dest org.freedesktop.PackageKit ... StateHasChanged cache-update
/etc/apt/apt.conf.d/70debconf:3     DPkg::Pre-Install-Pkgs {"/usr/sbin/dpkg-preconfigure --apt || true";};
```

PackageKit system bus policy allows unprivileged calls to reach the daemon, then relies on polkit:

```text
/usr/share/dbus-1/system.d/org.freedesktop.PackageKit.conf:11 only root can own org.freedesktop.PackageKit
/usr/share/dbus-1/system.d/org.freedesktop.PackageKit.conf:16 allow anyone to call into the service, reject using PolicyKit
/usr/share/dbus-1/system.d/org.freedesktop.PackageKit.conf:18-29 allow PackageKit, Transaction, Offline, Properties, Introspectable, Peer
```

Polkit defaults for the relevant PackageKit actions:

```text
package-install                  allow_any=auth_admin allow_inactive=auth_admin allow_active=auth_admin_keep
package-install-untrusted        allow_any=auth_admin allow_inactive=auth_admin allow_active=auth_admin
system-update                    allow_any=auth_admin allow_inactive=auth_admin allow_active=auth_admin_keep
system-sources-refresh           allow_any=auth_admin allow_inactive=yes        allow_active=yes
system-network-proxy-configure   allow_any=auth_admin allow_inactive=auth_admin allow_active=yes
trigger-offline-update           allow_any=auth_admin allow_inactive=auth_admin allow_active=yes
```

Binary strings confirm the suspected trust edge:

```text
/usr/libexec/packagekitd:
  SetHints
  frontend-socket
  frontend-socket has to be an absolute path
  frontend-socket does not exist
  sender does not match (%s vs %s)
  Failed to obtain authentication.

/usr/lib/aarch64-linux-gnu/packagekit-backend/libpk_backend_apt.so:
  DEBIAN_FRONTEND=passthrough
  DEBCONF_PIPE=%s
  DEBIAN_FRONTEND=noninteractive
  PACKAGEKIT_CALLER_UID

/usr/libexec/pk-debconf-helper:
  pk_client_helper_start_with_socket
```

## Probes

Create PackageKit transactions as uid1001:

```sh
runuser -u attacker -- busctl --system call \
  org.freedesktop.PackageKit /org/freedesktop/PackageKit \
  org.freedesktop.PackageKit CreateTransaction
```

Result:

```text
o "/37_bddababb"
```

Transaction introspection showed the transaction was owned by uid1001 and had no active local seat:

```text
Sender       ":1.1089"
Uid          1001
CallerActive false
```

`SetHints` must be sent on the same D-Bus connection as `CreateTransaction`; using `busctl` for separate calls is correctly rejected:

```text
Call failed: sender does not match (:1.1095 vs :1.1094)
```

Using one persistent D-Bus connection, PackageKit accepts attacker-controlled frontend sockets:

```text
path /run/user/1001/pk-debconf-socket       sethints ok
path /tmp/pk-hint-check-77523.sock          sethints ok
path /run/dbus/system_bus_socket            sethints ok
path /tmp/nonexistent-pk-sock               frontend-socket does not exist
```

It also accepts `user-id` hints, including `user-id=0`:

```text
hints ['user-id=0']                                                     ok
hints ['user-id=1001']                                                  ok
hints ['user-id=ubuntu']                                                ok
hints ['user-id=attacker']                                              ok
hints ['frontend-socket=/run/user/1001/pk-debconf-socket','user-id=0']  ok
```

Root/package operations still fail before any connection to the attacker socket:

```text
== refresh-cache /62_aecdccda hints user-id=0 fake /tmp/pk-userid0-77987-refresh-cache.sock
sethints ok
method ok
errors [(48, 'Failed to obtain authentication.')]
finished [(2, 0)]
listener {'connected': False}

== install-packages /63_deeedcca hints user-id=0 fake /tmp/pk-userid0-77987-install-packages.sock
sethints ok
method ok
errors [(48, 'Failed to obtain authentication.')]
finished [(2, 0)]
listener {'connected': False}

SetProxy:
org.gtk.GDBus.UnmappedGError.Quark._pk_2dengine_2derror_2dquark.Code3: failed to obtain auth
```

Query-only methods do not touch the debconf/frontend socket:

```text
SearchNames with frontend-socket: errors [] finished [(1, ...)] listener {'connected': False}
GetUpdates with frontend-socket:  errors [] finished [(1, ...)] listener {'connected': False}
```

Therefore the frontend socket is only a post-authorization interactive debconf channel for PackageKit jobs. It is not a pre-authentication root callback primitive from a default uid1001 shell.

## gpg-agent, keyboxd, dirmngr

The GnuPG helpers are default-installed and default-enabled as user sockets, but they are per-user services under `/run/user/1001/gnupg` with `SocketMode=0600` and `DirectoryMode=0700`. The default root PackageKit/APT path inspected here does not use uid1001 `GNUPGHOME`, `gpg-agent`, `keyboxd`, or `dirmngr` sockets.

APT signature verification uses the system APT method/config path, not the attacker's user session services. No tested root APT/PackageKit/debconf path inherited `DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR`, `GNUPGHOME`, or `GPG_AGENT_INFO` from uid1001.

## Cleanup

Performed:

```sh
loginctl disable-linger attacker 2>/dev/null || true
systemctl stop user@1001.service user-runtime-dir@1001.service 2>/dev/null || true
rm -f /tmp/pk-front-*.sock /tmp/pk-front-join-*.sock /tmp/pk-hint-check-*.sock /tmp/pk-userid0-*.sock
```

Post-cleanup proof:

```text
/var/lib/systemd/linger contains no attacker linger file
/run/user/1001 absent
no pk-front/pk-userid probe helpers left running
```

## Why scanners may miss this

This is not a fuzzable crash path. The useful behavior depends on D-Bus sender identity, PackageKit transaction state, polkit action semantics, systemd user socket activation, and whether the APT backend opens `DEBCONF_PIPE` before or after authorization. A scanner can notice `frontend-socket` or `DEBCONF_PIPE`, but it will likely miss the key negative condition: no root connection occurs until after the privileged PackageKit operation is authorized.

## Suggested hardening

These are hardening suggestions, not fixes for a validated LPE:

- In PackageKit, reject `frontend-socket` paths outside the caller's runtime directory and verify peer credentials before use.
- Treat `user-id` as informational only, or reject attempts to set it to a UID different from the D-Bus caller.
- Delay accepting frontend socket hints until after authorization and revalidate the D-Bus sender UID before backend dispatch.
- Consider making `pk-debconf-helper.socket` `SocketMode=0600`; the runtime directory already limits access, but the socket mode currently appears wider than necessary.
