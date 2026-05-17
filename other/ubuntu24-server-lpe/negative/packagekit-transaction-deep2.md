# Negative: PackageKit transaction state/path/env deep2

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default Docker/systemd target.

Result: no validated local privilege escalation. The active non-admin `selfauth` user can still reach interesting PackageKit trust boundaries, including newline-bearing `SetHints` values, root APT refresh, transaction cancellation, local `.deb` metadata parsing, and frontend-socket validation. None crossed into root command execution, root file write, repository source modification, or maintainer-script execution.

Artifacts:

```text
pocs/packagekit_transaction_deep2_probe.sh
logs/packagekit-transaction-deep2.out
```

## Default proof

Relevant stock target packages:

```text
apt                         2.8.3
dbus                        1.14.10-4ubuntu4.1
dpkg                        1.22.6ubuntu6.6
gir1.2-packagekitglib-1.0   1.2.8-2ubuntu1.5
libpackagekit-glib2-18      1.2.8-2ubuntu1.5
packagekit                  1.2.8-2ubuntu1.5
packagekit-tools            1.2.8-2ubuntu1.5
polkitd                     124-2ubuntu1.24.04.3
python3-gi                  3.48.2-1
systemd                     255.4-1ubuntu8.15
```

PackageKit is the default root D-Bus service:

```text
/usr/lib/systemd/system/packagekit.service
Type=dbus
BusName=org.freedesktop.PackageKit
User=root
ExecStart=/usr/libexec/packagekitd
```

The active test subject was a real local seat login and not a sudo/admin user:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
TTY=tty1
Seat=seat0
Active=yes
```

PackageKit authorization from that session:

```text
system-sources-refresh           -> 1
system-network-proxy-configure   -> 1
system-sources-configure         -> 3
package-install-untrusted        -> 3
system-update                    -> 3
```

## Tested hypotheses

### SetHints to root APT environment

The probe set active-user proxy state to a loopback fake proxy, then ran `RefreshCache(true)` after:

```text
SetHints([
  "locale=C.UTF-8\nAPT_CONFIG=/tmp/pkdeep2.conf\nPKDEEP2_LOCALE_SPLIT=1",
  "packagekit-transaction-deep2=x\nAPT_CONFIG=/tmp/pkdeep2.conf\nPKDEEP2_UNKNOWN_SPLIT=1",
  "interactive=true",
  "background=false",
  "cache-age=1",
  "supports-plural-signals=true"
])
```

`SetHints` succeeded, the root APT refresh hit the fake proxy for all four default Ubuntu repositories, and APT rejected the fake unsigned metadata as data:

```text
PROXY_COUNT label=hint-env-refresh count=4
ErrorCode ... Clearsigned file isn't valid, got 'NOSPLIT'
Finished (2, 2557)
```

The root process monitor saw attacker newlines propagate inside root child environment values:

```text
ENV_ITEM b'LANG=C.UTF-8\nAPT_CONFIG=/tmp/pkdeep2.conf\nPKDEEP2_LOCALE_SPLIT=1'
ENV_ITEM b'LANGUAGE=C.UTF-8\nAPT_CONFIG=/tmp/pkdeep2.conf\nPKDEEP2_LOCALE_SPLIT=1'
ENV_ITEM b'http_proxy=http://127.0.0.1:35907/'
SEPARATE_APT_CONFIG=0 SEPARATE_PKDEEP2=0
```

This is a real hardening finding: `locale=` hint content can enter root APT/helper environments with embedded newlines. It did not split into a separate attacker-controlled `APT_CONFIG` or `PKDEEP2_*` environment variable, and the attacker `APT::Update::Pre-Invoke` file did not run. Separate `APT_CONFIG=/tmp/apt.conf.*` entries observed in `apt-key` children were APT's own transient configs, not `/tmp/pkdeep2.conf`.

### Transaction running/cancel/reuse

While an active-user `RefreshCache` transaction was running, PackageKit rejected attempts to change role on the same transaction:

```text
InstallFiles real while RefreshCache running -> InvalidState already in state running
RepoEnable while RefreshCache running -> InvalidState already in state running
Cancel running RefreshCache -> ok
Finished (3, 1861)
```

After cancellation/finish, `SetHints` was still accepted, but new actions were blocked by the transaction state guard:

```text
SetHints after cancel/finish -> ok
InstallFiles real after cancel/finish -> InvalidState already in state finished
RefreshCache second action after cancel/finish -> InvalidState already in state finished
```

The same held after a completed `GetUpdates` and after a completed `InstallFiles(ONLY_DOWNLOAD)` transaction:

```text
InstallFiles real after GetUpdates finished -> InvalidState already in state finished
InstallFiles real after ONLY_DOWNLOAD finished -> InvalidState already in state finished
```

### Repo/source configure paths

`GetRepoList` was callable. A no-op `RepoEnable(repo_id, true)` still hit the repository configuration policy and failed auth:

```text
repo-enable-noop ErrorCode (48, 'Failed to obtain authentication.')
```

`RepoSetData(repo_id, "set-download-url", "file://...\nAPT_CONFIG=/tmp/pkdeep2.conf")` did not reach source mutation on this apt backend:

```text
RepoSetData not supported by backend
```

No apt source file was modified by the active non-admin user.

### Local `.deb`, proc-fd, and symlink paths

Read-only local parser methods can parse an attacker-owned package through a caller proc-fd path:

```text
proc_fd_path=/proc/189599/fd/7
GetDetailsLocal(proc_fd) -> ok
GetFilesLocal(proc_fd) -> Files(... '/usr/local/share/packagekit-transaction-deep2/payload.txt')
```

The install paths did not become root execution:

```text
InstallFiles(ONLY_DOWNLOAD, proc_fd) -> ErrorCode (8, 'Could not find package(s)')
InstallFiles(0, proc_fd) -> ErrorCode (48, 'Failed to obtain authentication.')
```

A symlink to the attacker `.deb` parsed normally. Swapping the symlink to `/etc/shadow` caused only package-parser errors, and direct `GetFilesLocal("/etc/shadow")` was rejected:

```text
details-symlink-to-shadow -> ErrorCode (26, 'Invalid archive signature ... Could not read meta data from /etc/shadow')
fileslocal-shadow-direct -> NoSuchFile: File /etc/shadow is not found or unsupported
```

No root file contents were disclosed and no root write occurred.

### Frontend socket path/env confusion

`SetHints` accepted an existing Unix socket path containing a newline and `APT_CONFIG=` text:

```text
frontend-socket=/tmp/packagekit-transaction-deep2/frontend\nAPT_CONFIG=/tmp/pkdeep2.conf
```

`GetUpdates` completed without connecting to it, and a real local install stayed auth-blocked:

```text
getupdates-frontend-newline Finished (1, 1474)
installfiles-real-frontend ErrorCode (48, 'Failed to obtain authentication.')
FRONTEND_EVENTS ... events=[]
```

## Root proof and cleanup

The malicious apt config and malicious package postinst both targeted root marker files:

```text
/root/packagekit_transaction_deep2_root
/root/packagekit_transaction_deep2_root.dpkg
```

Post-run proof stayed negative:

```text
ROOT_PROOF_ABSENT /root/packagekit_transaction_deep2_root
ROOT_DPKG_PROOF_ABSENT /root/packagekit_transaction_deep2_root.dpkg
dpkg-query: no packages found matching packagekit-transaction-deep2-root
```

Cleanup proof:

```text
ABSENT /tmp/packagekit-transaction-deep2
ABSENT /home/selfauth/packagekit_transaction_deep2_runner.sh
ABSENT /home/selfauth/packagekit_transaction_deep2_probe.py
ABSENT /tmp/pkdeep2.conf
ABSENT /root/packagekit_transaction_deep2_root
ABSENT /root/packagekit_transaction_deep2_root.dpkg
dpkg-query: no packages found matching packagekit-transaction-deep2-root
systemctl is-system-running -> running
```

## Verdict

Negative for LPE. The notable remaining primitive is newline-bearing `locale=` hint propagation into root APT/helper `LANG` and `LANGUAGE` values during active-user refresh. In this default target, those values stayed single environment entries, fake repository content stayed unsigned metadata, source mutation stayed auth-blocked or unsupported, transaction reuse stayed blocked by state, and local `.deb` parser paths did not execute maintainer scripts.
