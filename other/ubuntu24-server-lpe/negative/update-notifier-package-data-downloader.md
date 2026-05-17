# Negative: update-notifier package-data-downloader

Status: no validated privilege escalation.

## Default proof

Installed packages:

```text
update-notifier-common  3.192.68.2
update-manager-core     1:24.04.12
python3-update-manager  1:24.04.12
```

Default root timers/services:

```text
update-notifier-download.timer
  OnStartupSec=5m
  OnUnitActiveSec=24h

update-notifier-download.service
  ExecStart=/usr/lib/update-notifier/package-data-downloader
```

Default file state:

```text
/usr/share/package-data-downloads                         drwxr-xr-x root root, empty
/var/lib/update-notifier/package-data-downloads            drwxr-xr-x root root
/var/lib/update-notifier/package-data-downloads/partial    drwx------ _apt root
/var/lib/update-notifier/user.d                            drwxr-xr-x root root
/etc/update-notifier                                       drwxr-xr-x root root
```

## Candidate

`package-data-downloader` has a high-risk shape: root reads package-supplied hook descriptions, downloads files, verifies hashes, and executes a `Script` field. If a normal user could add or modify hook descriptions, stamp files, downloaded files, or the script path, this would become root command execution.

## Code evidence

`/usr/lib/update-notifier/package-data-downloader`:

- lines 36-40 set `DATADIR=/usr/share/package-data-downloads/`, `STAMPDIR=/var/lib/update-notifier/package-data-downloads/`, and notifier paths.
- lines 161-169 enumerate hook files from `DATADIR`.
- lines 174-200 download files into `STAMPDIR/partial` via `/usr/lib/apt/apt-helper download-file` with a required SHA256 hash.
- lines 247-255 parse each hook and set `command = [para['Script']]`.
- lines 271-287 append downloaded files and execute the hook with `subprocess.call(command)`.
- lines 291-295 create root-owned stamps and remove downloaded files after success.

## Attacker tests

As `attacker`:

```sh
find /var/lib/update-notifier /etc/update-notifier -maxdepth 4 -writable -ls
/usr/lib/update-notifier/package-data-downloader
/usr/lib/update-notifier/package-system-locked; echo status:$?
```

Observed:

```text
# no writable files or directories under /var/lib/update-notifier or /etc/update-notifier
status:0
```

`/usr/share/package-data-downloads` is empty in the default target, so the root service has no hook to execute.

## Why it is not a finding

The execution primitive is package-maintainer controlled, not user controlled, in the default state. The hook directory is root-owned and empty; the stamp directory is root-owned; the temporary download directory is `_apt`-owned and mode `0700`; and the attacker has no default package-install path to place a hook. No normal-user trigger reaches root command execution.

Cleanup: none required.
