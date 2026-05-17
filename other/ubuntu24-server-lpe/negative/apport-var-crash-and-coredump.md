# Negative: apport /var/crash and coredump handling

Status: no validated privilege escalation.

## Default proof

Target baseline: `baseline/live-target-standard` from `ubuntu24-server-lpe-target`.

Installed packages:

```text
apport                    2.28.1-0ubuntu3.8
apport-core-dump-handler  2.28.1-0ubuntu3.8
systemd                   255.4-1ubuntu8.15
```

Default units in the standard-server package state:

```text
apport.service            enabled, inactive in container due ConditionVirtualization=!container
apport-autoreport.path    enabled, inactive because /var/lib/apport/autoreport is absent
apport-autoreport.timer   enabled, inactive because /var/lib/apport/autoreport is absent
apport-forward.socket     enabled, active only in container due ConditionVirtualization=container
```

Writable/report paths:

```text
drwxrwsrwt root root /var/crash
drwxr-xr-x root root /var/lib/apport
drwxr-xr-x root root /var/lib/apport/coredump
```

`/usr/bin/whoopsie` is not present on this stock server target, and `/var/lib/apport/autoreport` is absent.

## Candidate

Two trust-boundary ideas were checked:

1. An unprivileged user can create files in `/var/crash`, so perhaps a crafted `.crash` file can be reprocessed by root.
2. The crash handler writes user core dumps after recovering root privileges, so perhaps the crashing process can force root to create attacker-owned files in privileged directories.

## Code/config evidence

`/usr/lib/systemd/system/apport-autoreport.service` runs `/usr/share/apport/whoopsie-upload-all --timeout 20`, but only when `/var/lib/apport/autoreport` exists via the path/timer unit condition.

`/usr/share/apport/whoopsie-upload-all`:

- lines 47-69 derive and skip existing `.upload` stamps.
- lines 77-84 load the `.crash` file.
- lines 125-138 reopen the report with `O_NOFOLLOW`, require a regular file, rewrite it, and chmod it `0640`.
- lines 217-226 exit early unless `whoopsie.path` is enabled.

`/usr/lib/python3/dist-packages/apport/fileutils.py`:

- lines 297-308 only return `.crash` reports that are readable and writable to the caller.
- lines 599-630 generate core files under fixed `core_dir`, default `/var/lib/apport/coredump`, with a sanitized name `core.<exe>.<uid>.<bootid>.<pid>.<timestamp>`.

`/usr/share/apport/apport`:

- lines 1168-1182 unlink an existing report and create a new report with `O_CREAT|O_EXCL`.
- lines 1195-1209 drop to the crashing user before writing report contents.
- lines 1214-1229 recover privileges only to write the optional core file, using the fixed coredump path above.

## Attacker tests

As `attacker`:

```sh
id
touch /var/crash/attacker.crash /var/crash/attacker.upload
ls -l /var/crash/attacker.crash /var/crash/attacker.upload
/usr/share/apport/whoopsie-upload-all --timeout 0
```

Observed:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
-rw-r--r-- 1 attacker root 0 /var/crash/attacker.crash
-rw-r--r-- 1 attacker root 0 /var/crash/attacker.upload
INFO:root:whoopsie.path is not enabled, doing nothing
```

Container caveat: the Docker target has `core_pattern=core`, so it is not valid for proving real-kernel crash delivery. The installed systemd/apport unit evidence still shows the default server path: systemd-coredump invokes `apport-coredump-hook@.service`, which has `ReadWritePaths=/var/crash /var/log` and then calls `/usr/share/apport/apport --from-systemd-coredump %i`.

## Why it is not a finding

The writable `/var/crash` directory alone does not create root execution in stock server state. The root autoreport path is gated by `/var/lib/apport/autoreport` and `whoopsie.path`; both are absent/not enabled by default here. Directly running `whoopsie-upload-all` as the attacker exits before processing reports.

The core-file write is also constrained. Although `apport` regains root before writing the optional core, `fileutils.get_core_path()` builds an absolute path under `/var/lib/apport/coredump`, not a pathname controlled by the crashing process cwd or argv. The filename is sanitized and the directory is not attacker-writable, so this does not become arbitrary root-directory file creation.

Cleanup:

```sh
rm -f /var/crash/attacker.crash /var/crash/attacker.upload /var/crash/attacker.uploaded
```
