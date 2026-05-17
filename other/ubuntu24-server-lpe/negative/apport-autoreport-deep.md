# Negative: apport autoreport path/service deep pass

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server Docker target.
Attacker identities tested:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

Result: no validated local privilege escalation. `ROOT_PROOF=NO`; no
`/root/apport_autoreport_*` target was created, and the target ended `running`
with zero failed units.

Rerun:

```sh
pocs/apport_autoreport_deep_probe.sh ubuntu24-server-lpe-target > logs/apport-autoreport-deep.out 2>&1
```

## Default proof

Relevant package state from the target:

```text
apport                    2.28.1-0ubuntu3.8
apport-core-dump-handler  2.28.1-0ubuntu3.8
apport-symptoms           0.25
python3-apport            2.28.1-0ubuntu3.8
python3-problem-report    2.28.1-0ubuntu3.8
systemd                   255.4-1ubuntu8.15
systemd-coredump          uninstalled
whoopsie                  absent
```

Default unit state:

```text
apport-autoreport.path     enabled, inactive/dead
apport-autoreport.timer    enabled, inactive/dead
apport-autoreport.service  static, inactive/dead
apport-forward.socket      enabled, active/listening
whoopsie.path              not-found
```

Important default path modes:

```text
/var/crash                  drwxrwsrwt root:root 3777
/var/lib/apport             drwxr-xr-x root:root 0755
/var/lib/apport/coredump    drwxr-xr-x root:root 0755
/run/apport.socket          srw------- root:root 0600
/usr/share/apport           root-owned, not attacker-writable
/usr/share/apport/package-hooks root-owned, not attacker-writable
/etc/apport                 root-owned, not attacker-writable
```

## Code/config evidence

`/usr/lib/systemd/system/apport-autoreport.path` lines 1-7 is enabled but has
`ConditionPathExists=/var/lib/apport/autoreport` and only watches
`PathChanged=/var/crash`.

`/usr/lib/systemd/system/apport-autoreport.service` lines 1-9 has the same
condition, wants `whoopsie.path`, and runs:

```text
ExecStart=/usr/share/apport/whoopsie-upload-all --timeout 20
```

`/usr/lib/systemd/system/apport-autoreport.timer` lines 1-7 is also gated by
`ConditionPathExists=/var/lib/apport/autoreport`.

`/usr/lib/systemd/system/apport-forward.socket` lines 1-11 is container-only
and active here, but `SocketMode=0600` makes `/run/apport.socket` root-only.

`/usr/share/apport/whoopsie-upload-all`:

```text
47-69    derive .upload/.uploaded state and skip already-marked reports
77-83    open the report and take a nonblocking flock
91-105   add package info and package hooks
129-138  reopen the report with O_NOFOLLOW and require a regular file before rewrite
142-145  create/chown the .upload stamp
217-226  exit unless whoopsie.path is enabled
```

`/usr/lib/python3/dist-packages/apport/fileutils.py`:

```text
201-211  mark_report_upload() creates the .upload file
297-308  get_all_reports() only returns readable+writable .crash files
404-414  increment_crash_counter() uses O_NOFOLLOW on report reopen
417-437  make_report_file() builds canonical report names and opens with xb
```

`/usr/share/apport/apport`:

```text
209-218   drops effective privileges to the crashing user
1168-1182 unlinks an old report and recreates with O_CREAT|O_EXCL
1195-1219 drops before writing report data, then recovers only to chmod/finalize
```

## Trigger results

`attacker` created regular `.crash`, `.upload`, `.uploaded`, symlink, and FIFO
entries under `/var/crash`:

```text
/var/crash/apport_autoreport_attacker.crash
/var/crash/apport_autoreport_attacker.upload
/var/crash/apport_autoreport_attacker.uploaded
/var/crash/apport_autoreport_symlink.crash -> /root/apport_autoreport_crash_target
/var/crash/apport_autoreport_symlink.upload -> /root/apport_autoreport_upload_target
/var/crash/apport_autoreport_fifo.crash
```

After the write, `apport-autoreport.path` and `apport-autoreport.service`
remained inactive/dead, the service journal had no entries, and no root target
was created. The path/timer condition is not attacker-satisfiable because
`/var/lib/apport` is root-owned and `/var/lib/apport/autoreport` is absent.

Both normal users were denied direct starts:

```text
systemctl start apport-autoreport.path       -> Interactive authentication required
systemctl start apport-autoreport.timer      -> Interactive authentication required
systemctl start apport-autoreport.service    -> Interactive authentication required
systemctl start apport-coredump-hook@manual.service -> Interactive authentication required
```

Direct user execution of the upload helper did not process reports:

```text
/usr/share/apport/whoopsie-upload-all --timeout 0 --loglevel debug
INFO:root:whoopsie.path is not enabled, doing nothing
```

The active `apport-forward.socket` was not reachable:

```text
attacker: connect(/run/apport.socket) -> errno=13 Permission denied
selfauth: connect(/run/apport.socket) -> errno=13 Permission denied
```

As `attacker`, `mark_report_upload()` created ordinary attacker-owned upload
state. A symlinked `.upload` to `/tmp` produced an attacker-owned `/tmp` file;
a symlinked `.upload` to `/root` failed with `PermissionError`. This confirms
the interesting stamp-following behavior stays in the caller's unprivileged
context in default state.

Direct `process_report()` as `attacker` rewrote a regular attacker-owned report
and created an attacker-owned `.upload`. A `.crash` symlink to a regular file
raised `OSError(40, 'Too many levels of symbolic links')` at the `O_NOFOLLOW`
rewrite; no upload stamp was created. A FIFO report blocked until the probe
timeout, which is at most a denial-of-service primitive and is not countable.
A locked report returned `None` and created no `.upload`.

## Why this is not a finding

The attractive root boundary is real but not default-reachable. The root
autoreport service only runs when root-owned `/var/lib/apport/autoreport`
exists, and the helper exits unless `whoopsie.path` is enabled; `whoopsie` is
absent on this stock Server target. The socket path is root-only, and starting
the path/timer/service/coredump hook from `attacker` or `selfauth` requires
admin authentication.

World-writable `/var/crash` lets a normal user stage crash-report state, but in
the default state nothing root-owned consumes it. Direct processing by the user
runs as that user, package hook/config roots are not writable, symlinked report
rewrites are stopped by `O_NOFOLLOW`, and the observed FIFO behavior is a hang,
not privilege escalation.

## Cleanup

The probe removed:

```text
/var/crash/apport_autoreport_*
/tmp/apport_autoreport_*
/root/apport_autoreport_*
/run/apport_autoreport_*
/home/attacker/apport-autoreport-deep
/home/selfauth/apport-autoreport-deep
```

Final health:

```text
systemctl is-system-running -> running
failed_units=0
ROOT_PROOF=NO
```

## Scanner miss note

A scanner can flag `/var/crash` as sticky world-writable, identify root Apport
code that parses report files, and notice `mark_report_upload()` uses normal
`open()` for `.upload` stamps. That looks like a symlink/race trust boundary,
but the exploit chain breaks on the default systemd conditions, absent
`whoopsie.path`, root-only socket mode, and unprivileged direct-execution
context.

## Suggested hardening

No Ubuntu Security fix is justified as an LPE from this pass. Defense in depth:
keep `/var/lib/apport/autoreport` root-only and absent unless explicitly
enabled, keep `/run/apport.socket` at `0600`, consider using `O_NOFOLLOW` when
creating `.upload` stamps too, and consider nonblocking report opens in
`whoopsie-upload-all` so FIFO reports cannot stall a manually enabled
autoreport service.
