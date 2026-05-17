# Negative: Apport core_pattern namespace/report handling

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 Server-style Docker target.
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no validated uid1001 to root LPE in the default Apport/core-dump slice.
No root command execution and no attacker-controlled root file write were
obtained.

Logs:

```sh
logs/apport-core-namespace-20260517-baseline.log
logs/apport-core-namespace-20260517-probes.log
logs/apport-core-namespace-20260517-forward-hooks.log
logs/apport-core-namespace-20260517-final-health.log
```

## Default proof

Package/service state:

```text
apport                    2.28.1-0ubuntu3.8
apport-core-dump-handler  2.28.1-0ubuntu3.8
python3-apport            2.28.1-0ubuntu3.8
python3-problem-report    2.28.1-0ubuntu3.8
systemd                   255.4-1ubuntu8.15
systemd-coredump          uninstalled
whoopsie                  absent
```

Default crash state:

```text
kernel.core_pattern = core
fs.suid_dumpable = 0
kernel.core_pipe_limit = 0
/var/crash = drwxrwsrwt root:root 3777
/var/lib/apport/coredump = drwxr-xr-x root:root 0755
/run/apport.socket = srw------- root:root 0600
```

`apport.service` is enabled but inactive in this container because
`/usr/lib/systemd/system/apport.service:4` has
`ConditionVirtualization=!container`; its start path would set
`kernel/core_pattern`, `fs/suid_dumpable`, and `kernel/core_pipe_limit` at
`/usr/share/apport/apport:693-701`. The container-specific
`apport-forward.socket` is active, but
`/usr/lib/systemd/system/apport-forward.socket:6-7` uses
`ListenStream=/run/apport.socket` and `SocketMode=0600`.

`apport-autoreport.path`, `.timer`, and `.service` are all gated by
`ConditionPathExists=/var/lib/apport/autoreport`; that root-owned file is
absent. The upload/helper path also exits unless `whoopsie.path` is enabled at
`/usr/share/apport/whoopsie-upload-all:217-226`, and `whoopsie` is absent.

## Probes

An ordinary uid1001 segfault followed the default kernel setting and did not
enter Apport:

```text
core_pattern=core
Segmentation fault
MISSING /var/crash/_usr_bin_python3.12.1001.crash
```

User, mount, and PID namespaces are available to uid1001. A namespaced process
with an attacker-owned `/run/apport.socket` was used to model the host root
helper path. For `dump_mode=1`, Apport forwarded the crashing process arguments
and coredump fd to the attacker-owned socket:

```text
uid_map=0 1001 1
socket uid=1001 gid=1001
exe uid=1001 gid=1001
msg=5 11 0 1
fds=[5]
payload=NS-FORWARD-CORE
```

This is not an LPE: the fd is the attacker-owned process coredump, the socket
must be owned by an ID mapped into the process user namespace, and no root code
executes from the socket. The privileged case is gated: the same namespace
forward attempt with `dump_mode=2` logged:

```text
Not forwarding crash with dump mode of 2 to container due to security concerns. Please provide --pidfd.
```

The relevant code is `/usr/share/apport/apport:777-786` for namespace
forwarding selection, `:563-570` for the `dump_mode != 1` no-pidfd refusal,
`:572-624` for socket/executable uid/gid-map validation, and `:625-663` for
the actual socket send.

Report-file races in `/var/crash` did not produce a root write. A symlinked
report path to `/root/apport_core_ns_symlink_target` failed with `EEXIST` and
left the root target missing. A FIFO at the report path was unlinked/replaced
with a normal report owned `attacker:root` mode `0640`. An attacker-created
unseen regular report caused Apport to skip to avoid clobbering:

```text
Could not create report file: [Errno 17] File exists
MISSING /root/apport_core_ns_symlink_target
regular file -rw-r----- attacker root /var/crash/_usr_bin_sleep.1001.crash
report ... already exists and unseen, skipping to avoid disk usage DoS
```

The relevant protections are `/usr/share/apport/apport:1161-1182`
(`O_CREAT|O_EXCL` after unlink), `:1185-1196` (chown then drop before writing),
`:1218-1220` (final chmod), and
`/usr/lib/python3/dist-packages/apport/fileutils.py:404-410`
(`O_NOFOLLOW|O_NONBLOCK` for existing report counters).

Environment, comm-name, cwd, and import-path probes did not cross privilege
boundaries. A process named with embedded `Uid:`/`Gid:` text still parsed as
uid1001 from the real status fields. Target-process `APPORT_LOG_FILE`,
`PYTHONPATH`, and custom `PATH` became report data or were ignored; they did
not affect the root Apport interpreter. The kernel path wrote `_HooksRun: no`
and did not run package hooks.

Package-hook execution was only reachable through the upload helper path, which
is not default-reachable. A uid1001-controlled `PYTHONPATH` hook file named
`python3.12-minimal.py` was ignored, and slash traversal in `Package` was
rejected:

```text
tmp_pythonpath_hook_result False
marker_exists False
slash_unreportable invalid Package: ../../tmp/apport_core_ns
MISSING /root/apport_core_ns_hook_marker
```

Hook loading is constrained by
`/usr/lib/python3/dist-packages/apport/report.py:1134-1149` (slash rejection)
and `:1151-1191` (root package hook dirs and `/opt` package hook dirs). The
helper that would run hooks does so at
`/usr/share/apport/whoopsie-upload-all:91-105`, but its default service path is
blocked as described above.

The executable path argument parser rejects `../` after decoding kernel `%E`
slash substitutions at `/usr/share/apport/apport:749-758`. A direct modeled
call with `..!root!apport_core_ns_escape` fell back to `/proc/<pid>/exe` and
did not create `/root/apport_core_ns_escape`.

The synthetic `core_ulimit=-1` modeled calls in
`logs/apport-core-namespace-20260517-probes.log` used a text string as fake
coredump input and hit a `TypeError` while replaying `CoreDump` back out to
`/var/lib/apport/coredump`. That left a zero-length root-owned core artifact
during the probe and was cleaned up. It is not an attacker-controlled root write
and does not appear in the default trigger, where `core_pattern=core` and Apport
is not invoked.

## Why this is not countable

The default uid1001 trigger does not reach Apport because `core_pattern=core`.
The active forward socket is root-only. The root upload/hook consumer is gated
by absent root-owned `/var/lib/apport/autoreport` and absent `whoopsie.path`.

When the root helper is modeled directly, the remaining attractive boundaries
are bounded: `/var/crash` symlink/fifo/report races do not become root writes,
target-process environment and import paths are not inherited by the root
interpreter, package hooks are not attacker-writable or path-traversable, and
namespace forwarding only sends the attacker's own dump-mode-1 coredump fd to
an attacker-owned namespace socket.

## Cleanup

Removed probe artifacts:

```text
/tmp/apport-core-ns-20260517
/tmp/apport-core-ns-forward-20260517
/root/apport_core_ns_*
/var/crash/_usr_bin_sleep.1001.*
/var/crash/_usr_bin_python3*.1001.*
/var/crash/_bin_sleep.1001.*
/var/lib/apport/coredump/core._usr_bin_sleep*
```

Final health from `logs/apport-core-namespace-20260517-final-health.log`:

```text
systemctl is-system-running -> running
MISSING /root/apport_core_ns_hook_marker
MISSING /root/apport_core_ns_symlink_target
MISSING /root/apport_core_ns_env_marker
MISSING /root/apport_core_ns_escape
MISSING /tmp/apport-core-ns-20260517
MISSING /tmp/apport-core-ns-forward-20260517
MISSING /var/crash/_usr_bin_sleep.1001.crash
```

## Hardening notes

No Ubuntu Security LPE fix is justified from this pass. Defense in depth:
keep `apport-forward.socket` at `0600`, keep autoreport disabled unless
explicitly configured, keep `whoopsie.path` absent/disabled on Server defaults,
and consider making namespace forwarding log the dump-mode-1 fd handoff more
explicitly so it is not mistaken for local processing.
