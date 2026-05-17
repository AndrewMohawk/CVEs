# Negative: apport crash metadata parser boundary

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server Docker target.
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no validated uid1001 to root LPE. The probe did not create any
`/root/codex_apport_meta_*` proof, did not redirect a root report write through
an attacker symlink, and left the target `running` with no failed units.

Rerun:

```sh
pocs/codex_apport_meta_probe.sh ubuntu24-server-lpe-target > logs/codex_apport_meta.out 2>&1
```

## Candidate

I tested a narrow apport/systemd-coredump semantic parser edge rather than the
already-covered generic `/var/crash`, autoreport, and socket cases:

- root `/usr/share/apport/apport` collecting metadata from an attacker-owned
  interpreted process under attacker-controlled cwd, argv, env, and symlinked
  paths;
- whether crashing-process `PYTHONPATH`, `APPORT_REPORT_DIR`,
  `APPORT_COREDUMP_DIR`, or D-Bus address values influenced the root handler;
- whether a mismatched packaged executable argument could create a useful root
  report path primitive; and
- whether a precreated report symlink or `.hanging` symlink could redirect root
  writes or root cleanup.

## Default proof

The target has apport installed but not a default attacker-reachable root
consumer:

```text
apport                    2.28.1-0ubuntu3.8
apport-core-dump-handler  2.28.1-0ubuntu3.8
python3-apport            2.28.1-0ubuntu3.8
python3-problem-report    2.28.1-0ubuntu3.8
systemd-coredump          uninstalled
whoopsie                  absent

/var/crash                drwxrwsrwt root:root
/run/apport.socket        srw------- root:root
/var/lib/apport           drwxr-xr-x root:root
/var/lib/apport/coredump  drwxr-xr-x root:root
/var/lib/apport/autoreport missing

kernel.core_pattern = core
fs.suid_dumpable = 0
kernel.core_pipe_limit = 0
```

`apport-autoreport.path`, `apport-autoreport.timer`, and
`apport-autoreport.service` are present, but the service is condition-gated by
missing root-owned `/var/lib/apport/autoreport`; `whoopsie` is not installed.
`apport-forward.socket` is active in the container, but mode `0600` blocks
uid1001.

## Probe results

The attacker process ran `/usr/bin/python3 ./hold.py` from an attacker-owned
cwd symlink target and carried hostile metadata:

```text
uid=1001 euid=1001 cwd=/home/attacker/codex_apport_meta/real cwd
PYTHONPATH=/home/attacker/codex_apport_meta/py
APPORT_REPORT_DIR=/root/codex_apport_meta_report_dir
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus/../../root/codex_apport_meta
```

Root apport interpreted the script path correctly, then rejected it as
unpackaged:

```text
script: /home/attacker/codex_apport_meta/real cwd/hold.py,
interpreted by /usr/bin/python3
executable does not belong to a package, ignoring
```

No `/root/codex_apport_meta_sitecustomize`,
`/root/codex_apport_meta_report_dir`, or `/root/codex_apport_meta_core_dir`
appeared. The attacker `sitecustomize.py` only ran in the attacker process and
wrote `/tmp/codex_apport_meta_sitecustomize_uid` as uid/euid 1001.

A root-controlled mismatch test showed apport will trust the executable
argument if root passes `/usr/bin/sudo` while inspecting an attacker-owned
`/usr/bin/sleep` process:

```text
ExecutablePath: '/usr/bin/sudo'
Package: 'sudo 1.9.15p5-3ubuntu5.24.04.2'
ProcCmdline: '/usr/bin/sleep 90'
/var/crash/_usr_bin_sudo.1001.crash -> attacker:root 0640
```

That is not a uid1001 primitive in the default path: the attacker does not
control the root handler's `%E` argument, and the generated report is
attacker-owned. Precreating `/var/crash/_usr_bin_sudo.1001.crash` as a symlink
to `/root/codex_apport_meta_root_proof` caused apport to fail/skip report
creation rather than follow the symlink. A `.hanging` symlink to `/etc/passwd`
was not converted into a write primitive.

Direct default consumer attempts stayed blocked:

```text
touch /var/lib/apport/autoreport -> Permission denied
systemctl start apport-autoreport.service -> Interactive authentication required
connect(/run/apport.socket) -> errno=13 Permission denied
ROOT_PROOF=NO
```

## Why this is not a finding

The semantic parser boundary is real: root apport combines root-supplied crash
arguments with attacker-owned `/proc/<pid>` metadata and can create report names
from that combined state. In this default Ubuntu Server target, the chain breaks
before LPE:

- normal crashes do not invoke apport because `kernel.core_pattern=core`;
- the container forward socket is root-only;
- autoreport is gated by a root-owned absent file and absent `whoopsie`;
- crashing-process environment variables are data in the report, not root
  handler environment;
- attacker-owned interpreted paths are rejected as unpackaged; and
- report creation uses `O_CREAT|O_EXCL`, so a precreated symlink is not followed
  to a root target.

No Ubuntu Security issue is supported by this evidence. A defense-in-depth
improvement would be to cross-check any supplied executable argument against
`/proc/<pid>/exe` before using it for package attribution/report naming, but the
tested mismatch was root-controlled and not attacker-reachable in the stock
configuration.
