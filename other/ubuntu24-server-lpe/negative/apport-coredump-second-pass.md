# Negative: apport and coredump second pass

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server Docker target.
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no validated uid1001 to root LPE. No `/root/apport_sp_*` marker or root-owned target file was created.

Rerun:

```sh
pocs/apport_coredump_second_pass_probe.sh ubuntu24-server-lpe-target
```

Captured log:

```text
logs/apport-coredump-second-pass.out
```

## Default proof

Relevant packages:

```text
apport                   2.28.1-0ubuntu3.8
apport-core-dump-handler 2.28.1-0ubuntu3.8
apport-symptoms          0.25
python3-apport           2.28.1-0ubuntu3.8
python3-problem-report   2.28.1-0ubuntu3.8
systemd                  255.4-1ubuntu8.15
systemd-coredump         uninstalled
whoopsie                 not installed
```

Default kernel/core state:

```text
kernel.core_pattern = core
fs.suid_dumpable = 0
kernel.core_pipe_limit = 0
kernel.core_uses_pid = 0
```

Default service/socket state:

```text
apport.service            enabled, inactive/dead, ConditionVirtualization=!container unmet
apport-forward.socket     enabled, active/listening, /run/apport.socket mode 0600 root:root
apport-autoreport.path    enabled, inactive/dead, ConditionPathExists=/var/lib/apport/autoreport unmet
apport-autoreport.timer   enabled, inactive/dead, ConditionPathExists=/var/lib/apport/autoreport unmet
apport-autoreport.service static, condition-gated, whoopsie absent
apport-coredump-hook@     static, systemd-coredump absent
```

Important config/code paths:

```text
/usr/lib/systemd/system/apport-forward.socket:6-11
  ListenStream=/run/apport.socket
  SocketMode=0600
  Accept=yes
  PassCredentials=true

/usr/lib/systemd/system/apport-autoreport.service:3-8
  ConditionPathExists=/var/lib/apport/autoreport
  ExecStart=/usr/share/apport/whoopsie-upload-all --timeout 20

/usr/lib/systemd/system/apport-coredump-hook@.service:19-42
  ExecStart=/usr/share/apport/apport --from-systemd-coredump %i
  NoNewPrivileges=yes
  ProtectSystem=strict
  ReadWritePaths=/var/crash /var/log

/usr/share/apport/apport:1074-1091
  drops to the real crashing user before collecting proc info

/usr/share/apport/apport:1161-1182
  recovers privileges only to unlink and recreate the report with O_CREAT|O_EXCL

/usr/share/apport/apport:1185-1196
  chowns report to the crash owner, then drops back to the real user before writing

/usr/share/apport/whoopsie-upload-all:217-226
  exits if whoopsie.path is not enabled

/usr/share/apport/whoopsie-upload-all:125-138
  rewrites reports using os.open(... O_NOFOLLOW|O_WRONLY|O_NONBLOCK) and only if regular
```

## Probes

Normal user crashes do not enter apport by default because the target has `kernel.core_pattern=core`:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
bash: Segmentation fault (core dumped)
/tmp/.../default-core/core -> attacker:attacker mode 0600
MISSING /var/crash/_usr_bin_bash.1001.crash
```

The container apport-forward socket is not reachable by the attacker:

```text
/run/apport.socket srw------- root root
connect=FAIL errno=13 Permission denied
```

The autoreport path cannot be enabled by uid1001 and whoopsie is absent:

```text
MISSING /var/lib/apport/autoreport
MISSING /usr/bin/whoopsie
touch /var/lib/apport/autoreport: Permission denied
systemctl start apport-autoreport.service: Interactive authentication required
whoopsie-upload-all --timeout 0: whoopsie.path is not enabled, doing nothing
```

Attacker-controlled package hooks did not import. A local `/tmp/apport_sp_hookpkg.py` was ignored, and a package name containing path traversal was rejected:

```text
local_tmp_package_hook_result False
local_tmp_hook_marker_exists False
slash_package_hook_result False
slash_package_unreportable invalid Package: ../../tmp/apport_sp_hookpkg
MISSING /root/apport_sp_hook_marker
```

Crash-report symlink/FIFO races in `/var/crash` did not yield a root write. For a normal process, a symlink report path to `/root/apport_sp_py_symlink_target` was not followed; after removing the symlink, apport created a normal attacker-owned report. A FIFO precreation for `/var/crash/_usr_bin_sleep.1001.crash` was replaced with a regular file owned by `attacker:root` mode `0640`.

```text
symbolic link /var/crash/_usr_bin_python3.1001.crash -> /root/apport_sp_py_symlink_target
MISSING /root/apport_sp_py_symlink_target

fifo /var/crash/_usr_bin_sleep.1001.crash
regular file -rw-r----- attacker root /var/crash/_usr_bin_sleep.1001.crash
```

The setuid target case created a root-owned report, but still did not follow the attacker symlink and did not leak root environment:

```text
su process: RUSER attacker, EUSER root, RUID 1001, EUID 0
symbolic link /var/crash/_usr_bin_su.1001.crash -> /root/apport_sp_su_symlink_target
rc=1
MISSING /root/apport_sp_su_symlink_target

regular file -rw-r----- root root /var/crash/_usr_bin_su.1001.crash
ExecutablePath: /usr/bin/su
ProcEnviron: "Error: [Errno 13] Permission denied: 'environ'"
```

## Why this is not countable

This target has several scanner-attractive trust boundaries: a world-writable sticky `/var/crash`, root apport code that can process crash metadata, a container socket activator, and report rewrites that briefly recover root privileges. In the default server state, those do not compose into an unprivileged root path:

```text
kernel crashes write local core files, not apport reports
/run/apport.socket is root-only
autoreport is condition-gated by a root-owned absent file
whoopsie is absent
package hooks are root-owned and package names are constrained
report creation uses unlink plus O_CREAT|O_EXCL
report rewrites use O_NOFOLLOW and regular-file checks
privileged collection drops to the real crashing user for user-controlled data
```

Impact observed: uid1001 can create ordinary files in `/var/crash` because it is `3777 root:root`, and a root-mode apport invocation can create a root-owned report for a setuid crash. That is not a privilege escalation: the report contents are apport-generated, the attacker symlink was not followed, no root file target was created, and no root command ran attacker code.

## Cleanup

Cleanup removed:

```text
/var/crash/_usr_bin_python3.12.1001.crash
/var/crash/_usr_bin_python3.1001.crash
/var/crash/_usr_bin_sleep.1001.crash
/var/crash/_usr_bin_su.1001.crash
/var/crash/apport_sp_fake.1001.crash
/var/crash/apport_sp_fake.1001.upload
/root/apport_sp_*
/tmp/apport-second-pass.*
/home/attacker/apport-second-pass*
```

Final verification:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend -> no output
leftover apport_sp/apport-second-pass files -> none
```

## Suggested hardening

No Ubuntu Security fix is warranted from this pass because no LPE was proven. Defense-in-depth options would be to keep `apport-forward.socket` `0600`, keep autoreport disabled unless explicitly configured, and continue using `O_NOFOLLOW` plus regular-file checks for all `/var/crash` update paths.
