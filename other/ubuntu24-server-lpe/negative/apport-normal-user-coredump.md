# Negative: apport/systemd-coredump/var-crash as passworded selfauth user

Status: no validated root LPE in the live `ubuntu24-server-lpe-target`.

Scope was the normal passworded non-sudo user `selfauth` rather than the locked
`attacker` account.

## Target identity and login reachability

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
selfauth:x:1002:1002::/home/selfauth:/bin/bash
selfauth : selfauth
sudo:x:27:ubuntu
adm:x:4:ubuntu,syslog
lxd:x:101:
selfauth P 2026-05-16 0 99999 7 -1
attacker L 2026-05-16 0 99999 7 -1
ubuntu L 2026-04-10 0 99999 7 -1
```

`selfauth` can authenticate over an active PTY through normal PAM login:

```text
Password:
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.10.14-linuxkit aarch64)
selfauth@fd448ecbc136:~$ id; tty; groups; exit
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
/dev/pts/0
selfauth
```

An unprivileged `attacker` process could also `su - selfauth` with the password
and land on `/dev/pts/0`, confirming this is not just root using `runuser`:

```text
Password:
selfauth@fd448ecbc136:~$ id; tty; groups; exit
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
/dev/pts/0
selfauth
logout
```

## Package and service state

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
apport 2.28.1-0ubuntu3.8 ii
apport-core-dump-handler 2.28.1-0ubuntu3.8 ii
systemd 255.4-1ubuntu8.15 ii
systemd-coredump  un
dpkg-query: no packages found matching whoopsie
```

Live Docker state before forced handler testing:

```text
kernel.core_pattern = core
fs.suid_dumpable = 0
kernel.core_pipe_limit = 0
```

`apport.service` is enabled but skipped in this container:

```text
apport.service - automatic crash report generation
Active: inactive (dead)
Condition: start condition unmet
... skipped because of an unmet condition check (ConditionVirtualization=!container).
```

The systemd-coredump package is not installed. Apport ships a hook drop-in, but
there is no base `systemd-coredump@.service` in this target:

```text
/usr/lib/systemd/system/systemd-coredump@.service.d/apport-coredump-hook.conf:
[Unit]
OnSuccess=apport-coredump-hook@%i.service

systemctl cat systemd-coredump@.service:
No files found for systemd-coredump@.service.
```

Container-only forwarding is present but not user-reachable:

```text
srw------- root root 600 /run/apport.socket
id 1002 1002 [1002]
connect=fail errno=13 Permission denied
```

## Writable paths and autoreport gates

```text
drwxrwsrwt root root 3777 /var/crash
drwxr-xr-x root root 755 /var/lib/apport
drwxr-xr-x root root 755 /var/lib/apport/coredump
```

`selfauth` can create regular files and symlinks in `/var/crash`, with group
`root` inherited from the setgid directory:

```text
-rw-r--r-- 1 selfauth root 20 /var/crash/selfauth_fake.crash
-rw-r--r-- 1 selfauth root  0 /var/crash/selfauth_fake.upload
lrwxrwxrwx 1 selfauth root 27 /var/crash/selfauth_link.crash -> /tmp/apport_selfauth_target
```

The root autoreport path is gated off in this stock server package set:

```text
stat: cannot statx '/var/lib/apport/autoreport': No such file or directory
stat: cannot statx '/usr/lib/systemd/system/whoopsie.path': No such file or directory
stat: cannot statx '/usr/bin/whoopsie': No such file or directory
INFO:root:whoopsie.path is not enabled, doing nothing
```

Starting `apport-autoreport.service` also skips on
`ConditionPathExists=/var/lib/apport/autoreport`.

## Crash behavior tested

With the live Docker defaults (`core_pattern=core`, `suid_dumpable=0`), a normal
`selfauth` crash produced only a user-owned cwd core, not an apport report:

```text
bash: line 1: 94158 Segmentation fault      (core dumped) /usr/bin/sleep 120
-rw------- 1 selfauth selfauth 389120 /home/selfauth/core
ls: cannot access '/var/crash/_usr_bin_sleep.1002.crash': No such file or directory
```

Crashing a setuid helper from an active `selfauth` PTY did not produce a core or
`/var/crash` report while `fs.suid_dumpable=0`:

```text
Password: child_pid=94308 sending_SIGSEGV
ls: cannot access '/home/selfauth/core': No such file or directory
ls: cannot access '/var/crash/_usr_bin_su.1002.crash': No such file or directory
```

I then forced `apport --start` to exercise the real handler settings and restored
them afterward. It set:

```text
kernel.core_pattern = |/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -F%F -- %E
fs.suid_dumpable = 2
kernel.core_pipe_limit = 10
```

In this Docker target, actual kernel pipe delivery still did not create reports
or log entries for either `/usr/bin/sleep` or setuid `/usr/bin/su`, so kernel
delivery remains a container caveat rather than exploit proof.

Manual invocation of the installed handler against live `selfauth` processes did
verify the file ownership logic:

```text
INFO: apport ... called for pid 94065, signal 11, core limit 0, dump mode 1
INFO: apport ... executable: /usr/bin/sleep (command line "/usr/bin/sleep 120")
INFO: apport ... wrote report /var/crash/_usr_bin_sleep.1002.crash
-rw-r----- selfauth root 640 3640 /var/crash/_usr_bin_sleep.1002.crash
```

For a live setuid `/usr/bin/su root` process with real uid `selfauth`, dump mode
2 created a fixed root-owned report:

```text
PID    USER     RUSER    EUSER    COMMAND
95651  root     selfauth root     su root
INFO: apport ... called for pid 95651, signal 11, core limit 0, dump mode 2
INFO: apport ... executable: /usr/bin/su (command line "su root")
INFO: apport ... wrote report /var/crash/_usr_bin_su.1002.crash
-rw-r----- root root 640 3898 /var/crash/_usr_bin_su.1002.crash
```

This confirms the expected stock non-container behavior: a normal user can cause
a root-owned apport report for a crashing setuid helper when apport is active.
The path is fixed to `/var/crash/_<executable>.<real uid>.crash`; I did not find
a way to choose an arbitrary root-owned pathname or get root code execution.

## Symlink, hardlink, and race behavior

Apport builds report paths from `ExecutablePath` and real uid:

```text
report = f"{apport.fileutils.report_dir}/{info['ExecutablePath'].replace('/', '_')}.{real_user.uid}.crash"
fd = os.open(report, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0)
```

A pre-created symlink for the report path caused report creation to fail with
`EEXIST`; the symlink target was not created or written:

```text
lrwxrwxrwx selfauth root 777 /var/crash/_usr_bin_sleep.1002.crash -> /tmp/apport_selfauth_target
ERROR: apport ... Could not create report file: [Errno 17] File exists: '/var/crash/_usr_bin_sleep.1002.crash'
stat: cannot statx '/tmp/apport_selfauth_target': No such file or directory
```

The same held for the root-owned setuid report path:

```text
lrwxrwxrwx selfauth root 777 /var/crash/_usr_bin_su.1002.crash -> /tmp/apport_su_symlink_target
ERROR: apport ... Could not create report file: [Errno 17] File exists: '/var/crash/_usr_bin_su.1002.crash'
stat: cannot statx '/tmp/apport_su_symlink_target': No such file or directory
```

Protected link sysctls are enabled, and a hardlink to `/etc/passwd` was denied:

```text
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 1
fs.protected_regular = 2
ln: failed to create hard link '/var/crash/selfauth_hardlink' => '/etc/passwd': Operation not permitted
```

Core files are generated under a fixed non-user-writable directory:

```text
core_dir = os.environ.get("APPORT_COREDUMP_DIR", "/var/lib/apport/coredump")
core_name = f"core.{exe}.{uid}.{get_boot_id()}.{str(pid)}.{str(timestamp)}"
core_path = os.path.join(core_dir, core_name)
```

`/var/lib/apport/coredump` is `0755 root:root`, so `selfauth` cannot pre-place
symlinks there.

## Conclusion

No root LPE was validated.

The meaningful primitive is limited: when the apport kernel handler is active
with `fs.suid_dumpable=2`, a passworded non-sudo user can crash a setuid helper
and cause apport to write a root-owned `0640` report in `/var/crash` containing
some attacker-influenced process fields. The filename and directory are fixed,
symlink/hardlink attempts did not redirect writes, autoreport/whoopsie execution
is gated off by absent stock server files, and the live Docker target did not
deliver real kernel pipe reports after forced `apport --start`.

Cleanup performed:

```text
kernel.core_pattern = core
fs.suid_dumpable = 0
kernel.core_pipe_limit = 0
```
