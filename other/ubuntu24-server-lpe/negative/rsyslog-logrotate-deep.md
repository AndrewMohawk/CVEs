# Negative: rsyslog, journald forwarding, and logrotate deep audit

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`.

Verdict: no uid1001-to-root LPE was found in the stock Ubuntu 24.04 Server rsyslog, journald forwarding, or logrotate log-ingestion path. The default system allows unprivileged users to inject syslog/journal records and to spoof log text fields, but I did not find a transition from attacker-controlled message bytes to attacker-selected root command execution, root-owned path creation/truncation, or a symlink/hardlink race in `/var/log` or `/run/log`.

## Baseline Proof

OS and users:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
attacker: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
selfauth: uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

Installed packages matched the current apt candidates in the target:

```text
rsyslog   8.2312.0-3ubuntu9.2
systemd   255.4-1ubuntu8.15
logrotate 3.21.0-2build1
util-linux 2.39.3-9ubuntu6.5
```

Active service/timer state:

```text
rsyslog.service          loaded enabled active running
systemd-journald.service loaded static  active running
logrotate.timer          loaded enabled active waiting, next Sun 2026-05-17 00:00:00 UTC
logrotate.service        loaded static  inactive after prior successful run
```

Relevant socket and directory modes:

```text
/dev/log                         socket 666 root:root
/run/systemd/journal/dev-log     socket 666 root:root
/run/systemd/journal/socket      socket 666 root:root
/run/systemd/journal/stdout      socket 666 root:root
/run/systemd/journal/syslog      socket 666 root:root
/run/log                         dir    755 root:root
/run/log/journal                 dir   2755 root:systemd-journal
/var/log                         dir    775 root:syslog
/var/log/journal                 dir   2755 root:systemd-journal
/var/log/syslog                  file   640 syslog:adm
/var/log/auth.log                file   640 syslog:adm
```

Default config points:

```text
/etc/rsyslog.conf:13      module(load="imuxsock")
/etc/rsyslog.conf:37-43   FileOwner syslog, FileGroup adm, mode 0640, PrivDropToUser/Group syslog
/etc/rsyslog.conf:48      WorkDirectory /var/spool/rsyslog
/etc/rsyslog.d/50-default.conf:8-23 fixed auth/syslog/kern/mail file targets
/etc/rsyslog.d/20-ufw.conf:2        fixed /var/log/ufw.log target when message contains "[UFW "
/usr/lib/tmpfiles.d/00rsyslog.conf  /var/log root:syslog 0775 and fixed syslog-owned log modes
```

Journald/syslog forwarding is default-enabled by Ubuntu:

```text
/usr/lib/systemd/journald.conf.d/syslog.conf:
[Journal]
ForwardToSyslog=yes

syslog.socket:
ListenDatagram=/run/systemd/journal/syslog
SocketMode=0666
PassCredentials=yes
PassSecurity=yes
```

Logrotate defaults:

```text
/etc/logrotate.conf:10             su root adm
/etc/logrotate.conf:16             create
/etc/logrotate.conf:25             include /etc/logrotate.d
/etc/logrotate.d/rsyslog:1-17      fixed syslog/mail/kern/auth/user/cron paths; postrotate /usr/lib/rsyslog/rsyslog-rotate
/etc/logrotate.d/ufw:1-12          fixed /var/log/ufw.log; fixed rsyslog-rotate postrotate
/usr/lib/rsyslog/rsyslog-rotate    systemctl kill -s HUP rsyslog.service
```

Runtime privilege state:

```text
systemd-journald: uid 0, NoNewPrivs: 1
rsyslogd: uid 103(syslog), gid 104(syslog), CapEff 0, NoNewPrivs: 1
/var/lib/logrotate/status: 640 root:root
/var/spool/rsyslog: 700 syslog:adm
```

## Attacker Input Tests

Direct syslog through `/dev/log` as uid1001:

```text
sent: <85>... fakehost sudo[1]: CODX_RSLOG_NL line1\nMay 16 ... ESC \x1b[31mRED\x1b[0m NUL \x00END

/var/log/auth.log:
fakehost sudo[1]: CODX_RSLOG_NL line1#012May 16 ... ESC #033[31mRED#033[0m NUL #000END

journalctl -o export:
_TRANSPORT=syslog
_UID=1001
_GID=1001
SYSLOG_FACILITY=10
MESSAGE=... original newline/control-bearing message ...
_PID=<attacker python3 pid>
```

Direct imuxsock write to `/run/systemd/journal/syslog` as uid1001:

```text
sent: <85>... directhost sshd[222]: CODX_IMUXSOCK_DIRECT line1\nMay 16 fake root line ESC \x1b[32mGREEN\x1b[0m

/var/log/auth.log:
directhost sshd[222]: CODX_IMUXSOCK_DIRECT line1#012May 16 fake root line ESC #033[32mGREEN#033[0m

journalctl -g CODX_IMUXSOCK_DIRECT:
-- No entries --
```

This proves the rsyslog socket itself is reachable, but the effect is still a fixed-file log write by the already-dropped `syslog` daemon. Newlines and terminal controls were encoded in file output, and no file path or shell transition used message text.

Journald native field spoofing with `logger --journald` as uid1001:

```text
input fields:
MESSAGE=CODX_JOURNALD_META attempt
PRIORITY=5
SYSLOG_FACILITY=10
SYSLOG_IDENTIFIER=sudo
_PID=1
_UID=0
OBJECT_PID=1

journalctl -o export:
_TRANSPORT=journal
_UID=1001
_GID=1001
SYSLOG_FACILITY=10
SYSLOG_IDENTIFIER=sudo
PRIORITY=5
MESSAGE=CODX_JOURNALD_META attempt
OBJECT_PID=1
_PID=<actual logger pid>
```

The user-controlled identifier/facility can spoof text in `/var/log/auth.log`, but trusted `_UID` and `_PID` were not overwritten. `OBJECT_PID=1` remained user data; I did not find a default root helper that consumes it as authority.

Journald stdout stream via `systemd-cat` as uid1001:

```text
systemd-cat -t roothelper -p 5 sh -c 'printf "CODX_STDOUT_STREAM line1\nMay 16 fake second line\n"'

journalctl -o export:
_TRANSPORT=stdout
_UID=1001
SYSLOG_IDENTIFIER=roothelper
MESSAGE=CODX_STDOUT_STREAM line1

/var/log/syslog:
roothelper[pid]: CODX_STDOUT_STREAM line1
```

The stream path split input into journal records and preserved uid1001 attribution.

## File and Race Checks

As uid1001:

```text
touch /var/log/CODX_attacker_create
  Permission denied
ln /etc/passwd /var/log/CODX_attacker_hardlink
  Operation not permitted
ln -s /etc/passwd /var/log/CODX_attacker_symlink
  Permission denied
truncate -s 0 /var/log/syslog
  Permission denied

touch /run/log/CODX_runlog_create
  Permission denied
touch /run/log/journal/CODX_journal_create
  Permission denied
ln -s /etc/passwd /run/log/CODX_runlog_symlink
  Permission denied
```

Kernel link protections were enabled:

```text
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 1
```

The dangerous precondition for logrotate symlink/hardlink exploitation was absent: uid1001 cannot place attacker-controlled directory entries in `/var/log`, `/run/log`, `/run/log/journal`, `/etc/logrotate.d`, `/etc/rsyslog.d`, `/var/lib/logrotate`, or `/var/spool/rsyslog`. The only writable ingress is socket data, and the default rsyslog config has no dynamic filename template, `omfile` dynaFile, or message-derived path.

## Logrotate Root Boundary

Attacker-trigger attempts:

```text
attacker$ systemctl start logrotate.service
Failed to start logrotate.service: Interactive authentication required.

attacker$ systemctl kill -s HUP rsyslog.service
Failed to kill unit rsyslog.service: Interactive authentication required.
```

Forced debug of the stock root config did not modify files, but showed the root actions that would occur:

```text
logrotate -d -f /etc/logrotate.conf

renaming /var/log/syslog to /var/log/syslog.1
creating new /var/log/syslog mode = 0640 uid = 103 gid = 4
renaming /var/log/kern.log to /var/log/kern.log.1
creating new /var/log/kern.log mode = 0640 uid = 103 gid = 4
renaming /var/log/auth.log to /var/log/auth.log.1
creating new /var/log/auth.log mode = 0640 uid = 103 gid = 4
running postrotate script: /usr/lib/rsyslog/rsyslog-rotate

creating new /var/log/alternatives.log mode = 0644 uid = 0 gid = 0
creating new /var/log/apport.log mode = 0640 uid = 0 gid = 4
creating new /var/log/apt/history.log mode = 0644 uid = 0 gid = 0
creating new /var/log/btmp mode = 0660 uid = 0 gid = 43
creating new /var/log/wtmp mode = 0664 uid = 0 gid = 43
```

Those root-owned creations are package-defined fixed paths. The rsyslog-controlled paths are recreated as `syslog:adm`, and the postrotate script is a fixed root-owned shell script that only HUPs `rsyslog.service`. I found no default path where log contents are parsed as logrotate configuration or shell.

## Why This Did Not Become LPE

The world-writable sockets are real attack surface, but the default trust boundary held:

```text
1. Message content can choose facility/tag/text, not output path or command.
2. Rsyslog file targets are fixed by root-owned config; no dynamic file templates are present.
3. Rsyslog drops to syslog:syslog with no effective capabilities before steady-state file writes.
4. Journald records trusted uid/pid from kernel credentials; user-supplied _UID/_PID did not override them.
5. Rsyslog file output encoded LF, ESC, and NUL as #012, #033, and #000.
6. uid1001 cannot create/truncate/link entries in /var/log or /run/log.
7. Logrotate config, state, and scripts are root-owned and not attacker-writable.
8. Root logrotate actions operate on package-defined paths and fixed postrotate scripts.
```

Non-counted behavior observed: auth/syslog text spoofing is possible, including fake `sudo[...]`/`sshd[...]` tags and attacker-selected authpriv facility. That is log spoofing only under this task's criteria; it did not produce root command execution, arbitrary root file write/truncate, or a privileged helper transition.

Cleanup: no PoC files were created because no root-impact finding was validated. The only target changes from testing are ordinary log entries with `CODX_*` markers; `logrotate -d -f` was debug-only and did not rotate or rewrite logs.
