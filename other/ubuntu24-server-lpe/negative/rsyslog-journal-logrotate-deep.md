# Negative: rsyslog, journald, and logrotate second-pass trust-boundary audit

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`.

Verdict: no uid1001-to-root LPE was found in the default-active Ubuntu 24.04 Server rsyslog/journald/logrotate boundary. uid1001 can inject syslog/journal text through default world-writable sockets, including fake `sudo`/`sshd`/`roothelper` tags, emerg broadcast text, structured journal fields, and raw stdout-stream records, but none of those inputs controlled a root command, root file path, logrotate config, logrotate state, or trusted journald identity.

Probe: `pocs/rsyslog_journal_logrotate_deep_probe.sh`

Full log: `logs/rsyslog-journal-logrotate-deep.out`

## Baseline Proof

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
attacker: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
cron       3.0pl1-184ubuntu2
logrotate  3.21.0-2build1
rsyslog    8.2312.0-3ubuntu9.2
systemd    255.4-1ubuntu8.15
util-linux 2.39.3-9ubuntu6.5
mailutils/postfix absent; bsd-mailx not installed
```

Default-active units and sockets:

```text
rsyslog.service                 loaded active running, enabled
systemd-journald.service        loaded active running, static
logrotate.timer                 loaded active waiting, enabled
logrotate.service               loaded inactive dead, static
syslog.socket                   loaded active running
systemd-journald.socket         loaded active running
systemd-journald-dev-log.socket loaded active running

/dev/log                         srw-rw-rw- root:root
/run/systemd/journal/dev-log     srw-rw-rw- root:root
/run/systemd/journal/socket      srw-rw-rw- root:root
/run/systemd/journal/stdout      srw-rw-rw- root:root
/run/systemd/journal/syslog      srw-rw-rw- root:root
```

Runtime privileges and protected paths:

```text
rsyslogd: uid=103(syslog), gid=104(syslog), groups=adm,syslog, CapEff=0, NoNewPrivs=1
systemd-journald: uid=0, CapEff=00000025402800cf, NoNewPrivs=1

/etc/rsyslog.conf              0644 root:root
/etc/rsyslog.d                 0755 root:root
/etc/logrotate.conf            0644 root:root
/etc/logrotate.d               0755 root:root
/var/lib/logrotate/status      0640 root:root
/var/spool/rsyslog             0700 syslog:adm
/run/log                       0755 root:root
/run/log/journal               2755 root:systemd-journal
/var/log                       0775 root:syslog
/var/log/syslog/auth/kern      0640 syslog:adm
```

Kernel link protections were enabled:

```text
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 1
```

## Attacker Ingress Tested

As uid1001, the probe used realistic triggers:

```text
logger -p authpriv.warning -t "sudo[1]" ...
logger -p user.emerg -t wallroot ...
AF_UNIX datagrams to /dev/log and /run/systemd/journal/syslog
logger --journald with _UID=0, _PID=1, _COMM=systemd, OBJECT_PID=1, CODE_FILE=/etc/logrotate.d/rsyslog
systemd-cat -t roothelper -p warning ...
raw AF_UNIX stream connection to /run/systemd/journal/stdout with attacker-supplied unit "sshd.service"
```

Text logs showed spoofed log text only. Embedded newlines, tabbed `postrotate` text, ESC, and NUL bytes were escaped in rsyslog file output:

```text
/var/log/auth.log:
sudo[1]: RSJLD_..._LOGGER_AUTHPRIV rootcmd=id>/root/RSJLD_..._root_proof
fakehost sshd[222]: RSJLD_..._syslog line1#012postrotate#012#011/bin/sh -c 'id > /root/RSJLD_..._root_proof'#012endscript ESC=#033[31mRED#033[0m NUL=#000 [UFW BLOCK]
sudo[809597]: RSJLD_..._JOURNALD_NATIVE newline1

/var/log/syslog:
wallroot: RSJLD_..._EMERG_OMUSRMSG #033[31mroot-looking broadcast#033[0m
roothelper[809599]: RSJLD_..._SYSTEMD_CAT line1
roothelper[809605]: RSJLD_..._RAW_STDOUT line1
```

Journald kept trusted peer identity from kernel credentials. User-controlled fields such as `SYSLOG_IDENTIFIER`, `MESSAGE_ID`, `OBJECT_PID`, and `CODE_FILE` were accepted as data, but `_UID`, `_GID`, `_PID`, `_COMM`, and `_SYSTEMD_UNIT` stayed tied to the uid1001 sender:

```text
_TRANSPORT=journal
_UID=1001
_GID=1001
_SYSTEMD_UNIT=init.scope
SYSLOG_IDENTIFIER=sudo
MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1
OBJECT_PID=1
CODE_FILE=/etc/logrotate.d/rsyslog
_PID=809597

_TRANSPORT=stdout
_UID=1001
_GID=1001
_SYSTEMD_UNIT=init.scope
SYSLOG_IDENTIFIER=roothelper
MESSAGE=RSJLD_..._RAW_STDOUT line1
```

## Rsyslog and Logrotate Semantics

`rsyslogd -N1` validated the stock config. The active rsyslog actions were fixed file targets under `/var/log` plus `*.emerg :omusrmsg:*`; the grep for `template(`, `dynaFile`, `omprog`, `ompipe`, and executable `action(` patterns found no default message-derived path or command sink. `/etc/rsyslog.conf` drops privileges to `syslog:syslog`, uses `/var/spool/rsyslog`, and sets log file creation to `syslog:adm 0640`.

Logrotate config was root-owned and fixed. Relevant default directives:

```text
/etc/logrotate.conf: su root adm; create; include /etc/logrotate.d
/etc/logrotate.d/rsyslog: fixed /var/log/syslog/mail.log/kern.log/auth.log/user.log/cron.log; sharedscripts; postrotate /usr/lib/rsyslog/rsyslog-rotate
/etc/logrotate.d/ufw: fixed /var/log/ufw.log; fixed rsyslog-rotate postrotate
/etc/logrotate.d/bootlog: copytruncate on fixed /var/log/boot.log
/etc/logrotate.d/wtmp,btmp,dpkg,alternatives,ubuntu-pro-client: fixed package paths and fixed create ownership
```

No `mail`, `mailfirst`, or `maillast` directives were present in `/etc/logrotate.conf` or `/etc/logrotate.d`. `logrotate --version` reports default mail command `/usr/bin/mail`, but `mailutils`, `postfix`, and `bsd-mailx` were not installed, and the service does not pass attacker-controlled `-m` or config paths.

As uid1001, required filesystem and control preconditions failed:

```text
touch /var/log/RSJLD_*_create                         Permission denied
ln /etc/passwd /var/log/RSJLD_*_hardlink              Operation not permitted
ln -s /etc/passwd /var/log/RSJLD_*_symlink            Permission denied
truncate -s 0 /var/log/syslog                         Permission denied
touch /run/log/RSJLD_*_runlog_create                  Permission denied
touch /run/log/journal/RSJLD_*_journal_create         Permission denied
touch /var/spool/rsyslog/RSJLD_*_spool_create         Permission denied
touch /etc/logrotate.d/RSJLD_*.conf                   Permission denied
touch /etc/rsyslog.d/RSJLD_*.conf                     Permission denied
printf x >> /var/lib/logrotate/status                 Permission denied
systemctl start logrotate.service                     Interactive authentication required
systemctl kill -s HUP rsyslog.service                 Interactive authentication required
```

Running `logrotate -d /etc/logrotate.conf` directly as uid1001 was not privileged and failed at `su root adm` transitions:

```text
Reading state from file: /var/lib/logrotate/status
error opening state file /var/lib/logrotate/status: Permission denied
switching euid from 1001 to 0 and egid from 1001 to 4
error switching euid ... Operation not permitted
attacker_logrotate_debug_rc=1
```

Root debug mode of the stock config was non-mutating and showed simulated fixed-path behavior only: rsyslog logs would be recreated as `uid=103(syslog) gid=4(adm) mode=0640`, UFW as `syslog:adm 0640`, and the only rsyslog-related postrotate scripts were the root-owned `/usr/lib/rsyslog/rsyslog-rotate` invocations.

## Result

```text
ROOT_PROOF=NO
systemctl is-system-running: running
rsyslog.service active
systemd-journald.service active
logrotate.timer active
systemctl --failed: 0 loaded units listed
```

Reason this remains negative: uid1001 has socket-level log ingress, but the default stack treats that ingress as data. Rsyslog file actions are fixed and privilege-dropped, journald trusted fields are credential-derived, logrotate consumes root-owned config/state and fixed package paths, and uid1001 cannot create the symlink/hardlink/config/state/log-file preconditions that would turn create/copytruncate/postrotate/mail behavior into root LPE.
