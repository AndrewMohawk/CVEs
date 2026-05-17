# Negative: rsyslog, journald, and logrotate local log ingestion

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`.

Verdict: no uid1001-to-root LPE was found in the stock Ubuntu 24.04 Server rsyslog/journald local syslog ingestion path or the default logrotate interaction with those logs.

## Baseline

Probe: `pocs/rsyslog_journald_logrotate_probe.sh`

Full log: `logs/rsyslog-journald-logrotate.out`

Relevant target state:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
attacker: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
attacker_groups=attacker
logrotate 3.21.0-2build1
rsyslog   8.2312.0-3ubuntu9.2
systemd   255.4-1ubuntu8.15
systemctl is-system-running: running
rsyslog.service: active
systemd-journald.service: active
```

World-reachable sockets were present:

```text
/dev/log -> /run/systemd/journal/dev-log
/run/systemd/journal/dev-log    srw-rw-rw- root:root
/run/systemd/journal/socket     srw-rw-rw- root:root
/run/systemd/journal/stdout     srw-rw-rw- root:root
/run/systemd/journal/syslog     srw-rw-rw- root:root
```

The default config uses fixed file targets and drops rsyslog privileges:

```text
/etc/rsyslog.conf: module(load="imuxsock")
/etc/rsyslog.conf: $FileOwner syslog, $FileGroup adm, $FileCreateMode 0640
/etc/rsyslog.conf: $PrivDropToUser syslog, $PrivDropToGroup syslog
/etc/rsyslog.d/50-default.conf: fixed /var/log/auth.log, /var/log/syslog, /var/log/kern.log, /var/log/mail.log, /var/log/mail.err
/etc/rsyslog.d/20-ufw.conf: fixed /var/log/ufw.log when message contains "[UFW "
/etc/logrotate.d/rsyslog: fixed /var/log/syslog/mail/kern/auth/user/cron paths
/usr/lib/rsyslog/rsyslog-rotate: systemctl kill -s HUP rsyslog.service
```

## Attacker Input Tested

As uid1001, the probe sent syslog datagrams to `/dev/log` and `/run/systemd/journal/syslog` containing fake `sudo[1]` metadata, embedded newlines, a fake `postrotate` block, shell syntax targeting `/root/RSJL_*_root_proof`, ESC, and NUL bytes.

Observed `/var/log/auth.log` output encoded the dangerous bytes as log text:

```text
fakehost sudo[1]: RSJL_..._syslog line1#012postrotate#012#011/bin/sh -c 'id > /root/RSJL_..._root_proof'#012endscript ESC=#033[31mRED#033[0m NUL=#000 END
fakehost sudo[1]: RSJL_..._log line1#012postrotate#012#011/bin/sh -c 'id > /root/RSJL_..._root_proof'#012endscript ESC=#033[31mRED#033[0m NUL=#000 END
```

As uid1001, the probe also used `logger --journald` with spoofed trusted fields:

```text
MESSAGE=RSJL_..._JOURNALD_NATIVE id > /root/RSJL_..._root_proof
SYSLOG_IDENTIFIER=sudo
SYSLOG_FACILITY=10
_PID=1
_UID=0
_GID=0
OBJECT_PID=1
```

Journald retained kernel-provided sender credentials:

```text
_UID=1001
_GID=1001
_TRANSPORT=journal
SYSLOG_IDENTIFIER=sudo
OBJECT_PID=1
_PID=<actual logger pid>
```

The stdout stream path via `systemd-cat` split newline-delimited input into separate journal records and kept `_UID=1001`.

## Boundary Checks

uid1001 could not create, link, or truncate the log paths needed for symlink/hardlink/logrotate preconditions:

```text
touch /var/log/RSJL_*_create: Permission denied
ln /etc/passwd /var/log/RSJL_*_hardlink: Operation not permitted
ln -s /etc/passwd /var/log/RSJL_*_symlink: Permission denied
truncate -s 0 /var/log/syslog: Permission denied
touch /run/log/RSJL_*_runlog_create: Permission denied
ln -s /etc/passwd /run/log/RSJL_*_runlog_symlink: Permission denied
touch /run/log/journal/RSJL_*_journal_create: Permission denied
```

Kernel protections were enabled:

```text
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 1
```

uid1001 also could not trigger the root maintenance boundary:

```text
systemctl start logrotate.service: Interactive authentication required
systemctl kill -s HUP rsyslog.service: Interactive authentication required
```

Stock `logrotate -d -f /etc/logrotate.conf` showed create/compress/postrotate behavior only for package-defined paths. For rsyslog logs, it would rename fixed `/var/log/syslog`, `/var/log/kern.log`, and `/var/log/auth.log`, create new logs as `uid=103(syslog) gid=4(adm) mode=0640`, and run the fixed root-owned `/usr/lib/rsyslog/rsyslog-rotate` script. No message bytes were parsed as logrotate config, path names, or shell.

## Result

```text
ROOT_PROOF=NO
probe_owned_files_after_cleanup=
journal_entries_after_cleanup=0
text_log_entries_after_cleanup=0
systemctl is-system-running: running
rsyslog.service: active
systemd-journald.service: active
systemctl --failed: 0 loaded units listed
```

Reason this stayed negative: normal uid1001 messages can spoof log text and select configured facilities, but default rsyslog uses root-owned fixed destinations, log output escapes embedded controls/newlines, journald keeps trusted sender credentials from the kernel, uid1001 cannot place filesystem objects under `/var/log` or `/run/log`, and logrotate executes fixed root-owned config/scripts rather than data from log contents.
