# Negative: log ingestion and root log maintenance paths

Verdict: no uid1001 -> root local privilege escalation was found in the default Ubuntu 24.04 Server log ingestion, journald forwarding, logrotate, savelog/dmesg, utmp/wtmp/btmp, or relevant apport log/crash cleanup paths.

## Target and package proof

Target container: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`.

Default target state:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
systemctl is-system-running: running
attacker: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Affected/default packages in this slice:

```text
apport                         2.28.1-0ubuntu3.8
apport-core-dump-handler       2.28.1-0ubuntu3.8
bsdutils                       1:2.39.3-9ubuntu6.5
debianutils                    5.17build1
login                          1:4.13+dfsg1-4ubuntu3.2
logrotate                      3.21.0-2build1
passwd                         1:4.13+dfsg1-4ubuntu3.2
rsyslog                        8.2312.0-3ubuntu9.2
systemd                        255.4-1ubuntu8.15
util-linux                     2.39.3-9ubuntu6.5
```

Default-reachable units/sockets:

```text
rsyslog.service                 loaded active running
systemd-journald.service        loaded active running
systemd-update-utmp.service     loaded active exited
apport-forward.socket           loaded active listening
systemd-journald-dev-log.socket loaded active running
systemd-journald.socket         loaded active running
logrotate.timer                 loaded active waiting
```

World-reachable log sockets:

```text
/dev/log -> /run/systemd/journal/dev-log
/run/systemd/journal/dev-log    srw-rw-rw- root:root
/run/systemd/journal/socket     srw-rw-rw- root:root
/run/systemd/journal/stdout     srw-rw-rw- root:root
/run/systemd/journal/syslog     srw-rw-rw- root:root
```

## Code and config paths

Rsyslog default ingestion and privilege drop:

```text
/etc/rsyslog.conf:13                 module(load="imuxsock")
/etc/rsyslog.conf:24-25              module(load="imklog" permitnonkernelfacility="on")
/etc/rsyslog.conf:37-43              FileOwner/FileGroup plus PrivDropToUser syslog, PrivDropToGroup syslog
/etc/rsyslog.conf:53                 include /etc/rsyslog.d/*.conf
/etc/rsyslog.d/50-default.conf:8-15  fixed facility-to-file paths under /var/log
/etc/rsyslog.d/50-default.conf:39    *.emerg to :omusrmsg:*
/etc/rsyslog.d/20-ufw.conf:2         :msg,contains,"[UFW " /var/log/ufw.log
/usr/lib/tmpfiles.d/00rsyslog.conf:6-12 /var/log root:syslog 0775 and fixed syslog-owned log modes
/usr/lib/systemd/system/rsyslog.service:10-23 fixed ExecStart and NoNewPrivileges=yes
```

Runtime proof: `rsyslogd` ran as `syslog:syslog` with no effective capabilities and `NoNewPrivs: 1`.

Journald forwarding and credential binding:

```text
/usr/lib/systemd/system/systemd-journald.socket:22-29     dev-facing journal socket/stdout, PassCredentials=yes, SocketMode=0666
/usr/lib/systemd/system/systemd-journald-dev-log.socket:22-35 /dev/log socket, PassCredentials=yes, SocketMode=0666
/usr/lib/systemd/system/syslog.socket:26-29               /run/systemd/journal/syslog, PassCredentials=yes
/usr/lib/systemd/journald.conf.d/syslog.conf:4-5          ForwardToSyslog=yes
/usr/lib/systemd/system/systemd-journald.service:30-61    fixed journald daemon, NoNewPrivileges=yes, AF_UNIX/AF_NETLINK only
```

Root log rotation and maintenance:

```text
/usr/lib/systemd/system/logrotate.timer:5-8        daily persistent timer
/usr/lib/systemd/system/logrotate.service:8-9      ExecStart=/usr/sbin/logrotate /etc/logrotate.conf
/usr/lib/systemd/system/logrotate.service:22-34    hardening including PrivateTmp, ProtectSystem=full, RestrictNamespaces
/etc/logrotate.conf:10                             su root adm
/etc/logrotate.conf:25                             include /etc/logrotate.d
/etc/logrotate.d/rsyslog:1-17                      fixed syslog/auth/kern/mail paths; postrotate /usr/lib/rsyslog/rsyslog-rotate
/usr/lib/rsyslog/rsyslog-rotate:3-4                systemctl kill -s HUP rsyslog.service
/etc/logrotate.d/ufw:1-12                          fixed /var/log/ufw.log; fixed rsyslog-rotate postrotate
/etc/logrotate.d/apport:1-8                        fixed /var/log/apport.log
/etc/logrotate.d/wtmp:2-7                          fixed /var/log/wtmp, create 0664 root utmp
/etc/logrotate.d/btmp:2-6                          fixed /var/log/btmp, create 0660 root utmp
```

Dmesg/savelog and utmp/wtmp:

```text
/usr/lib/systemd/system/dmesg.service:6-10         fixed /var/log/dmesg, savelog -m640 -q -p -n -c 5, journalctl --dmesg
/usr/bin/savelog:83-88                             PATH append and gzip defaults
/usr/bin/savelog:187-259                           quoted filename handling and fixed savedir derivation
/usr/bin/savelog:260-355                           mv/rm/chown/chmod with --; optional -x hook only if caller supplies it
/usr/lib/systemd/system/systemd-update-utmp.service:20-26 fixed /var/log/wtmp service updates
/usr/lib/systemd/system/systemd-update-utmp-runlevel.service:16-25 fixed runlevel update
/usr/lib/tmpfiles.d/var.conf:15-17                 /var/log/wtmp, btmp, lastlog root:utmp modes
/usr/lib/tmpfiles.d/systemd.conf:11                /run/utmp root:utmp mode
```

Apport log/crash cleanup:

```text
/usr/lib/systemd/system/apport-forward.socket:3-11      container-only /run/apport.socket, SocketMode=0600, PassCredentials=true
/usr/lib/systemd/system/apport-autoreport.path:1-7      PathChanged=/var/crash, gated by /var/lib/apport/autoreport
/usr/lib/systemd/system/apport-autoreport.service:1-9   whoopsie-upload-all, gated by /var/lib/apport/autoreport
/etc/cron.daily/apport:1-5                              find /var/crash cleanup with -exec rm, no shell
/usr/share/apport/apport:229-249                        APPORT_LOG_FILE only from process environment; default /var/log/apport.log
/usr/share/apport/package-hooks/source_apport.py:16-23  glob /var/crash/* passed as stat argv, not shell
```

`apport-autoreport.path` and service were not active in the default target because `/var/lib/apport/autoreport` did not exist. `/run/apport.socket` was active only because this Docker target is a container, but it was mode `0600 root:root`.

## Attacker triggers tested

The probe used only `uid=1001(attacker)` for attacker-controlled input and a root marker at `/root/log_ingest_rotation_marker` to detect command execution or root file write.

Attacker-controlled syslog/journald input:

```sh
logger -p authpriv.warning -t "${probe}_auth;touch_/root/log_ingest_rotation_marker" -- $'line1\npostrotate\n  id > /root/log_ingest_rotation_marker\nendscript'
logger -p mail.err -t "${probe}_mail../../root" -- "mail facility should only create fixed mail logs"
logger -p user.warning -t "${probe}_ufw" -- '[UFW BLOCK] IN=lo OUT= MAC= cmd=$(id>/root/log_ingest_rotation_marker)'
printf 'MESSAGE=%s\nPRIORITY=2\nSYSLOG_IDENTIFIER=%s\n_UID=0\n_PID=1\n' \
  "journald spoof attempt $probe \$(id>/root/log_ingest_rotation_marker)" \
  "${probe}_journal" | logger --journald
```

Observed log materialization:

```text
/var/log/auth.log syslog:adm:640
  ${probe}_auth;touch_/root/log_ingest_rotation_marker: line1#012postrotate#012  id > /root/log_ingest_rotation_marker#012endscript

/var/log/syslog syslog:adm:640
  ${probe}_mail../../root: mail facility should only create fixed mail logs
  ${probe}_ufw: [UFW BLOCK] IN=lo OUT= MAC= cmd=$(id>/root/log_ingest_rotation_marker)
  ${probe}_journal[pid]: journald spoof attempt ... $(id>/root/log_ingest_rotation_marker)

/var/log/mail.log syslog:adm:640     fixed path created by mail.* rule
/var/log/mail.err syslog:adm:640     fixed path created by mail.err rule
/var/log/ufw.log syslog:adm:640      fixed path created by [UFW ] content rule
```

Newlines were encoded as `#012`; shell metacharacters stayed literal. Logger-controlled facility and UFW content could only select fixed configured files.

Journald trusted field spoofing failed:

```text
_UID=1001
PRIORITY=2
MESSAGE=journald spoof attempt ... $(id>/root/log_ingest_rotation_marker)
SYSLOG_IDENTIFIER=${probe}_journal
_PID=<logger pid>
```

The attempted `_UID=0` and `_PID=1` fields did not override journald's trusted sender credentials.

Attacker attempts to trigger root maintenance services:

```text
runuser -u attacker -- systemctl start logrotate.service
  rc=1, Failed to start logrotate.service: Interactive authentication required.

runuser -u attacker -- systemctl restart dmesg.service
  rc=1, Failed to restart dmesg.service: Interactive authentication required.
```

Kernel/dmesg input checks:

```text
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 1
/dev/kmsg  crw-r--r-- root:root
/proc/kmsg -r-------- root:root
attacker dmesg: read kernel buffer failed: Operation not permitted
attacker write /dev/kmsg: Permission denied
```

Attacker-controlled `/var/crash` filenames:

```text
/var/crash/${probe};id-root-marker.crash
/var/crash/${probe}<newline>postrotate-id-root-marker.crash
/var/crash/${probe}.symlink.crash -> /root/log_ingest_rotation_marker
/var/crash/123456789012/${probe}.inner -> /root/log_ingest_rotation_marker
```

Running the default root maintenance paths after those inputs:

```sh
systemctl start logrotate.service
systemctl start dmesg.service
/etc/cron.daily/apport
```

Result:

```text
root_start_logrotate_rc:0
root_start_dmesg_rc:0
root_cron_apport_rc:0
no_root_marker
```

The old malicious regular crash files and the old numeric crash directory were removed safely by `/etc/cron.daily/apport`. The symlink report remained until explicit cleanup and was not followed.

Forced debug of the default logrotate config showed fixed rotations and fixed scripts only:

```text
logrotate -d -f /etc/logrotate.conf

rotating pattern: /var/log/syslog /var/log/mail.log /var/log/kern.log /var/log/auth.log /var/log/user.log /var/log/cron.log
renaming /var/log/syslog to /var/log/syslog.1
creating new /var/log/syslog mode = 0640 uid = 103 gid = 4
running script with args ... "/usr/lib/rsyslog/rsyslog-rotate"

rotating pattern: /var/log/btmp
renaming /var/log/btmp to /var/log/btmp.1
creating new /var/log/btmp mode = 0660 uid = 0 gid = 43

rotating pattern: /var/log/wtmp
renaming /var/log/wtmp to /var/log/wtmp.1
creating new /var/log/wtmp mode = 0664 uid = 0 gid = 43
```

Debug mode does not modify files, but it proves the path and script choices logrotate would take on a real rotation. The inputs are root-owned config/state and fixed log path patterns, not log contents.

## Why this is not exploitable in the default state

* The only attacker-controlled primitive is log record content and selected syslog facility/tag. Default rsyslog routes these records to fixed paths; it does not derive filenames or commands from tags, message bodies, or journald fields.
* Rsyslog's parser/formatter runs after the daemon has dropped to `syslog:syslog`, with no effective capabilities and `NoNewPrivs: 1`. This audit did not find a uid1001 path to execute code in rsyslog, and even a hypothetical syslog compromise would still need a separate root pivot.
* Journald sockets are world-writable by design, but `PassCredentials=yes` is enabled and trusted fields were taken from SCM credentials. `_UID=0` and `_PID=1` spoofing did not work.
* Root logrotate reads only root-owned `/etc/logrotate.conf`, `/etc/logrotate.d/*`, and `/var/lib/logrotate/status`. The attacker cannot write `/var/log`, `/etc/logrotate.d`, or the state file.
* Logrotate postrotate scripts in scope call only `/usr/lib/rsyslog/rsyslog-rotate`, which sends a HUP to the fixed `rsyslog.service`.
* `dmesg.service` uses fixed `/var/log/dmesg` and kernel journal input. The attacker cannot write `/dev/kmsg`, read dmesg, or start/restart the service.
* `wtmp`, `btmp`, `lastlog`, and `/run/utmp` are root:utmp files. The attacker is not in `utmp` and cannot write or replace those files.
* Apport autoreporting is not default-active, the container forwarding socket is root-only, and the daily `/var/crash` cleanup uses `find -exec rm ... '{}'` without a shell. Malicious filenames were deleted or left as inert symlinks; no root marker was created.

## Cleanup

Probe cleanup removed:

```text
/root/log_ingest_rotation_marker
/tmp/attacker-logrotate.out
/tmp/attacker-dmesg.out
/var/crash/*LOGINGEST*
/var/crash/123456789012
```

Optional logs created only by the probe and absent before testing were removed:

```text
/var/log/mail.log
/var/log/mail.err
/var/log/ufw.log
```

Final cleanup check:

```text
systemctl is-system-running: running
attacker: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
absent:/var/log/mail.log
absent:/var/log/mail.err
absent:/var/log/ufw.log
absent:/root/log_ingest_rotation_marker
no /var/crash LOGINGEST residue
```

The syslog/auth log lines generated by the probe remain in the normal system logs as expected.

## Why routine scanners may miss this boundary

Generic writable-directory checks will flag `/dev/log`, journald's `0666` sockets, `/var/crash`, and `/var/log root:syslog 0775`, but they usually do not follow the whole data path into rsyslog's fixed selectors, journald credential binding, logrotate's `su root adm` handling, or apport's exact `find -exec` cleanup behavior. The interesting question is not whether uid1001 can write log records; it is whether any root-maintained path later treats those records or filenames as code or destination paths. In this default target, it did not.

## Suggested hardening

* Keep `PassCredentials=yes` on journald/syslog sockets and add regression tests that client-supplied `_UID`, `_PID`, and other trusted fields cannot override SCM credentials.
* Consider documenting in the Ubuntu rsyslog packaging why `mail.err` is created by the default rules but not rotated by `/etc/logrotate.d/rsyslog`; this is not an LPE, but it is a maintenance inconsistency.
* Keep logrotate configs and state root-owned; avoid future package logrotate snippets that derive paths or shell commands from log contents or writable directories.
* In apport, preserve `find -exec ... '{}'` style cleanup and `O_NOFOLLOW` handling in report processing; avoid shelling out with crash filenames.
* In `dmesg.service`, keep the fixed absolute savelog path and do not use savelog's optional `-x` hook from any attacker-influenced configuration.
