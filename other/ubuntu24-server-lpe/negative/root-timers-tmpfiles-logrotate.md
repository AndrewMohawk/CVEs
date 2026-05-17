# Negative: root timers, tmpfiles, cron, logrotate, man-db, landscape, update-notifier, needrestart

Status: no valid LPE from attacker uid 1001 was found in this slice.

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4, systemd PID 1, `systemctl is-system-running` = `running`.

Attacker proof:

```sh
id attacker
# uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Default package/version proof from `baseline/live-target-standard/packages.txt`:

```text
apt 2.8.3
cron 3.0pl1-184ubuntu2
landscape-common 24.02-0ubuntu5.7
logrotate 3.21.0-2build1
man-db 2.12.0-4build2
needrestart 3.6-7ubuntu4.5
sysstat 12.6.1-2
ubuntu-minimal 1.539.2
ubuntu-server 1.539.2
ubuntu-standard 1.539.2
unattended-upgrades 2.9.1+nmu4ubuntu1
update-notifier-common 3.192.68.2
```

Default active/enabled proof:

```text
cron.service active running
apt-daily.timer active waiting
apt-daily-upgrade.timer active waiting
dpkg-db-backup.timer active waiting
logrotate.timer active waiting
man-db.timer active waiting
motd-news.timer active waiting
sysstat-collect.timer active waiting
sysstat-summary.timer active waiting
systemd-tmpfiles-clean.timer active waiting
update-notifier-download.timer active waiting
update-notifier-motd.timer active waiting
unattended-upgrades.service active running
```

Apport `/var/crash` was intentionally excluded per task instruction. I only noted that logrotate reads `/etc/logrotate.d/apport`; I did not triage Apport crash handling here.

## Attacker write reachability

The normal attacker cannot write the root job configuration/state directories that would make the shell/PATH/config primitives exploitable:

```sh
docker exec --user attacker ubuntu24-server-lpe-target sh -lc '
for p in /etc/landscape /var/cache/man /run/screen /var/local /var/mail \
  /var/spool/cron/crontabs /usr/share/package-data-downloads \
  /var/lib/update-notifier /var/lib/update-notifier/package-data-downloads \
  /var/lib/update-notifier/user.d /var/cache /var/log /etc/cron.d \
  /etc/logrotate.d /etc/tmpfiles.d /etc/needrestart/conf.d \
  /etc/apt/apt.conf.d; do
    touch "$p/.attacker_write_test" 2>&1 && rm -f "$p/.attacker_write_test" && echo "$p WRITABLE" || echo "$p NO"
done'
```

Result: every path above returned `Permission denied` except `/run/screen`, which is intentionally sticky-world-writable.

Relevant mode evidence:

```text
/etc/landscape                      drwxrwxr-x root:landscape
/var/cache/man                      drwxr-xr-x man:man
/run/screen                         drwxrwxrwt root:utmp
/var/local                          drwxrwsr-x root:staff
/var/mail                           drwxrwsr-x root:mail
/var/spool/cron/crontabs            drwx-wx--T root:crontab
/usr/share/package-data-downloads   drwxr-xr-x root:root
/var/lib/update-notifier            drwxr-xr-x root:root
/var/backups                        drwxr-xr-x root:root
/var/cache/apt/archives             drwxr-xr-x root:root
/var/lib/apt/periodic               drwxr-xr-x root:root
/var/log                            drwxrwxr-x root:syslog
/usr/local/bin                      drwxr-xr-x root:root
/usr/local/sbin                     drwxr-xr-x root:root
```

Kernel link protections were enabled:

```text
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 1
```

## Cron and cron-owned paths

Default root cron config:

```text
/etc/crontab:7  SHELL=/bin/sh
/etc/crontab:19 17 * * * * root cd / && run-parts --report /etc/cron.hourly
/etc/crontab:20 25 6 * * * root test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
/etc/crontab:21 47 6 * * 7 root test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
/etc/crontab:22 52 6 1 * * root test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
/lib/systemd/system/cron.service:7 EnvironmentFile=-/etc/default/cron
/lib/systemd/system/cron.service:8 ExecStart=/usr/sbin/cron -f -P $EXTRA_OPTS
```

The root crontab uses an unqualified `run-parts`, but the inherited systemd manager `PATH` is:

```text
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Attacker cannot write any PATH directory:

```text
/usr/local/bin NO
/usr/local/sbin NO
/usr/bin NO
/usr/sbin NO
/bin NO
/sbin NO
```

User crontabs do not cross privilege boundaries. Test:

```sh
runuser -u attacker -- sh -lc 'printf "* * * * * id > /tmp/attacker_cron_id\n" | crontab - && crontab -l'
ls -l /var/spool/cron/crontabs/attacker
```

Result:

```text
* * * * * id > /tmp/attacker_cron_id
-rw------- 1 attacker crontab ... /var/spool/cron/crontabs/attacker
```

This schedules code as `attacker`, not root.

The legacy cron daily scripts for apt, dpkg, logrotate, man-db, and sysstat all skip when systemd is present:

```text
/etc/cron.daily/apt-compat:10-12 if [ -d /run/systemd/system ]; then exit 0; fi
/etc/cron.daily/dpkg:3-5 if [ -d /run/systemd/system ]; then exit 0; fi
/etc/cron.daily/logrotate:3-5 if [ -d /run/systemd/system ]; then exit 0; fi
/etc/cron.daily/man-db:7-9 if [ -d /run/systemd/system ]; then exit 0; fi
/etc/cron.daily/sysstat:12-13 [ ! -d /run/systemd/system ] || exit 0
```

## Logrotate

Default service and config:

```text
/usr/lib/systemd/system/logrotate.service:8  ExecStart=/usr/sbin/logrotate /etc/logrotate.conf
/usr/lib/systemd/system/logrotate.service:30 PrivateTmp=true
/usr/lib/systemd/system/logrotate.service:37 ProtectSystem=full
/etc/logrotate.conf:10 su root adm
/etc/logrotate.conf:25 include /etc/logrotate.d
```

Default rotate snippets use root-owned log paths and absolute postrotate helpers:

```text
/etc/logrotate.d/rsyslog:15-17 postrotate /usr/lib/rsyslog/rsyslog-rotate
/etc/logrotate.d/ufw:10-12 postrotate [ -x /usr/lib/rsyslog/rsyslog-rotate ] && /usr/lib/rsyslog/rsyslog-rotate || true
/usr/lib/rsyslog/rsyslog-rotate:3-4 systemctl kill -s HUP rsyslog.service
```

Attacker cannot append to or replace default rotated logs:

```text
/var/log/syslog NO
/var/log/auth.log NO
/var/log/mail.log NO
/var/log/cron.log NO
/var/log/boot.log NO
/var/log/dpkg.log NO
/var/log/apt/history.log NO
/var/log/unattended-upgrades/unattended-upgrades.log NO
/var/log/landscape/sysinfo.log NO
/var/log/wtmp NO
/var/log/btmp NO
```

`logger` can inject content into syslog via the daemon, but logrotate never interprets log content as commands. `logrotate -d /etc/logrotate.conf` showed it only reads root-owned config and rotates fixed path patterns under effective root/adm.

## systemd-tmpfiles and sticky directories

Relevant tmpfiles config:

```text
/etc/tmpfiles.d/screen-cleanup.conf:2 d /run/screen 1777 root utmp
/usr/lib/tmpfiles.d/screen-cleanup.conf:1 d /run/screen 0777 root utmp
/usr/lib/tmpfiles.d/cron-daemon-common.conf:1 d /var/spool/cron/crontabs 1730 root crontab
/usr/lib/tmpfiles.d/man-db.conf:1 d /var/cache/man 0755 man man 1w
/usr/lib/tmpfiles.d/tmp.conf:11 D /tmp 1777 root root 30d
/usr/lib/tmpfiles.d/var.conf:15 f /var/log/wtmp 0664 root utmp -
/usr/lib/tmpfiles.d/var.conf:16 f /var/log/btmp 0660 root utmp -
/usr/lib/tmpfiles.d/00rsyslog.conf:6 z /var/log 0775 root syslog -
```

`/run/screen` is attacker-writable, so I tested both cleanup and create against attacker-owned symlinks and old files:

```sh
runuser -u attacker -- sh -lc '
  ln -s /root/tmpfiles_screen_pwned /run/screen/attacker_shadow_link
  printf attacker > /run/screen/attacker_old_file
  touch -d 1970-01-01 /run/screen/attacker_old_file
'
systemd-tmpfiles --clean --prefix=/run/screen
systemd-tmpfiles --create --prefix=/run/screen
ls -l /root/tmpfiles_screen_pwned /run/screen/attacker_shadow_link /run/screen/attacker_old_file
```

Result:

```text
/run/screen/attacker_old_file remained attacker:attacker
/run/screen/attacker_shadow_link remained attacker:attacker -> /root/tmpfiles_screen_pwned
/root/tmpfiles_screen_pwned did not exist
```

Hardlink probes also failed:

```text
ln /etc/shadow /tmp/shadow_hardlink -> Operation not permitted
ln /etc/shadow /run/screen/shadow_hardlink -> Invalid cross-device link
```

No tmpfiles root write or ownership-change primitive was reachable from uid 1001.

## man-db

Default service:

```text
/lib/systemd/system/man-db.service:9  ExecStart=+/usr/bin/install -d -o man -g man -m 0755 /var/cache/man
/lib/systemd/system/man-db.service:11 ExecStart=/usr/bin/mandb --quiet
/lib/systemd/system/man-db.service:12 User=man
/lib/systemd/system/man-db.service:19 PrivateTmp=true
/lib/systemd/system/man-db.service:27 ProtectSystem=full
```

Config maps only root-owned system manpaths into `/var/cache/man`:

```text
/etc/manpath.config:20 MANDATORY_MANPATH /usr/man
/etc/manpath.config:21 MANDATORY_MANPATH /usr/share/man
/etc/manpath.config:22 MANDATORY_MANPATH /usr/local/share/man
/etc/manpath.config:66 MANDB_MAP /usr/man /var/cache/man/fsstnd
/etc/manpath.config:67 MANDB_MAP /usr/share/man /var/cache/man
/etc/manpath.config:68 MANDB_MAP /usr/local/man /var/cache/man/oldlocal
/etc/manpath.config:69 MANDB_MAP /usr/local/share/man /var/cache/man/local
```

Attacker cannot replace `/var/cache/man`:

```text
rmdir /var/cache/man -> Permission denied
mv /var/cache/man /var/cache/man.attacker -> Permission denied
ln -s /root/manpwn /var/cache/man_link_probe -> Permission denied
```

Attacker-controlled `MANPATH` affects only the attacker's own cache:

```sh
runuser -u attacker -- sh -lc '
  install -d /home/attacker/man/man1
  printf ".TH NR 1\n.SH NAME\nnr - test\n" > /home/attacker/man/man1/nr.1
  MANPATH=/home/attacker/man mandb -q
'
```

Result:

```text
/home/attacker/man/index.db attacker:attacker
/var/cache/man/index.db man:man unchanged
```

## apt, unattended-upgrades, update-notifier, and release-upgrader timers

Default timer service paths:

```text
/usr/lib/systemd/system/apt-daily.service:8 ExecStartPre=-/usr/lib/apt/apt-helper wait-online
/usr/lib/systemd/system/apt-daily.service:9 ExecStart=/usr/lib/apt/apt.systemd.daily update
/usr/lib/systemd/system/apt-daily-upgrade.service:9 ExecStart=/usr/lib/apt/apt.systemd.daily install
/usr/lib/systemd/system/update-notifier-download.service:5 ExecStart=/usr/lib/update-notifier/package-data-downloader
/usr/lib/systemd/system/update-notifier-motd.service:5 ExecStart=/usr/lib/ubuntu-release-upgrader/release-upgrade-motd
/usr/lib/systemd/system/unattended-upgrades.service:6 ExecStart=/usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
```

APT periodic config in the target:

```text
/etc/apt/apt.conf.d/10periodic:1 APT::Periodic::Update-Package-Lists "1";
/etc/apt/apt.conf.d/20auto-upgrades:1 APT::Periodic::Update-Package-Lists "1";
/etc/apt/apt.conf.d/20auto-upgrades:2 APT::Periodic::Unattended-Upgrade "1";
/etc/apt/apt.conf.d/20archive:1 APT::Archives::MaxAge "30";
/etc/apt/apt.conf.d/20archive:2 APT::Archives::MinAge "2";
/etc/apt/apt.conf.d/20archive:3 APT::Archives::MaxSize "500";
```

The container-derived target also has Docker apt config that sets `APT::Periodic::Enable "0"`; I did not use that artifact as a security conclusion. I inspected the root script semantics anyway.

`apt.systemd.daily` uses unquoted variables from apt config, but those values come from root-owned `/etc/apt/apt.conf.d` and root-owned state/cache directories:

```text
/usr/lib/apt/apt.systemd.daily:325 eval $(apt-config shell StateDir Dir::State/d)
/usr/lib/apt/apt.systemd.daily:326 exec 3>${StateDir}/daily_lock
/usr/lib/apt/apt.systemd.daily:355 AutoAptEnable=1
/usr/lib/apt/apt.systemd.daily:356 eval $(apt-config shell AutoAptEnable APT::Periodic::Enable)
/usr/lib/apt/apt.systemd.daily:395-402 reads APT::Periodic intervals via apt-config
/usr/lib/apt/apt.systemd.daily:451-454 runs apt-get -y update and touches /var/lib/apt/periodic/update-stamp
/usr/lib/apt/apt.systemd.daily:494-496 runs unattended-upgrade and touches /var/lib/apt/periodic/upgrade-stamp
/usr/lib/apt/apt.systemd.daily:507-508 runs apt-get -y clean
```

Attacker cannot write the relevant apt state/config/cache paths:

```text
/etc/apt/apt.conf.d NO
/var/lib/apt/periodic NO
/var/cache/apt/archives NO
/var/cache/apt/archives/partial NO
/var/backups NO
```

`package-data-downloader` executes per-package hook scripts if files exist in `/usr/share/package-data-downloads`, but that directory is root-owned and empty on this target:

```text
/usr/lib/update-notifier/package-data-downloader:36 DATADIR = "/usr/share/package-data-downloads/"
/usr/lib/update-notifier/package-data-downloader:37 STAMPDIR = "/var/lib/update-notifier/package-data-downloads/"
/usr/lib/update-notifier/package-data-downloader:161-169 os.listdir(DATADIR)
/usr/lib/update-notifier/package-data-downloader:247-255 parses hook and sets command = [para["Script"]]
/usr/lib/update-notifier/package-data-downloader:271-287 downloads verified files then subprocess.call(command)
```

State permissions:

```text
/usr/share/package-data-downloads                        drwxr-xr-x root:root, no files
/var/lib/update-notifier/package-data-downloads           drwxr-xr-x root:root
/var/lib/update-notifier/package-data-downloads/partial   drwx------ _apt:root
/var/lib/update-notifier/user.d                           drwxr-xr-x root:root
```

`release-upgrade-motd` writes a root-owned stamp under a root-owned directory:

```text
/usr/lib/ubuntu-release-upgrader/release-upgrade-motd:23 stamp=/var/lib/ubuntu-release-upgrader/release-upgrade-available
/usr/lib/ubuntu-release-upgrader/release-upgrade-motd:31 /usr/lib/ubuntu-release-upgrader/check-new-release -q > "$stamp" &
/usr/lib/ubuntu-release-upgrader/release-upgrade-motd:37-39 if uid is root and no stamp, write "$stamp"
/var/lib/ubuntu-release-upgrader drwxr-xr-x root:root
```

Attacker could not write `/var/lib/ubuntu-release-upgrader`, `/var/lib/update-manager`, or `/var/lib/update-notifier`.

`package-system-locked` has a permissive polkit action, but `pkexec` and `policykit-1` are not installed on this target:

```text
com.ubuntu.update-notifier.pkexec.package-system-locked implicit inactive: yes, active: yes
/usr/lib/update-notifier/package-system-locked:6-11 checks apt locks with fuser
dpkg -l pkexec policykit-1 polkitd:
  un pkexec <none>
  un policykit-1 <none>
  ii polkitd 124-2ubuntu1.24.04.3
/usr/bin/pkexec: No such file or directory
```

Direct attacker execution of `/usr/lib/update-notifier/package-system-locked` is unprivileged and returned `exit:0`; `pkexec ...` failed with `pkexec: not found`.

## landscape/update-motd

Default MOTD landscape script:

```text
/etc/update-motd.d/50-landscape-sysinfo -> /usr/share/landscape/landscape-sysinfo.wrapper
/usr/share/landscape/landscape-sysinfo.wrapper:5 CACHE="/var/lib/landscape/landscape-sysinfo.cache"
/usr/share/landscape/landscape-sysinfo.wrapper:24-28 runs /usr/bin/landscape-sysinfo and writes "$CACHE"
/usr/share/landscape/landscape-sysinfo.wrapper:29 chmod 0644 "$CACHE"
```

Normal attacker cannot place the cache symlink:

```text
runuser -u attacker -- ln -s /root/landscape_attacker_to_root_probe /var/lib/landscape/landscape-sysinfo.cache
-> Permission denied
```

A non-counting service-account edge exists: if code is already running as `landscape`, it can replace `/var/lib/landscape/landscape-sysinfo.cache` with a symlink and the root-run wrapper follows it:

```sh
runuser -u landscape -- sh -lc '
  rm -f /var/lib/landscape/landscape-sysinfo.cache
  ln -s /root/landscape_service_to_root_probe /var/lib/landscape/landscape-sysinfo.cache
'
/etc/update-motd.d/50-landscape-sysinfo >/tmp/landscape_symlink.out 2>/tmp/landscape_symlink.err
ls -l /root/landscape_service_to_root_probe /var/lib/landscape/landscape-sysinfo.cache
```

Result:

```text
landscape:x:106:108::/var/lib/landscape:/usr/sbin/nologin
/var/lib/landscape drwxr-xr-x landscape:landscape
/root/landscape_service_to_root_probe -rw-r--r-- root:root
/var/lib/landscape/landscape-sysinfo.cache -> /root/landscape_service_to_root_probe landscape:landscape
```

Impact: `landscape` service account to root file write on root MOTD execution. This does not satisfy the requested uid 1001 normal-user scope because attacker is not in group `landscape` and cannot write `/var/lib/landscape` or `/etc/landscape`.

## needrestart

Default apt hook:

```text
/etc/apt/apt.conf.d/99needrestart:8 DPkg::Post-Invoke {"test -x /usr/lib/needrestart/apt-pinvoke && /usr/lib/needrestart/apt-pinvoke -m u || true"; };
/usr/lib/needrestart/apt-pinvoke:18 RUNDIR=/run/needrestart
/usr/lib/needrestart/apt-pinvoke:27 if [ -e "$RUNDIR/unpacked" ]; then
/usr/lib/needrestart/apt-pinvoke:48 rm -f "$RUNDIR/unpacked"
/usr/lib/needrestart/apt-pinvoke:49 exec /usr/sbin/needrestart "$@"
```

`/run/needrestart` did not exist during steady state and attacker had no writable path into apt/dpkg hooks.

Needrestart config and interpreter scanner hardening:

```text
/etc/needrestart/needrestart.conf:57-67 binary blacklist
/etc/needrestart/needrestart.conf:155-162 blacklist_interp ignores ^/tmp/, ^/var/, ^/run/
/etc/needrestart/needrestart.conf:164-187 blacklist_mappings ignores device/memfd/tmp/run mappings
/etc/needrestart/needrestart.conf:228-234 loads /etc/needrestart/conf.d/*.conf
/etc/needrestart/conf.d drwxr-xr-x root:root, attacker not writable
/usr/share/perl5/NeedRestart/Interp/Python.pm:47 only matches ^/usr/(local/)?bin/python...
/usr/share/perl5/NeedRestart/Interp/Python.pm:84-90 chdir_empty() uses a private empty tempdir
/usr/share/perl5/NeedRestart/Interp/Python.pm:203-216 local %ENV, parse target PYTHONPATH as data, then exec python '-' to print sys.path
/usr/share/perl5/NeedRestart/Utils.pm:187-204 nr_fork_pipe2 execs with STDERR closed unless debug and LANG undefined
```

I tested the historical Python `PYTHONPATH`/`sitecustomize.py` style primitive with an attacker-owned Python process:

```sh
runuser -u attacker -- sh -lc '
  PYTHONPATH=/home/attacker/nrtest /usr/bin/python3 /home/attacker/nrtest/victim.py &
'
needrestart -v -b -r l
ls -l /root/nr_sitecustomize_pwned
```

Result:

```text
attacker startup marker: euid=1001
[Core] #3493 is a NeedRestart::Interp::Python
[Python] #3493: source=/home/attacker/nrtest/victim.py
/root/nr_sitecustomize_pwned: No such file or directory
```

Needrestart detected the attacker Python process but did not import attacker `sitecustomize.py` as root.

## sysstat, dpkg backup, e2scrub

Sysstat timers are root, but source root-owned config and write root-owned logs:

```text
/usr/lib/systemd/system/sysstat-collect.service:8 User=root
/usr/lib/systemd/system/sysstat-collect.service:9 ExecStart=/usr/lib/sysstat/sa1 1 1
/usr/lib/systemd/system/sysstat-summary.service:8 User=root
/usr/lib/systemd/system/sysstat-summary.service:9 ExecStart=/usr/lib/sysstat/sa2 -A
/usr/lib/sysstat/sa1:19 sources /etc/sysstat/sysstat if readable
/usr/lib/sysstat/sa1:25-26 falls back to /var/log/sysstat
/usr/lib/sysstat/sa1:60-62 execs /usr/lib/sysstat/sadc
/usr/lib/sysstat/sa2:21-22 sources /etc/sysstat/sysstat
/usr/lib/sysstat/sa2:53-64 writes reports under SA_DIR and execs sar.sysstat
/etc/sysstat/sysstat:19 SA_DIR=/var/log/sysstat
/etc/sysstat/sysstat root:root 0644
/var/log/sysstat root:root 0755, attacker not writable
```

`dpkg-db-backup` is root timer, but uses fixed root-owned paths:

```text
/usr/lib/systemd/system/dpkg-db-backup.service:5 ExecStart=/usr/libexec/dpkg/dpkg-db-backup
/usr/libexec/dpkg/dpkg-db-backup:19 ADMINDIR='/var/lib/dpkg'
/usr/libexec/dpkg/dpkg-db-backup:20 BACKUPSDIR='/var/backups'
/usr/libexec/dpkg/dpkg-db-backup:51 cd $BACKUPSDIR
/usr/libexec/dpkg/dpkg-db-backup:68 cp -p "$dbdir/$db" "dpkg.$db"
/usr/libexec/dpkg/dpkg-db-backup:72 savelog -c "$ROTATE" "dpkg.$db"
/var/backups root:root 0755, attacker not writable
/var/lib/dpkg root:root 0755, attacker not writable
```

`e2scrub_all.timer` is enabled, but the service did not pass conditions in the container and periodic scrubbing is disabled by default config:

```text
/usr/lib/systemd/system/e2scrub_all.service:5 ConditionCapability=CAP_SYS_ADMIN
/usr/lib/systemd/system/e2scrub_all.service:6 ConditionCapability=CAP_SYS_RAWIO
/usr/lib/systemd/system/e2scrub_all.service:10 Environment=SERVICE_MODE=1
/usr/lib/systemd/system/e2scrub_all.service:11 ExecStart=/sbin/e2scrub_all
/etc/e2scrub.conf:3-5 periodic_e2scrub is commented out
/sbin/e2scrub_all:77-88 exits in SERVICE_MODE when periodic_e2scrub != 1 and no leftover snapshots
systemctl show e2scrub_all.service: ConditionResult=no
```

## Conclusion

No uid 1001 to root LPE was validated in default root timers/tmpfiles/cron/logrotate/man-db/landscape/update-notifier/needrestart paths.

Promising but non-counting edge: `landscape` service account to root file write through `/var/lib/landscape/landscape-sysinfo.cache` symlink when root executes `/etc/update-motd.d/50-landscape-sysinfo`. This is blocked for the requested normal attacker because uid 1001 cannot write landscape-owned state or config, and the `landscape` account has `/usr/sbin/nologin`.
