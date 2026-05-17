# sysstat timer/service LPE audit

Target: `ubuntu24-server-lpe-target`, stock Ubuntu Server 24.04 default Docker/systemd install.
Attacker: uid 1001 `attacker`, group only `attacker`, no sudo or special groups.
Scope: sysstat default systemd timer/service path only. DoS and attacker-only execution are not counted.

Result: no real uid1001-to-root LPE was found in the default sysstat timer/service path. No PoC was created.

## Default package and unit state

Commands:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'cat /etc/os-release; dpkg-query -W -f="\${Package} \${Version} \${db:Status-Abbrev}\n" sysstat systemd; id attacker; systemctl list-timers --all "*sysstat*" --no-pager'
docker exec ubuntu24-server-lpe-target bash -lc 'systemctl cat sysstat.service sysstat-collect.timer sysstat-collect.service sysstat-summary.timer sysstat-summary.service --no-pager'
docker exec ubuntu24-server-lpe-target bash -lc 'systemctl is-enabled sysstat.service sysstat-collect.timer sysstat-summary.timer; systemctl is-active sysstat.service sysstat-collect.timer sysstat-summary.timer'
```

Evidence:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_CODENAME=noble

sysstat 12.6.1-2 ii
systemd 255.4-1ubuntu8.15 ii

uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)

NEXT                            LEFT LAST                          PASSED UNIT                  ACTIVATES
Sat 2026-05-16 11:40:00 UTC 2min Sat 2026-05-16 11:30:01 UTC 7min ago sysstat-collect.timer sysstat-collect.service
Sun 2026-05-17 00:07:00 UTC 12h  -                             -      sysstat-summary.timer sysstat-summary.service

sysstat.service:          User=root ExecStart=/usr/lib/sysstat/sa1 --boot
sysstat-collect.service:  User=root ExecStart=/usr/lib/sysstat/sa1 1 1
sysstat-summary.service:  User=root ExecStart=/usr/lib/sysstat/sa2 -A

sysstat.service enabled active
sysstat-collect.timer enabled active
sysstat-summary.timer enabled active
```

The collect timer is enabled and runs every 10 minutes. The summary timer is enabled and runs daily at `00:07:00`.

## Files, configs, and state permissions

Commands:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'stat -c "%A %U:%G %n" /usr/lib/systemd/system/sysstat-* /etc/default/sysstat /etc/sysstat /etc/sysstat/* /usr/lib/sysstat /usr/lib/sysstat/* /usr/bin/sar /usr/bin/sadf /usr/bin/pidstat /usr/bin/iostat /var/log/sysstat 2>&1'
docker exec ubuntu24-server-lpe-target bash -lc 'runuser -u attacker -- sh -c '"'"'for p in /etc/default/sysstat /etc/sysstat /etc/sysstat/sysstat /etc/sysstat/sysstat.ioconf /usr/lib/systemd/system/sysstat-collect.service /usr/lib/systemd/system/sysstat-summary.service /usr/lib/sysstat /usr/lib/sysstat/sa1 /usr/lib/sysstat/sa2 /usr/lib/sysstat/sadc /var/log/sysstat /tmp /var/tmp; do [ -e "$p" ] || continue; if [ -w "$p" ]; then echo writable:$p; else echo not-writable:$p; fi; done'"'"''
```

Evidence:

```text
-rw-r--r-- root:root /usr/lib/systemd/system/sysstat-collect.service
-rw-r--r-- root:root /usr/lib/systemd/system/sysstat-collect.timer
-rw-r--r-- root:root /usr/lib/systemd/system/sysstat-summary.service
-rw-r--r-- root:root /usr/lib/systemd/system/sysstat-summary.timer
-rw-r--r-- root:root /etc/default/sysstat
drwxr-xr-x root:root /etc/sysstat
-rw-r--r-- root:root /etc/sysstat/sysstat
-rw-r--r-- root:root /etc/sysstat/sysstat.ioconf
drwxr-xr-x root:root /usr/lib/sysstat
-rwxr-xr-x root:root /usr/lib/sysstat/debian-sa1
-rwxr-xr-x root:root /usr/lib/sysstat/sa1
-rwxr-xr-x root:root /usr/lib/sysstat/sa2
-rwxr-xr-x root:root /usr/lib/sysstat/sadc
lrwxrwxrwx root:root /usr/bin/sar -> /usr/bin/sar.sysstat
-rwxr-xr-x root:root /usr/bin/sadf
-rwxr-xr-x root:root /usr/bin/pidstat
-rwxr-xr-x root:root /usr/bin/iostat
drwxr-xr-x root:root /var/log/sysstat

not-writable:/etc/default/sysstat
not-writable:/etc/sysstat
not-writable:/etc/sysstat/sysstat
not-writable:/etc/sysstat/sysstat.ioconf
not-writable:/usr/lib/systemd/system/sysstat-collect.service
not-writable:/usr/lib/systemd/system/sysstat-summary.service
not-writable:/usr/lib/sysstat
not-writable:/usr/lib/sysstat/sa1
not-writable:/usr/lib/sysstat/sa2
not-writable:/usr/lib/sysstat/sadc
not-writable:/var/log/sysstat
writable:/tmp
writable:/var/tmp
```

`/var/log/sysstat` contained only root-owned state:

```text
drwxr-xr-x root:root /var/log/sysstat
-rw-r--r-- root:root /var/log/sysstat/sa16
```

## Script review

`/usr/lib/sysstat/sa1`:

```sh
HISTORY=0
SADC_OPTIONS=""
SA_DIR=/var/log/sysstat
SYSCONFIG_DIR=/etc/sysstat
SYSCONFIG_FILE=sysstat
UMASK=0022
LONG_NAME=n

[ -r ${SYSCONFIG_DIR}/${SYSCONFIG_FILE} ] && . ${SYSCONFIG_DIR}/${SYSCONFIG_FILE}
umask ${UMASK}
[ -d ${SA_DIR} ] || SA_DIR=/var/log/sysstat
[ -d /var/log/sysstat ] || mkdir /var/log/sysstat
ENDIR=/usr/lib/sysstat
cd ${ENDIR}
exec ${ENDIR}/sadc -F -L ${SADC_OPTIONS} $* ${SA_DIR}
```

The root-executed inputs are the fixed service arguments `1 1`, root-owned `/etc/sysstat/sysstat`, and root-owned `/var/log/sysstat`.

`/usr/lib/sysstat/sa2`:

```sh
S_TIME_FORMAT=ISO ; export S_TIME_FORMAT
SA_DIR=/var/log/sysstat
SYSCONFIG_DIR=/etc/sysstat
SYSCONFIG_FILE=sysstat
HISTORY=7
COMPRESSAFTER=10
ZIP="xz"
UMASK=0022
DELAY_RANGE=0

[ -r ${SYSCONFIG_DIR}/${SYSCONFIG_FILE} ] && . ${SYSCONFIG_DIR}/${SYSCONFIG_FILE}
umask ${UMASK}
[ -d ${SA_DIR} ] || SA_DIR=/var/log/sysstat
RPT=${SA_DIR}/${CURRENTRPT}
DFILE=${SA_DIR}/${CURRENTFILE}
cd ${ENDIR}
${ENDIR}/sar.sysstat "$@" -f ${DFILE} > ${RPT}
find "${SA_DIR}" -type f -mtime +${HISTORY} | grep -E "${SAFILES_REGEX}" | xargs rm -f
find "${SA_DIR}" -type f -mtime +${COMPRESSAFTER} | grep -E "${UNCOMPRESSED_SAFILES_REGEX}" | xargs -r "${ZIP}" > /dev/null
```

The dangerous-looking shell controls (`SA_DIR`, `ZIP`, `ENDIR`, `HISTORY`, `COMPRESSAFTER`, `REPORTS`, `DELAY_RANGE`) all come from root-owned config. uid1001 cannot write the config or the directory where `find`, `rm`, compression, report redirection, and data-file names operate.

## PATH, environment, locale, and `/tmp`

The scripts call helpers such as `date`, `find`, `grep`, `xargs`, `rm`, and `sleep` without absolute paths. The live system manager PATH is not attacker-controlled and contains only root-owned directories.

Commands:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'runuser -u attacker -- sh -c "systemctl show-environment | sed -n 1,20p; systemctl set-environment PATH=/tmp/sysstat-pwn:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin 2>&1; systemctl show-environment | grep ^PATH="; systemctl show-environment | grep ^PATH='
docker exec ubuntu24-server-lpe-target bash -lc 'IFS=:; for d in $(systemctl show-environment | sed -n "s/^PATH=//p"); do stat -c "%A %U:%G %n" "$d" 2>&1; runuser -u attacker -- test -w "$d" && echo attacker-writable:$d || echo attacker-not-writable:$d; done'
```

Evidence:

```text
LANG=C.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
Failed to set environment: Access denied
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin

drwxr-xr-x root:root /usr/local/sbin
attacker-not-writable:/usr/local/sbin
drwxr-xr-x root:root /usr/local/bin
attacker-not-writable:/usr/local/bin
drwxr-xr-x root:root /usr/sbin
attacker-not-writable:/usr/sbin
drwxr-xr-x root:root /usr/bin
attacker-not-writable:/usr/bin
stat: cannot statx '/snap/bin': No such file or directory
attacker-not-writable:/snap/bin
```

Live `/tmp` helper probe:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'rm -f /root/sysstat_lpe_path /root/sysstat_lpe_proc; rm -rf /tmp/sysstat-pwn; mkdir -m 0777 /tmp/sysstat-pwn; cat >/tmp/sysstat-pwn/date <<EOF
#!/bin/sh
echo path-pwn > /root/sysstat_lpe_path
exec /usr/bin/date "$@"
EOF
chmod 755 /tmp/sysstat-pwn/date; chown -R attacker:attacker /tmp/sysstat-pwn; systemctl start sysstat-collect.service; rc=$?; echo collect_rc:$rc; test -e /root/sysstat_lpe_path && echo PATH_PWN_CREATED || echo no_path_pwn'
```

Evidence:

```text
collect_rc:0
no_path_pwn
```

Conclusion: `/tmp`, attacker locale, and attacker PATH do not influence the root timer/services by default.

## Process-name and summary-output influence

The default config uses `SADC_OPTIONS="-S DISK"`, not per-process collection. A live probe with an attacker-controlled argv string did not appear in `sar -A` output and did not execute as root.

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'rm -f /root/sysstat_lpe_proc; runuser -u attacker -- bash -lc '"'"'(exec -a "SYSSTAT_PWN_;touch_/root/sysstat_lpe_proc" sleep 90) >/tmp/sysstat-proc-hit 2>&1 & echo $! >/tmp/sysstat-proc-pid'"'"'; sleep 1; ps -eo uid,pid,comm,args | grep -F "SYSSTAT_PWN" | grep -v grep || true; systemctl start sysstat-collect.service; rc=$?; echo collect_rc:$rc; today=$(date +%d); /usr/bin/sar.sysstat -A -f /var/log/sysstat/sa${today} 2>&1 | grep -aF "SYSSTAT_PWN" || echo no_proc_name_in_sar_A; test -e /root/sysstat_lpe_proc && echo PROC_PWN_CREATED || echo no_proc_pwn; kill $(cat /tmp/sysstat-proc-pid) 2>/dev/null || true'
```

Evidence:

```text
1001 19517 sleep SYSSTAT_PWN_;touch_/root/sysstat_lpe_proc 90
collect_rc:0
no_proc_name_in_sar_A
no_proc_pwn
```

This rejects both shell-injection-through-report and root-file-write-through-process-name for the default timer path.

## File overwrite and symlink probes

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'runuser -u attacker -- sh -c "touch /var/log/sysstat/attacker-create 2>&1; echo varlog_create_rc:\$?; ln -s /root/sysstat_lpe /var/log/sysstat/sar99 2>&1; echo varlog_symlink_rc:\$?; echo X >> /var/log/sysstat/sa16 2>&1; echo sa_append_rc:\$?; touch /etc/sysstat/sysstat 2>&1; echo config_touch_rc:\$?"'
```

Evidence:

```text
touch: cannot touch '/var/log/sysstat/attacker-create': Permission denied
varlog_create_rc:1
ln: failed to create symbolic link '/var/log/sysstat/sar99': Permission denied
varlog_symlink_rc:1
sh: 1: cannot create /var/log/sysstat/sa16: Permission denied
sa_append_rc:2
touch: cannot touch '/etc/sysstat/sysstat': Permission denied
config_touch_rc:1
```

`sa2` overwrites `sarDD`, removes old `saDD`/`sarDD`, and compresses old files only inside `SA_DIR`. Because `SA_DIR` and the existing directory are root-controlled, uid1001 cannot pre-place symlinks, choose report paths, feed filenames to `xargs rm`, or choose the compression binary.

## Adjacent package paths

`/etc/cron.d/sysstat`, `/etc/cron.daily/sysstat`, and `/usr/lib/systemd/system-sleep/sysstat.sleep` are root-owned. The cron scripts explicitly skip when systemd is present. The sleep hook is outside the requested timer/service path and receives fixed systemd sleep arguments, not uid1001 input.

Evidence:

```text
-rw-r--r-- root:root /etc/cron.d/sysstat
-rwxr-xr-x root:root /etc/cron.daily/sysstat
-rwxr-xr-x root:root /usr/lib/systemd/system-sleep/sysstat.sleep

/usr/lib/sysstat/debian-sa1: [ ! -d /run/systemd/system ] || exit 0
/etc/cron.daily/sysstat:     [ ! -d /run/systemd/system ] || exit 0
```

## Cleanup

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'rm -f /root/sysstat_lpe_path /root/sysstat_lpe_proc; rm -rf /tmp/sysstat-pwn /tmp/sysstat-proc-hit /tmp/sysstat-proc-pid; ls -ld /tmp/sysstat-pwn /tmp/sysstat-proc-hit /tmp/sysstat-proc-pid 2>&1 || true; ls -l /root/sysstat_lpe_path /root/sysstat_lpe_proc 2>&1 || true; find /var/log/sysstat -maxdepth 1 -printf "%M %u:%g %s %p -> %l\n" | sort'
```

Evidence:

```text
ls: cannot access '/tmp/sysstat-pwn': No such file or directory
ls: cannot access '/tmp/sysstat-proc-hit': No such file or directory
ls: cannot access '/tmp/sysstat-proc-pid': No such file or directory
ls: cannot access '/root/sysstat_lpe_path': No such file or directory
ls: cannot access '/root/sysstat_lpe_proc': No such file or directory

-rw-r--r-- root:root 36404 /var/log/sysstat/sa16 ->
drwxr-xr-x root:root 4096 /var/log/sysstat ->
```

## Conclusion

No exploitable default sysstat timer/service path was identified for uid1001-to-root LPE:

- root services are enabled and reachable by timers, but execute fixed root-owned scripts;
- sourced config files and unit files are root-owned and not attacker-writable;
- `/var/log/sysstat` is root-owned `0755`, preventing attacker symlink, race, file-name, and report-path control;
- uid1001 cannot change the system manager environment/PATH for future sysstat services;
- `/tmp` helper binaries are not reached;
- default collection does not expose attacker process names to shell evaluation or root-controlled file paths;
- summary cleanup/compression operates only on root-controlled files under root-controlled `SA_DIR`.

The finding is negative: sysstat’s default Ubuntu 24.04 Server timer/service path did not yield root code execution or root file overwrite from the specified attacker.
