# Negative: service-account-to-root bridge chains

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default image `ubuntu24-server-default-lpe:20260516-standard`.

Probe: `pocs/agent_service_account_bridges_probe.sh`

Log: `logs/agent_service_account_bridges.out`

Verdict: no uid1001-to-root LPE was found in this lane. uid1001 can reach several default service-account boundaries, but the writable state behind those boundaries is either not attacker-writable, not root-consumed, consumed only as data, or fixed-path/root-owned.

## Default proof

The probe re-proved the target and attacker:

```text
Ubuntu 24.04.4 LTS (noble)
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 1
```

Relevant default package versions:

```text
systemd 255.4-1ubuntu8.15
rsyslog 8.2312.0-3ubuntu9.2
logrotate 3.21.0-2build1
cron 3.0pl1-184ubuntu2
apport 2.28.1-0ubuntu3.8
uuid-runtime/util-linux/libuuid1 2.39.3-9ubuntu6.5
apt 2.8.3
packagekit 1.2.8-2ubuntu1.5
unattended-upgrades 2.9.1+nmu4ubuntu1
update-notifier-common 3.192.68.2
landscape-common 24.02-0ubuntu5.7
udisks2 2.10.1-6ubuntu1.3
fwupd 1.9.34-0ubuntu1~24.04.1
polkitd 124-2ubuntu1.24.04.3
libutempter0 1.2.1-3build1
```

Default-reachable units included `rsyslog.service`, `logrotate.timer`, `cron.service`, `uuidd.socket`, `apport-forward.socket`, `systemd-resolved.service`, `polkit.service`, `udisks2.service`, `apt-daily*.timer`, `unattended-upgrades.service`, and the MOTD/update-notifier timers. `systemd-networkd.service`, `systemd-timesyncd.service`, `packagekit.service`, and `fwupd.service` were installed but inactive until activated or condition-gated in this container.

uid1001 was not a member of `syslog`, `adm`, `uuidd`, `mail`, `landscape`, `crontab`, `utmp`, `systemd-journal`, or the systemd service-account groups.

## Code/config paths checked

The syslog/logrotate chain stayed fixed-path:

```text
/etc/rsyslog.conf:37-43          $FileOwner syslog; $FileGroup adm; drop to syslog:syslog
/etc/rsyslog.conf:48             $WorkDirectory /var/spool/rsyslog
/etc/rsyslog.d/50-default.conf:8 /var/log/auth.log
/etc/rsyslog.d/50-default.conf:9 /var/log/syslog
/etc/rsyslog.d/50-default.conf:14 /var/log/mail.log
/etc/logrotate.conf:10           su root adm
/etc/logrotate.conf:25           include /etc/logrotate.d
/etc/logrotate.d/rsyslog:1-6     fixed /var/log/{syslog,mail,kern,auth,user,cron}.log set
/etc/logrotate.d/rsyslog:15-16   fixed postrotate /usr/lib/rsyslog/rsyslog-rotate
```

Other bridge configs checked:

```text
/usr/lib/systemd/system/uuidd.socket:5              ListenStream=/run/uuidd/request
/usr/lib/systemd/system/uuidd.service:7-19          User=uuidd, Group=uuidd, ReadWritePaths=/var/lib/libuuid/
/etc/update-motd.d/50-landscape-sysinfo:5,27-29     root writes /var/lib/landscape/landscape-sysinfo.cache
/etc/cron.daily/apport:3-5                          fixed /var/crash cleanup only
/usr/lib/tmpfiles.d/00rsyslog.conf:6-11             fixed /var/log ownership/modes
/usr/lib/tmpfiles.d/systemd.conf:11                 fixed /run/utmp mode root:utmp
/usr/lib/tmpfiles.d/var.conf:15-17                  fixed wtmp/btmp/lastlog modes
/usr/lib/tmpfiles.d/cron-daemon-common.conf:1       fixed /var/spool/cron/crontabs mode root:crontab
/usr/lib/tmpfiles.d/systemd-network.conf:10-13      fixed /run/systemd/netif ownership
/usr/lib/tmpfiles.d/systemd-resolve.conf:10         fixed /etc/resolv.conf symlink
```

## Trigger attempts

Run command:

```sh
./pocs/agent_service_account_bridges_probe.sh ubuntu24-server-lpe-target | tee logs/agent_service_account_bridges.out
```

uid1001 direct-write checks all failed for the candidate service-account and root-consumed state:

```text
DIR_WRITE_DENY /var/log
DIR_WRITE_DENY /var/spool/rsyslog
DIR_WRITE_DENY /var/lib/libuuid
DIR_WRITE_DENY /var/cache/apt/archives/partial
DIR_WRITE_DENY /var/lib/apt/lists/partial
DIR_WRITE_DENY /var/lib/update-notifier/package-data-downloads/partial
DIR_WRITE_DENY /etc/landscape
DIR_WRITE_DENY /var/lib/landscape
DIR_WRITE_DENY /run/systemd/resolve
DIR_WRITE_DENY /run/systemd/netif
DIR_WRITE_DENY /var/mail
DIR_WRITE_DENY /var/spool/cron/crontabs
FILE_APPEND_DENY /var/log/syslog
FILE_APPEND_DENY /var/log/auth.log
FILE_APPEND_DENY /var/log/wtmp
FILE_APPEND_DENY /var/log/btmp
FILE_APPEND_DENY /var/log/lastlog
FILE_APPEND_DENY /run/utmp
FILE_APPEND_DENY /var/lib/libuuid/clock.txt
FILE_APPEND_DENY /run/systemd/resolve/resolv.conf
```

Reachable data-ingress triggers were exercised:

```text
logger to authpriv/user.emerg with root-command strings
raw AF_UNIX datagrams to /dev/log and /run/systemd/journal/syslog
logger --journald with attempted _UID=0 and _SYSTEMD_UNIT=logrotate.service fields
uuidd --time/--random plus malformed socket frames against /run/uuidd/request
pkcon get-updates
attacker ~/.landscape config before root MOTD run-parts
resolvectl query/status and resolve1 tree introspection
polkit property read, udisksctl status, fwupdmgr get-devices
direct crontab/mail spool planting attempts
libutempter add/remove record against a pty
```

## Results

Syslog/journald accepted attacker text, including fake `postrotate`/root-command strings, but treated it as log data. Rsyslog wrote to fixed files under `/var/log`; root `logrotate -d /etc/logrotate.conf` read only root-owned config and fixed package log paths and did not consume message content as config.

`uuidd` was reachable through the default world socket, and malformed frames produced resets or bounded replies. The daemon stayed `uid=101(uuidd) gid=102(uuidd)`, with no capabilities, and only maintained `/var/lib/libuuid/clock.txt` under `uuidd:uuidd`.

Package/cache checks showed `_apt` partial directories as `0700 _apt:root`; uid1001 could not write them. The bounded `pkcon get-updates` trigger activated PackageKit but did not reach an install, maintainer-script, or root cache-control bridge; the final run timed out with no root marker and the probe restored PackageKit to its initial inactive state.

Landscape/MOTD root execution refreshed `/var/lib/landscape/landscape-sysinfo.cache` as `root:root 0644`. The attacker-owned `~/.landscape` config remained user-owned data and did not affect the root MOTD run.

`systemd-resolved` allowed normal query/status calls and owned `/run/systemd/resolve`, but uid1001 could not write resolver state. `systemd-networkd` and `systemd-timesyncd` were installed but inactive in this default container state; their writable runtime/state paths were not attacker-writable.

Polkit/PackageKit/UDisks/fwupd checks did not expose a service-account state handoff: PackageKit and UDisks were root processes, polkit ran as `polkitd` but only answered policy data, and fwupd produced no usable state in this container.

Mail/crontab/utmp helpers stayed bounded. uid1001 could not plant files or symlinks in `/var/mail` or `/var/spool/cron/crontabs`. `libutempter` could create and remove a structured pty record, but no arbitrary wtmp/utmp write or root parser path was reached.

Final proof:

```text
ROOT_PROOF=NO
root_decoy_sha256=457d2768b0164b5cf1fcb95ff2f9b6b7163ae8f79a0f1fc27a3a8ff64dc2dbba
systemctl is-system-running: running
failed units: 0
```

## Cleanup

The probe removed only its own prefixed files:

```text
/tmp/agent_service_account_bridges*
/var/tmp/agent_service_account_bridges*
/var/crash/agent_service_account_bridges*
/home/attacker/.landscape/agent_service_account_bridges*
/root/agent_service_account_bridges_root_proof
/root/agent_service_account_bridges_root_decoy
```

If `packagekit.service` or `fwupd.service` were inactive at probe start, cleanup stops them again after activation tests. Post-cleanup proof in the log shows the prefixed paths absent, the system still `running`, and `0` failed units; a follow-up health check showed `packagekit.service` and `fwupd.service` inactive.

## Why scanners may over-rank this

This lane has several misleading signals: world-writable `/dev/log` and journald sockets, world-reachable `/run/uuidd/request`, group-writable service-account directories such as `/var/log`, `/var/lib/libuuid`, `/etc/landscape`, and `/var/mail`, setgid `crontab`/`utempter`, and root timers consuming nearby state. The missing exploit bridge is the important part: uid1001 can reach data APIs, but cannot become the service account, cannot write the service account's persistent state directly, and the root consumers use root-owned config plus fixed paths rather than attacker-controlled filenames, commands, or environment.
