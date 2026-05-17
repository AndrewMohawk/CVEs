# Negative: root script import/path/env trust boundaries

Date: 2026-05-16
Target: Docker container `ubuntu24-server-lpe-target`
Image: `ubuntu24-server-default-lpe:20260516-standard`
Result: no validated uid1001-to-root local privilege escalation.

## Scope

Lane covered default-installed/default-enabled Python, Perl, and shell helpers reached by root systemd timers/services, cron, logrotate, and apt hooks. The probe focused on import path, `PATH`/environment propagation, writable plugin directories, and symlink/cache-output trust boundaries.

## Default proof

Attacker:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
sudo: a password is required
sudo_rc=1
```

Target:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_ID="24.04"
VERSION_CODENAME=noble
systemd pid 1: /sbin/init
```

Package versions:

```text
apport 2.28.1-0ubuntu3.8
apt 2.8.3
command-not-found 23.04.0
cron 3.0pl1-184ubuntu2
debconf 1.5.86ubuntu1
e2fsprogs 1.47.0-2.4~exp1ubuntu4.1
logrotate 3.21.0-2build1
man-db 2.12.0-4build2
needrestart 3.6-7ubuntu4.5
networkd-dispatcher 2.2.4-1
perl-base 5.38.2-3.2ubuntu0.2
python3 3.12.3-0ubuntu2.1
systemd 255.4-1ubuntu8.15
ubuntu-pro-client 37.2ubuntu~24.04
ubuntu-release-upgrader-core 1:24.04.28
unattended-upgrades 2.9.1+nmu4ubuntu1
update-notifier-common 3.192.68.2
```

Default root/script consumers proven from the live target included `apt-daily`, `apt-daily-upgrade`, `apt-news`, `esm-cache`, `update-notifier-download`, `update-notifier-motd`, `motd-news`, `ua-timer`, `dpkg-db-backup`, `logrotate`, `e2scrub_all`, `sysstat-collect`, `sysstat-summary`, cron `run-parts`, and `/etc/cron.d/sysstat`. `apport-autoreport` is installed/enabled but condition-gated by missing `/var/lib/apport/autoreport`; `man-db`, `fwupd-refresh`, and `pollinate` run under non-root service users where applicable.

## Probe Results

Direct attacker env hijacks worked only as uid1001:

```text
PATH_PAYLOAD cmd=mktemp euid=1001 ruid=1001
PY_PAYLOAD .../py/uaclient/__init__.py euid=1001 uid=1001
PERL_PAYLOAD module=Debconf::Config euid=1001 ruid=1001
```

uid1001 could not write the trust roots: `/usr/local/{bin,sbin}`, `/etc/cron*`, `/etc/logrotate.d`, `/etc/apt/apt.conf.d`, `/etc/update-motd.d`, Python dist-packages, Perl include dirs, networkd-dispatcher hook dirs, `/var/cache/swcatalog`, `/var/lib/command-not-found`, `/var/lib/update-notifier`, `/var/lib/ubuntu-advantage`, `/var/backups`, and `/var/log/sysstat` all returned permission denied. `/var/crash` was writable, but the root cron/apport path did not follow the planted `.upload` symlink, and autoreport remained condition-gated.

uid1001 could not push env into systemd or start root units:

```text
systemctl set-environment PATH=...        -> Access denied
systemctl set-environment PYTHONPATH=...  -> Access denied
systemctl set-environment PERL5LIB=...    -> Access denied
systemctl start motd-news.service         -> Interactive authentication required
systemctl start update-notifier-download.service -> Interactive authentication required
systemctl start apt-news.service          -> Interactive authentication required
```

Root trigger commands exercised by the repeatable probe:

```sh
systemctl start apt-news.service esm-cache.service update-notifier-download.service update-notifier-motd.service motd-news.service ua-timer.service dpkg-db-backup.service logrotate.service e2scrub_all.service sysstat-collect.service sysstat-summary.service man-db.service apport-autoreport.service fwupd-refresh.service apt-daily.service apt-daily-upgrade.service
env -i SHELL=/bin/sh HOME=/root LOGNAME=root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --report /etc/cron.daily
env -i SHELL=/bin/sh HOME=/root LOGNAME=root PATH=/usr/lib/sysstat:/usr/sbin:/usr/bin:/sbin:/bin debian-sa1 1 1
```

Root proof absence:

```text
/tmp/root_script_import_path_probe_payload_hits: NO_HITS
/tmp/root_script_import_path_probe_python_hits: NO_HITS
/tmp/root_script_import_path_probe_perl_hits: NO_HITS
/var/crash/root_script_import_path_probe.upload -> /root/root_script_import_path_probe_symlink_target remained a symlink after root triggers
NO_ROOT_MARKER
cleanup_done
```

APT hook note: default apt hooks contain relative commands such as `touch`, `systemctl`, `appstreamcli`, `test`, and `rm`, but the Docker target has `APT::Periodic::Enable "0";`. Root `apt-daily`/`apt-daily-upgrade` starts succeeded and did not consume attacker `PATH`; uid1001 could not set the root systemd manager environment or trigger those units.

## Cleanup

`pocs/root_script_import_path_probe.sh` removes `/home/attacker/root_script_import_path_probe`, `/tmp/root_script_import_path_probe*`, `/var/crash/root_script_import_path_probe*`, and `/root/root_script_import_path_probe*` before and after the run. Final log showed `cleanup_done`.

## Why Scanners Miss

Static scanners will flag relative commands in root shell helpers and apt hooks, Python imports from root scripts, Perl module loads, and writable `/var/crash`. Those findings did not cross the uid1001-to-root boundary here because the root search/import directories are not writable, systemd units do not accept attacker `PATH`/`PYTHONPATH`/`PERL5LIB`, unprivileged systemd manager env changes are denied, apt periodic execution is disabled in the default Docker target, and the only writable crash directory is either handled by non-following cron cleanup or gated by missing autoreport state.
