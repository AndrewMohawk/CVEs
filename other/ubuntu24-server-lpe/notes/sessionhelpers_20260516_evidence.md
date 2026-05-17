# sessionhelpers 2026-05-16 evidence

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS, `attacker` is `uid=1001 gid=1001 groups=1001`.

## Default package proof

Relevant default-installed versions on the target:

```text
landscape-common                         24.02-0ubuntu5.7
libpam-modules:arm64                     1.5.3-5ubuntu5.5
libpam-runtime                           1.5.3-5ubuntu5.5
libpam0g:arm64                           1.5.3-5ubuntu5.5
login                                    1:4.13+dfsg1-4ubuntu3.2
passwd                                   1:4.13+dfsg1-4ubuntu3.2
pollinate                                4.33-3.1ubuntu1.3
ubuntu-pro-client                        37.2ubuntu~24.04
ubuntu-release-upgrader-core             1:24.04.28
update-notifier-common                   3.192.68.2
util-linux                               2.39.3-9ubuntu6.5
```

Default units/timers:

```text
motd-news.timer                          enabled, active waiting
update-notifier-download.timer           enabled, active waiting
update-notifier-motd.timer               enabled, active waiting
pollinate.service                        enabled, skipped in Docker by ConditionVirtualization=!container
ua-timer.timer                           enabled, inactive because /var/lib/ubuntu-advantage/private/machine-token.json is absent
ubuntu-advantage.service                 enabled, inactive because cloud/auto-attach trigger paths are absent
```

## Code/config boundaries

`/etc/pam.d/login:33-34` is the only default PAM file in this target that invokes `pam_motd.so`. `/etc/pam.d/su` and `runuser` do not include `pam_motd`, so a normal already-local shell cannot trigger MOTD through `su`.

`/usr/bin/login` is not setuid:

```text
-rwxr-xr-x 1 root root 69200 May 30  2024 /usr/bin/login
```

An attacker shell cannot launch the `login` PAM stack with effective root:

```text
$ runuser -u attacker -- /usr/bin/login -f attacker
login: Cannot possibly work without effective root
```

The root-side PAM/getty path does execute update-motd scripts. It produced root-owned cache files:

```text
/var/lib/landscape/landscape-sysinfo.cache uid=0 gid=0 mode=644
/var/lib/update-notifier/fsck-at-reboot uid=0 gid=0 mode=644
/var/lib/ubuntu-release-upgrader/release-upgrade-available uid=0 gid=0 mode=644
```

Interesting root helper lines:

```text
/usr/share/landscape/landscape-sysinfo.wrapper:5-29
  CACHE=/var/lib/landscape/landscape-sysinfo.cache
  runs /usr/bin/landscape-sysinfo and writes/chmods the cache

/etc/update-motd.d/91-release-upgrade:13-20
  skips unless id -u is 0, then execs /usr/lib/ubuntu-release-upgrader/release-upgrade-motd

/usr/lib/ubuntu-release-upgrader/release-upgrade-motd:23-39
  root-owned stamp /var/lib/ubuntu-release-upgrader/release-upgrade-available

/usr/lib/update-notifier/update-motd-updates-available:15-66
  root-owned stamp /var/lib/update-notifier/updates-available and absolute /usr/lib/update-notifier/apt-check

/usr/lib/update-notifier/package-data-downloader:36-40,161-169,247-287
  root timer reads /usr/share/package-data-downloads and runs listed Script entries, but the directory is root-owned and empty on this default target
```

## Hostile environment tests

I installed attacker-controlled fake `find`, `bc`, `cut`, `id`, and a Python `sitecustomize.py` under `/home/attacker/sessionhelpers`.

Direct attacker execution of the MOTD scripts hit the fake hooks, but only as uid1001:

```text
FAKEFIND uid=1001 args=/var/lib/landscape/landscape-sysinfo.cache -newermt now-1 minutes
FAKEBC uid=1001 args=
FAKECUT uid=1001 euid=1001 args=-f1 -d   /proc/loadavg
FAKEID uid=1001 args=-u
sitecustomize uid=1001 euid=1001 argv=['/usr/bin/landscape-sysinfo']
```

Root-side PAM login was triggered with `login -p -f attacker` under hostile `PATH` and `PYTHONPATH`. The MOTD printed, but no hostile markers were created:

```text
Welcome to Ubuntu 24.04.4 LTS ...
System information as of Sat May 16 12:04:55 UTC 2026
...
/tmp/sessionhelpers_path_marker NONE
/tmp/sessionhelpers_py_marker NONE
```

Direct Python helpers are hookable by the attacker only in the attacker's own process:

```text
sitecustomize uid=1001 euid=1001 argv=['/usr/bin/pro', 'status', '--format', 'json']
sitecustomize uid=1001 euid=1001 argv=['/usr/bin/pro', 'refresh']
sitecustomize uid=1001 euid=1001 argv=['/usr/bin/do-release-upgrade', '-c']
sitecustomize uid=1001 euid=1001 argv=['/usr/lib/update-notifier/apt_check.py', '--human-readable']
sitecustomize uid=1001 euid=1001 argv=['/usr/lib/ubuntu-release-upgrader/check-new-release', '-q']
```

`pro refresh` as attacker returned:

```text
This command must be run as root (try using sudo).
```

## Writable state tests

Attacker writes failed with `Permission denied` for the relevant root/service-owned state:

```text
/etc/default/motd-news
/etc/default/pollinate
/etc/update-manager/release-upgrades
/etc/ubuntu-advantage/uaclient.conf
/var/cache/motd-news
/var/cache/pollinate
/var/lib/landscape
/var/lib/landscape/landscape-sysinfo.cache
/var/lib/update-notifier
/var/lib/update-notifier/updates-available
/var/lib/update-notifier/fsck-at-reboot
/var/lib/ubuntu-release-upgrader
/var/lib/ubuntu-release-upgrader/release-upgrade-available
/var/lib/ubuntu-advantage
/var/lib/ubuntu-advantage/status.json
```

Service-account boundary check:

```text
uid=106(landscape) gid=108(landscape) groups=108(landscape)
/var/lib/landscape is writable by landscape, not by attacker.

uid=105(pollinate) gid=1(daemon) groups=1(daemon)
/var/cache/pollinate is writable by pollinate, not by attacker.
```

No default-running path from `attacker` to either service account was found.

## Systemd control tests

Attacker cannot start the root helper services or poison the system manager environment:

```text
Failed to start motd-news.service: Interactive authentication required.
Failed to start update-notifier-motd.service: Interactive authentication required.
Failed to start update-notifier-download.service: Interactive authentication required.
Failed to start ua-timer.service: Interactive authentication required.
Failed to start ubuntu-advantage.service: Interactive authentication required.
Failed to start pollinate.service: Interactive authentication required.
Failed to set environment: Access denied
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
```

## Cleanup

Removed `/home/attacker/sessionhelpers*`, `/tmp/sessionhelpers_*`, and root-owned cache files created only by the PAM-login simulation when they were absent before the test.
