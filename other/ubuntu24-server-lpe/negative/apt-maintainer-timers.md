# apt/dpkg/man-db/sysstat/unattended-upgrades/update-manager-core timer audit

Target: `ubuntu24-server-lpe-target`, Ubuntu `24.04.4 LTS (noble)`.
Attacker model: uid 1001 `attacker`, groups only `attacker`; no sudo/adm/lxd.

## Live default proof

Package versions from the live target:

```text
apt                         2.8.3
dpkg                        1.22.6ubuntu6.6
man-db                      2.12.0-4build2
sysstat                     12.6.1-2
unattended-upgrades         2.9.1+nmu4ubuntu1
update-manager-core         1:24.04.12
update-notifier-common      3.192.68.2
ubuntu-release-upgrader-core 1:24.04.28
```

Active/enabled root timers observed with `systemctl list-timers` and
`systemctl is-enabled/is-active`:

```text
apt-daily.timer                  enabled active
apt-daily-upgrade.timer          enabled active
dpkg-db-backup.timer             enabled active
man-db.timer                     enabled active
sysstat-collect.timer            enabled active
sysstat-summary.timer            enabled active
update-notifier-download.timer   enabled active
update-notifier-motd.timer       enabled active
```

Relevant unit entry points:

```text
apt-daily.service                /usr/lib/apt/apt.systemd.daily update
apt-daily-upgrade.service        /usr/lib/apt/apt.systemd.daily install
dpkg-db-backup.service           /usr/libexec/dpkg/dpkg-db-backup
man-db.service                   +/usr/bin/install -d -o man -g man -m 0755 /var/cache/man; then User=man /usr/bin/mandb --quiet
sysstat-collect.service          User=root /usr/lib/sysstat/sa1 1 1
sysstat-summary.service          User=root /usr/lib/sysstat/sa2 -A
update-notifier-download.service /usr/lib/update-notifier/package-data-downloader
update-notifier-motd.service     /usr/lib/ubuntu-release-upgrader/release-upgrade-motd
```

## Global attacker write check

As `attacker`, no writable files/directories existed under:

```text
/var/lib/apt /var/cache/apt /var/log/apt /var/lib/dpkg /var/backups
/var/cache/man /var/log/sysstat /var/lib/update-notifier
/var/lib/update-manager /var/lib/ubuntu-release-upgrader
/var/log/unattended-upgrades /etc/apt /etc/update-manager
/usr/share/package-data-downloads
```

Explicit symlink probes into `/var/backups`, apt list/cache/partial dirs,
`/var/cache/man`, `/var/log/sysstat`, update-notifier/update-manager state,
release-upgrader state, unattended-upgrades logs, and `/etc/apt/apt.conf.d`
all failed with `Permission denied`. Hardlink probes to `/etc/shadow` into
`/var/backups`, `/var/lib/dpkg`, `/var/cache/apt/archives`, and
`/var/log/sysstat` failed with `Operation not permitted` or directory
permission denial. No `apt-lpe-*`/`apt_lpe_*` probe artifacts remained.

As `attacker`, attempts to start each audited root service with `systemctl
start` failed with `Interactive authentication required`, so the attacker
cannot trigger these units directly.

## Dead ends

### apt daily and unattended-upgrades

`apt-config dump` shows `APT::Periodic::Update-Package-Lists "1"` and
`APT::Periodic::Unattended-Upgrade "1"`, but the live container also has
`APT::Periodic::Enable "0"` from `docker-disable-periodic-update`.
`/usr/lib/apt/apt.systemd.daily` takes a root-owned lock at lines 325-327,
backs up `/var/lib/apt/extended_states` to `/var/backups` at lines 338-345,
then exits at lines 355-360 when `APT::Periodic::Enable` is 0. A direct root
smoke of `/usr/lib/apt/apt.systemd.daily update` returned `rc=0` and did not
run update/upgrade paths.

The dangerous-looking apt cleanup/backup paths are not attacker-fed here:
`Dir::Cache`, `Dir::State`, apt hooks, and unattended-upgrades config all come
from root-owned `/etc/apt`. The live cache/list partial dirs are `_apt:root`
`0700`, and their parents are root-owned. Root apt hooks in
`99update-notifier`, `50command-not-found`, PackageKit, appstream, and docker
cleanup use fixed root-owned paths.

`/usr/bin/unattended-upgrade` logging opens dpkg logs with
`O_APPEND|O_CREAT` mode `0640` and `fchown(root, adm)` at lines 515-524.
Main logging derives `Unattended-Upgrade::LogDir` from apt config and creates
`/var/log/unattended-upgrades` at lines 1572-1603; the live directory is
`root:adm` `0750`. The periodic apt path that would invoke unattended-upgrade
is disabled before reaching lines 479-495.

### dpkg database backup

`/usr/libexec/dpkg/dpkg-db-backup` fixes `ADMINDIR=/var/lib/dpkg` and
`BACKUPSDIR=/var/backups` at lines 19-20, `cd`s to `/var/backups` at line 51,
copies root dpkg databases at lines 65-72, and rotates the alternatives tar at
lines 81-85. `/var/backups` is `root:root` `0755`; attacker cannot create
preexisting symlinks/hardlinks there. A root service smoke completed
successfully and left only root-owned backup files.

### man-db

`man-db.service` has one root-prefixed `ExecStart=+` to recreate
`/var/cache/man` as `man:man` `0755`, then runs `mandb --quiet` as `User=man`
with `ProtectSystem=full`. The live `/var/cache/man` tree is `man:man` `0755`,
not writable by uid1001. `/usr/bin/man` and `/usr/bin/mandb` are root-owned
`0755`, not setuid/setgid in this install.

The maintainer script mirrors this boundary: `man-db.postinst` creates the
cache dir with `install -d -o man -g man -m 0755` at lines 6-10, runs mandb
via `setpriv --reuid man --regid man --init-groups` or `runuser -u man` at
lines 23-29, and only changes `/usr/bin/man`/`/usr/bin/mandb` ownership based
on debconf at lines 48-65. No attacker-writable manpath or cache path is
trusted by root.

### sysstat

`sysstat-collect.service` and `sysstat-summary.service` run as root, but their
only mutable inputs are root-owned config and log paths. `sa1` sources
`/etc/sysstat/sysstat` at line 19, defaults `SA_DIR=/var/log/sysstat` at line
13, falls back to that root-owned directory at lines 23-27, and execs `sadc`
with the fixed directory at lines 54-62. `sa2` sources the same root-owned
config at line 22, writes reports under `SA_DIR` at lines 53-65, then removes
or compresses files matching `sar?[0-9]{2,8}` under that directory at lines
67-77. `/var/log/sysstat` is `root:root` `0755`; attacker cannot create race
or symlink candidates there.

### update-notifier package data

`package-data-downloader` treats `/usr/share/package-data-downloads` as the
hook source and `/var/lib/update-notifier/package-data-downloads` as the stamp
dir at lines 36-40. It enumerates hook filenames from the root-owned data dir
at lines 161-169, builds `stampfile` and hook paths at lines 229-232, downloads
to `STAMPDIR/partial/basename(uri)` at lines 174-195, checks SHA256 before use,
and executes only the hook-provided `Script` at lines 247-292. The live
`/usr/share/package-data-downloads` directory is empty and root-owned; the
stamp dir is root-owned `0755`; `partial` is `_apt:root` `0700`. Attacker
cannot add a hook, preseed a stamp, replace partial downloads, or choose a
script path.

`update-notifier-common.postinst` also repairs `partial` to `_apt:root` `0700`
at lines 23-25 and invokes the downloader at line 29; those maintainer-script
paths are only reached by root package operations, not by uid1001.

### update-manager-core / release checks

`update-notifier-motd.service` runs
`/usr/lib/ubuntu-release-upgrader/release-upgrade-motd` as root. That script
uses fixed stamp `/var/lib/ubuntu-release-upgrader/release-upgrade-available`
at line 23 and writes it via `check-new-release -q > "$stamp"` at lines 31 and
39. `/var/lib/ubuntu-release-upgrader` is `root:root` `0755`.

`MetaRelease.py` reads root-owned `/etc/update-manager/meta-release` and
`/etc/update-manager/release-upgrades` at lines 77-150. It first writes the
meta-release cache in `/var/lib/update-manager/basename(uri)` at lines
195-203; only if that is not writable does it fall back to `$XDG_CACHE_HOME`
or `~/.cache/update-manager-core` at lines 205-233. Under the root timer the
global directory is writable by root, so attacker-controlled cache env is not
used. The `do-release-upgrade --env` option exists at lines 113-116 and
223-230, but the timer invokes only `check-new-release -q` and attacker cannot
start the unit.

## Maintainer-script review

Reviewed targeted maintainer scripts in `/var/lib/dpkg/info` for `apt`,
`dpkg`, `man-db`, `sysstat`, `unattended-upgrades`, `update-manager-core`,
`python3-update-manager`, `update-notifier-common`, and
`ubuntu-release-upgrader-core`. Root file operations were fixed-path
debhelper/systemd glue, fixed cache/log permission repair, or purge/remove
cleanup. Notable fixed operations:

- `apt.postinst` enables/starts apt timers; `apt.postrm purge` removes
  `/var/cache/apt` and `/var/lib/apt`.
- `dpkg.postinst` enables `dpkg-db-backup.timer`; backup logic is in the
  fixed-path timer script above.
- `man-db.postinst` creates `/var/cache/man`, optionally sets man/mandb mode
  from debconf, then runs mandb as `man`.
- `unattended-upgrades.preinst/postrm` copy/remove only root-owned apt config
  paths during package operations.
- `update-notifier-common.postinst` chowns/chmods only its fixed `_apt`
  partial dir and runs the root-owned package-data downloader.
- `ubuntu-release-upgrader-core.postinst` chmods fixed dist-upgrade tarballs
  and removes the fixed release-upgrade stamp.

None of these are triggerable by uid1001 without a root package operation, and
the default root timer surfaces do not consume attacker-writable state.

## Conclusion

No uid1001-to-root LPE validated in the audited default apt/dpkg/man-db/sysstat
/unattended-upgrades/update-manager-core timer or maintainer-script surfaces.
The scanner-miss-relevant finding is negative: several scripts contain
unquoted shell variables, hardlink backups, root log creation, script hooks,
and env/cache fallbacks, but in the live default container every corresponding
input directory/config file is root-owned or `_apt`/`man`-owned and not
writable by the normal attacker, and the attacker cannot start the root units.
