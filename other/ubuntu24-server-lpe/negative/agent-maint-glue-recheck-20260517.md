# Agent maintenance glue recheck: no uid1001-to-root LPE

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS, aarch64, systemd running.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no valid local privilege escalation was found in this maintenance-glue recheck. No root proof marker was created, and the probe cleaned its target artifacts.

Artifacts:

```sh
./pocs/agent_maint_glue_recheck.sh ubuntu24-server-lpe-target
logs/agent_maint_glue_recheck.out
```

This was a freshness and gap recheck, not a replacement for the broader existing notes such as `apt-needrestart-deep`, `apt-maintainer-timers`, `root-timers-tmpfiles-logrotate`, `ubuntu-pro-client-default-timers`, `update-notifier-package-data-downloader`, `cron-*`, and `tmpfiles-public-dirs`.

## Default state

The live target had the expected attacker model and relevant package versions:

```text
apt                         2.8.3
cron                        3.0pl1-184ubuntu2
dpkg                        1.22.6ubuntu6.6
logrotate                   3.21.0-2build1
needrestart                 3.6-7ubuntu4.5
systemd                     255.4-1ubuntu8.15
ubuntu-pro-client           37.2ubuntu~24.04
unattended-upgrades         2.9.1+nmu4ubuntu1
update-notifier-common      3.192.68.2
ubuntu-release-upgrader-core 1:24.04.28
```

Default active or installed root maintenance entry points included `apt-daily`, `apt-daily-upgrade`, `dpkg-db-backup`, `logrotate`, `man-db`, `motd-news`, `sysstat-*`, `systemd-tmpfiles-clean`, `update-notifier-*`, `ua-timer`, `unattended-upgrades`, `apport-autoreport`, and `systemd-ask-password-wall`. Path units present were `apport-autoreport.path` and `systemd-ask-password-wall.path`; the latter watches `/run/systemd/ask-password`.

## Write gates

As `attacker`, write attempts failed against the root-controlled inputs for apt hooks, needrestart config, cron, logrotate, tmpfiles, update-notifier package-data, Ubuntu Pro state, release-upgrader/update-manager state, apt/dpkg/backups, unattended-upgrades logs, systemd ask-password, apport autoreport, crontabs, sysstat, man-db, `/run/needrestart`, and `/run`.

The only writable paths in the checked maintenance set were expected sticky/public locations: `/tmp`, `/var/tmp`, and `/run/screen`. This recheck did not find a default root consumer in this lane that treats those as executable config or follows them to a root write.

Explicit attacker planting attempts failed:

```text
/etc/apt/apt.conf.d/99agent-maint                         Permission denied
/usr/share/package-data-downloads/agent-maint             Permission denied
/var/lib/update-notifier/package-data-downloads/agent-maint Permission denied
/run/needrestart/unpacked                                  Permission denied
/run/systemd/ask-password/agent-maint                      Permission denied
/var/lib/apport/autoreport                                 Permission denied
```

## Dead ends

Needrestart: an attacker Python process with a module side effect wrote the marker as `uid=1001/euid=1001`. A root `needrestart -v -b -r l` run classified the attacker process as Python and saw the source path, but did not import the attacker module. The marker remained absent after the root needrestart run.

Apt, unattended-upgrades, update-notifier, Ubuntu Pro: `attacker` could not set or import the systemd manager environment, start the root timer services, create unattended-upgrades pid/progress files, signal the root unattended-upgrade-shutdown process, write apt hooks, write package-data hooks, or write Ubuntu Pro state. Root smokes of `update-notifier-download`, `update-notifier-motd`, `ua-timer`, `apt-daily`, and `apt-daily-upgrade` completed without creating a root marker.

Cron/anacron: `anacron` was absent. The root cron entries and `/etc/cron.daily` scripts are root-owned; the daily apt/dpkg/logrotate/man-db/sysstat scripts either defer under systemd or run fixed root-owned paths. `attacker` could not start `cron.service`.

Logrotate: default snippets were root-owned. The checked non-rsyslog logs under `/var/log/dpkg.log`, `/var/log/apt`, `/var/log/unattended-upgrades`, `/var/log/wtmp`, `/var/log/btmp`, and `/var/log/sysstat` were not attacker-writable. `logrotate -d /etc/logrotate.conf` only read fixed root-owned config and log paths.

Maintainer scripts: the targeted maintainer-script scan for apt, dpkg, needrestart, unattended-upgrades, update-notifier-common, ubuntu-pro-client, cron, and logrotate showed debhelper/systemd enablement, fixed chmod/chown, fixed cleanup, and package-data trigger glue. These require root dpkg/apt execution and do not expose attacker-writable trigger inputs in the default state.

## Cleanup and proof

Final probe result:

```text
ROOT_PROOF=NO
NEEDRESTART_MARKER_AFTER_ROOT=NO
cleanup_done
```

Post-run health check:

```text
/root/agent_maint_glue_root_marker absent
/tmp/agent_maint_needrestart_import absent
/tmp/agent_maint_nr_user.out absent
no attacker agent_maint processes
systemctl --failed: 0 loaded units listed
```
