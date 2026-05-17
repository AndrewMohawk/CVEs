# Negative: dpkg database backup timer

Date: 2026-05-16
Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`

Result: no uid1001-to-root local privilege escalation was validated.

## Evidence

Probe:

```sh
pocs/dpkg_db_backup_probe.sh ubuntu24-server-lpe-target | tee logs/dpkg-db-backup.out
```

Default package and unit state from the target:

```text
dpkg      1.22.6ubuntu6.6
systemd   255.4-1ubuntu8.15
tar       1.35+dfsg-3build1
dpkg-db-backup.timer enabled active
dpkg-db-backup.service static inactive/dead, triggered by timer
```

Relevant code/config paths:

```text
/usr/libexec/dpkg/dpkg-db-backup:23-28 reads DPKG_DATADIR then sources dpkg-error.sh
/usr/libexec/dpkg/dpkg-db-backup:25,41-46 resolves `tar` and `savelog` through PATH
/usr/libexec/dpkg/dpkg-db-backup:51-85 writes rotated backups in /var/backups
/usr/lib/systemd/system/dpkg-db-backup.service:5-7 ExecStart=/usr/libexec/dpkg/dpkg-db-backup
/usr/lib/systemd/system/dpkg-db-backup.timer:5-10 OnCalendar=daily, Persistent=true
```

Default permissions:

```text
/usr/libexec/dpkg/dpkg-db-backup        0755 root:root
/usr/lib/systemd/system/dpkg-db-backup.service 0644 root:root
/usr/lib/systemd/system/dpkg-db-backup.timer   0644 root:root
/var/backups                            0755 root:root
/var/lib/dpkg                           0755 root:root
/var/lib/dpkg/status                    0644 root:root
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
```

uid1001 could not write or preplace the backup/input paths, could not set the systemd manager environment, and could not start the service/timer:

```text
touch /var/backups/dpkg.status -> Permission denied
ln -s /tmp/... /var/backups/dpkg.status -> Permission denied
touch /var/lib/dpkg/status.probe -> Permission denied
ln /var/lib/dpkg/status /tmp/... -> Operation not permitted
systemctl set-environment PATH=... DPKG_DATADIR=... -> Access denied
systemctl start dpkg-db-backup.service -> Interactive authentication required
Manager.StartUnit(dpkg-db-backup.service) -> Interactive authentication required
```

Direct execution with attacker-controlled `PATH` and `DPKG_DATADIR` did hit fake `tar`, `savelog`, and `dpkg-error.sh`, but only as uid1001 and failed to write `/var/backups`. A root-started service while uid1001 raced symlink/hardlink replacement created only normal root-owned backups under `/var/backups`; the attacker's chosen target stayed unchanged.

Root proof:

```text
NO_ROOT_MARKER
NO_ROOT_HIT_IN_ATTACKER_HITS
attacker_chosen_target_contents=attacker target before root
```

Cleanup removed the created `/var/backups/dpkg.*.0` and `alternatives.tar.0` files, `/tmp/dpkg_db_backup_probe*`, and reset failed state. Final health was `systemctl is-system-running -> running`, failed units `0`.

## Why scanners may miss it

The script has scanner-attractive primitives: root timer execution, unqualified `tar`/`savelog`, attacker-influencable `DPKG_DATADIR` if an environment can be injected, and root writes in `/var/backups`. In the default Server state, uid1001 cannot control the root manager environment or the root-owned input/output directories, and direct execution is unprivileged.

## Suggested fix

No Ubuntu Security LPE fix is justified from this target state. Defense in depth: use absolute `/usr/bin/tar` and `/usr/bin/savelog`, ignore `DPKG_DATADIR` when running from the packaged systemd unit, and keep `/var/backups` and `/var/lib/dpkg` root-owned/non-writable.
