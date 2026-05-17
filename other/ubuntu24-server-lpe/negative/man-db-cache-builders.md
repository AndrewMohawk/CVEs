# man-db/groff cache builders: no default local privilege escalation

## Result

No LPE was found in the stock Ubuntu 24.04 Server man-db/groff cache-builder lane.

The only command-execution primitive reached was attacker-controlled roff unsafe-mode execution from the attacker's own `catman`/`groff` invocation. The payload ran as `uid=1001(attacker)` only. The default root-triggered path (`man-db.timer` -> `man-db.service`) did not consume attacker `MANPATH`, `MANROFFOPT`, `PAGER`, `LESSOPEN`, `PATH`, per-user manpages, per-user `manpath.config`, or attacker cache symlinks.

## Default install and reachability proof

Target: `ubuntu24-server-lpe-target`.

Observed packages in `logs/man-db-cache.out`:

- `man-db 2.12.0-4build2`
- `groff-base 1.23.0-3build2`
- `cron 3.0pl1-184ubuntu2`
- `cron-daemon-common 3.0pl1-184ubuntu2`

Default enabled/reachable state:

- `man-db.timer` is `enabled enabled` and active waiting.
- `man-db.service` is static and triggered by the timer.
- `cron.service` is `enabled enabled` and active running, but `/etc/cron.daily/man-db` and `/etc/cron.weekly/man-db` exit when `/run/systemd/system` exists.

## Relevant code/config paths

- `/usr/lib/systemd/system/man-db.service:9` runs `+/usr/bin/install -d -o man -g man -m 0755 /var/cache/man` as root.
- `/usr/lib/systemd/system/man-db.service:11-12` runs `/usr/bin/mandb --quiet` as `User=man`.
- `/usr/lib/systemd/system/man-db.service:19,22,27` sets `PrivateTmp=true`, `ProtectHome=true`, and `ProtectSystem=full`.
- `/usr/lib/systemd/system/man-db.timer:6-8` runs daily with randomized delay and persistence.
- `/etc/cron.daily/man-db:7-9` and `/etc/cron.weekly/man-db:7-9` skip in favor of the systemd timer.
- `/etc/cron.daily/man-db:33-47` and `/etc/cron.weekly/man-db:34-37` would run cache cleanup/`mandb` as `--chuid man` on non-systemd systems.
- `/usr/lib/tmpfiles.d/man-db.conf:1` creates `/var/cache/man` as `0755 man man`.
- `/etc/manpath.config:20-22` maps global manpaths `/usr/man`, `/usr/share/man`, and `/usr/local/share/man`.
- `/etc/manpath.config:66-72` maps those global manpaths to `/var/cache/man*`.

Default permissions: global manpath/config roots were root-owned and not writable by uid1001; `/var/cache/man` was `0755 man:man`; man-db/groff binaries were root-owned `0755` with no file capabilities.

## Trigger commands

```sh
cd /Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe
bash -n pocs/man_db_cache_probe.sh
./pocs/man_db_cache_probe.sh ubuntu24-server-lpe-target > logs/man-db-cache.out 2>&1
```

The probe plants attacker-owned manpages, a hostile per-user `manpath.config`, fake groff/troff/tbl/eqn/pic/preconv/soelim/pager helpers, `MANROFFOPT=-U`, `PAGER`, `LESSOPEN`, and cache symlinks. It then exercises:

- attacker direct `mandb -C ... --user-db`
- attacker direct `catman -C ... -M ...`
- attacker direct `/usr/bin/groff -U ...`
- attacker `mandb` mapped to `/var/cache/man/man_db_cache_probe`
- attacker `systemctl set-environment`, `systemctl start man-db.service`, and `systemd-run`
- root-simulated default `systemctl start man-db.service`
- default cron scripts with systemd present
- `systemd-tmpfiles --create /usr/lib/tmpfiles.d/man-db.conf`

## Evidence

Key log lines:

- `touch /var/cache/man/...`: `Permission denied`
- `mkdir /usr/local/share/man/...`: `Permission denied`
- `ln -s ... /var/cache/man/...`: `Permission denied`
- `mandb_rootcache_rc=2`; `Only the 'man' user can create or update system-wide databases; acting as if the --user-db option was used.`
- `systemctl set-environment`: `Access denied`
- `systemctl start man-db.service`: `Interactive authentication required`
- root service execution showed only the intended paths: `/usr/bin/install ... /var/cache/man` and `/usr/bin/mandb --quiet`
- `NO_ROOT_PAYLOAD_MARKER`
- `system_state_after=running`
- `failed_units_after=0`
- `NO_PROBE_LEFTOVERS`

The direct roff `.pso`/`.sy` payload hits were logged as `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

## Cleanup

The PoC removes:

- `/tmp/man_db_cache_probe`
- `/var/tmp/man_db_cache_probe`
- `/root/man_db_cache_probe_*`
- `/home/attacker/.local/share/man/man1/man_db_cache_probe.1`
- `/home/attacker/.cache/man_db_cache_probe*`

Post-run verification found no probe leftovers and zero failed systemd units.

## Why this is likely missed by generic scans

The interesting surface is not a simple SUID bit or writable path. It depends on following the trust boundary between user-controlled roff/man-db inputs and the default timer path, then proving whether systemd propagates user environment or scans per-user manpaths. The apparent risky knobs (`MANROFFOPT=-U`, `PAGER`, `LESSOPEN`, groff preprocessors, per-user `manpath.config`) are real execution surfaces only for the invoking unprivileged user in this default state.

## Suggested triage disposition

No Ubuntu Security issue from this lane. The current defaults are the right hardening shape: keep `mandb` under `User=man`, keep global manpath/config roots root-owned, keep `/var/cache/man` non-writable to normal users, retain `PrivateTmp=true`/`ProtectHome=true`/`ProtectSystem=full`, and keep cron scripts deferring to the systemd timer on systemd systems.
