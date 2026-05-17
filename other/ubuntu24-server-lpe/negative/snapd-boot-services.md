# Negative: snapd boot and helper services

Date: 2026-05-16
Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`

Result: no uid1001-to-root local privilege escalation was validated.

## Evidence

Probe:

```sh
pocs/snapd_boot_services_probe.sh ubuntu24-server-lpe-target
# writes logs/snapd-boot-services.out
```

Default package proof:

```text
snapd     2.74.1+ubuntu24.04.4
systemd   255.4-1ubuntu8.15
polkitd   124-2ubuntu1.24.04.3
snap list: no snaps are installed
```

Scoped units:

```text
snapd.core-fixup.service               enabled, condition-skipped
snapd.recovery-chooser-trigger.service enabled, condition-skipped on missing /dev/input/event*
snapd.snap-repair.service              static, condition-skipped
snapd.snap-repair.timer                enabled, condition-skipped
snapd.apparmor.service                 enabled, condition-skipped on ConditionSecurity=apparmor
snapd.failure.service                  static, manually root-startable but exits: no snapd snap in system
snapd.autoimport.service               enabled, condition-skipped on missing snap_core/snapd_recovery_mode cmdline
snapd.system-shutdown.service          enabled, condition-skipped because finalrd is installed
snapd.seeded.service                   enabled, active/exited
snapd.socket                           enabled, active
```

Relevant code/config paths from `logs/snapd-boot-services.out`:

```text
/usr/lib/systemd/system/snapd.recovery-chooser-trigger.service: ExecStart=/usr/lib/snapd/snap-bootstrap recovery-chooser-trigger
/usr/lib/systemd/system/snapd.snap-repair.service: ExecStart=/usr/lib/snapd/snap-repair run
/usr/lib/systemd/system/snapd.apparmor.service: EnvironmentFile=-/etc/environment and -/var/lib/snapd/environment/snapd.conf; ExecStart=/usr/lib/snapd/snapd-apparmor start
/usr/lib/systemd/system/snapd.failure.service: EnvironmentFile=-/var/lib/snapd/environment/snapd.conf; ExecStart=/usr/lib/snapd/snap-failure snapd
/usr/lib/systemd/system/snapd.autoimport.service: ExecStart=/usr/bin/snap auto-import
/usr/lib/systemd/system/snapd.system-shutdown.service: mount/mkdir/cp fixed absolute paths into /run/initramfs
```

uid1001 could not preseed root-owned snapd inputs:

```text
/var/lib/snapd/environment/snapd.conf -> Permission denied
/var/lib/snapd/seed/seed.yaml -> Permission denied
/var/lib/snapd/seed/assertions -> Permission denied
/var/cache/snapd/assertions -> Permission denied
/var/lib/snapd/snaps and snaps/partial -> Permission denied
/var/lib/snapd/auto-import -> Permission denied
/run/mnt and /run/mnt/ubuntu-seed -> Permission denied
/dev/input and /dev/input/event0 -> Permission denied
/var/cache/apparmor -> Permission denied
```

Unprivileged unit starts all failed with interactive authorization. Direct uid1001 helper execution did not cross a privilege boundary; `snap debug seeding` was read-only, `snap auto-import` and `snap-repair` did not create markers, and `snap-preseed` on an attacker tree exited nonzero as uid1001.

A root validation pass started each service/timer while uid1001 raced symlink creation into snapd environment, seed, cache, auto-import, and `/run/mnt` paths. Condition-skipped units stayed skipped, `snapd.failure.service` ran but reported no snapd snap, and no attacker helper in the fake `PATH` ran as root.

Root proof:

```text
FINAL_ROOT_PROOF=NO
MISSING /root/snapd_boot_services_root_marker
MISSING /tmp/snapd_boot_services_tmp_marker
MISSING /var/tmp/snapd_boot_services_var_tmp_marker
```

Cleanup removed `/tmp/snapd-boot-services-probe`, probe markers, and any probe-created snapd path candidates. Final health was `systemctl is-system-running -> running`, failed units `0`, and `snapd.socket`/`snapd.seeded.service` remained active.

## Why scanners may miss it

This surface is attractive statically because multiple enabled root units consume snapd environment files, seed state, auto-import state, `/run/mnt/ubuntu-seed`, AppArmor profile state, and shutdown helpers. Exploitability depended on exact systemd conditions and path ownership: every root-consumed input was root-owned or condition-gated, and the only attacker-writable candidates were `/tmp` and `/var/tmp`, which none of the default root units consumed as trusted snapd state.

## Suggested fix

No Ubuntu Security LPE fix is justified from this target state. Defense in depth: keep snapd seed/environment/auto-import/cache directories root-owned, keep Core-only services gated by kernel command line or hardware conditions on classic Server installs, and keep absolute helper paths in the unit files.
