# Negative: systemd storage, quota, battery, BSOD, and machine-id maintenance units

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server image. Attacker identity was `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no uid1001 -> root local privilege escalation was validated in this lane. The audited units are real default systemd root-transition surfaces, but the live Server state made them condition-gated, admin-gated, missing their optional quota helpers, or directly executable only as uid1001.

Artifacts:

```text
pocs/systemd_storage_quota_misc_probe.sh
logs/systemd-storage-quota-misc.out
```

## Default package and unit proof

Relevant package state from the target:

```text
systemd              255.4-1ubuntu8.15
systemd-sysv         255.4-1ubuntu8.15
udev                 255.4-1ubuntu8.15
libsystemd0:arm64    255.4-1ubuntu8.15
libudev1:arm64       255.4-1ubuntu8.15
mount                2.39.3-9ubuntu6.5
util-linux           2.39.3-9ubuntu6.5
quota                ABSENT
```

The helpers and unit files are shipped by `systemd`:

```text
systemd: /usr/lib/systemd/systemd-storagetm
systemd: /usr/lib/systemd/systemd-quotacheck
systemd: /usr/lib/systemd/systemd-battery-check
systemd: /usr/lib/systemd/systemd-bsod
systemd: /usr/bin/systemd-machine-id-setup
systemd: /usr/lib/systemd/system/quotaon.service
systemd: /usr/lib/systemd/system/systemd-quotacheck.service
```

Default unit state:

```text
quotaon.service                   static
systemd-quotacheck.service        static
systemd-storagetm.service         static
systemd-battery-check.service     static
systemd-bsod.service              static
systemd-machine-id-commit.service static
```

## Code/config trust boundaries checked

Relevant unit paths and line numbers:

```text
/usr/lib/systemd/system/systemd-storagetm.service
  line 13: ConditionVirtualization=!container
  lines 19-20: FailureAction=reboot / SuccessAction=reboot
  lines 23-27: Type=notify, tty stdio, ExecStart=/usr/lib/systemd/systemd-storagetm --all

/usr/lib/systemd/system/quotaon.service
  line 14: ConditionPathExists=/usr/sbin/quotaon
  line 24: ExecStart=/usr/sbin/quotaon -aug

/usr/lib/systemd/system/systemd-quotacheck.service
  line 14: ConditionPathExists=/usr/sbin/quotacheck
  line 24: ExecStart=/usr/lib/systemd/systemd-quotacheck

/usr/lib/systemd/system/systemd-battery-check.service
  lines 13-16: container, power_supply, kernel cmdline, and initrd assertions
  lines 24-25: ExecStart=/usr/lib/systemd/systemd-battery-check and FailureAction=poweroff-force

/usr/lib/systemd/system/systemd-bsod.service
  line 13: ConditionVirtualization=no
  line 21: ExecStart=/usr/lib/systemd/systemd-bsod --continuous

/usr/lib/systemd/system/systemd-machine-id-commit.service
  lines 17-18: /etc writable and /etc/machine-id mount-point conditions
  line 23: ExecStart=systemd-machine-id-setup --commit
```

The condition checks failed in the live Docker Server target:

```text
ConditionVirtualization=!container failed
ConditionPathExists=/usr/sbin/quotaon failed
ConditionPathExists=/usr/sbin/quotacheck failed
ConditionVirtualization=no failed
ConditionDirectoryNotEmpty=/sys/class/power_supply failed
AssertPathExists=/etc/initrd-release failed
ConditionPathIsMountPoint=/etc/machine-id failed
```

## Attacker trigger attempts

uid1001 could not write the fixed root input, drop-in, generator, quota, machine-id, storage target, battery, BSOD, or kernel control paths:

```text
/etc/systemd/system/systemd-storagetm.service.d/probe.conf  Permission denied
/run/systemd/system/systemd-storagetm.service.d/probe.conf  Permission denied
/run/systemd/system.conf.d/probe.conf                       Permission denied
/run/systemd/generator/quotaon.service                      Permission denied
/etc/fstab                                                   Permission denied
/aquota.user                                                 Permission denied
/aquota.group                                                Permission denied
/etc/machine-id                                              Permission denied
/run/machine-id                                              Permission denied
/var/lib/systemd/storagetm/attacker                         Permission denied
/run/systemd/bsod/attacker                                  Permission denied
/sys/class/power_supply/attacker                            Permission denied
/sys/kernel/config/nvmet/attacker                           Permission denied
/proc/sysrq-trigger                                         Permission denied
```

System manager mutation and unit transition attempts were denied:

```text
systemctl --system set-environment PATH=...     Access denied
systemctl --system import-environment PATH      Access denied
systemctl start systemd-storagetm.service       Interactive authentication required
systemctl start quotaon.service                 Interactive authentication required
systemctl start systemd-quotacheck.service      Interactive authentication required
systemctl start systemd-battery-check.service   Interactive authentication required
systemctl start systemd-bsod.service            Interactive authentication required
systemctl start systemd-machine-id-commit.service Interactive authentication required
systemd-run --system ...                        Interactive authentication required
systemctl daemon-reload                         Interactive authentication required
systemctl link ...                              Interactive authentication required
```

The bare `ExecStart=systemd-machine-id-setup --commit` path was checked for PATH hijack. The systemd default binary search path was `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin`, the system manager's live `PATH` stayed root-controlled, and uid1001 could not change it. A fake `systemd-machine-id-setup` in `/home/attacker` was never reached.

Direct helper execution did not cross privilege. The helpers are ordinary `0755 root:root` executables, not setuid/setgid. Representative direct results as uid1001:

```text
systemd-storagetm --nqn=... /home/attacker/.../disk.img
  Failed to open /sys/kernel/config/nvmet/subsystems: No such file or directory

systemd-storagetm --all
  Failed to open /sys/kernel/config/nvmet/ports: No such file or directory

/usr/lib/systemd/systemd-quotacheck
  rc=0, no root write

/usr/lib/systemd/systemd-battery-check
  rc=0, no root write

/usr/lib/systemd/systemd-bsod
  rc=0, no root write

systemd-machine-id-setup --commit
  rc=0, /etc/machine-id SHA256 unchanged

touch /root/systemd_storage_quota_misc_lpe_marker
  Permission denied
```

Final root-marker and health proof:

```text
ROOT_MARKER_ABSENT
systemctl is-system-running -> running
systemctl --failed --no-legend | wc -l -> 0
ROOT_PROOF=NO
```

## Cleanup

The probe removes:

```text
/root/systemd_storage_quota_misc_lpe_marker
/home/attacker/systemd_storage_quota_misc_probe
/tmp/systemd_storage_quota_misc_*
/tmp/attacker-systemd-run-id
```

It also resets failed state for the audited units. The target remained healthy after cleanup.

## Why scanners likely miss this lane

These are low-frequency root transitions hidden behind systemd conditions, early-boot/initrd assumptions, static unit state, and missing optional helper packages. A generic scanner may flag root execution, `SuccessAction=reboot`, the storage-target helper accepting regular file arguments, quota `aquota.*` naming, the BSOD journal parser, or the bare machine-id `ExecStart` path. The exploitable question is whether a normal local user can control a default root start or a default consumed input; in this target, they could not.

## Suggested fixes

No Ubuntu Security LPE fix is proposed because no privilege escalation was validated. Hardening options suitable for triage notes:

```text
- Keep storage-target-mode and maintenance units admin-gated through systemd/polkit.
- Preserve root-only ownership on /etc/systemd, /run/systemd, /etc/fstab, /etc/machine-id, /sys/kernel/config, and quota files.
- Consider changing systemd-machine-id-commit.service to an absolute ExecStart path (/usr/bin/systemd-machine-id-setup --commit) to remove ambiguity for reviewers, even though systemd used a fixed root-controlled search path here.
- Keep quotaon.service and systemd-quotacheck.service condition-gated when the quota package is absent.
```

Novelty checks were not run because this lane did not produce a root proof or reportable LPE.
