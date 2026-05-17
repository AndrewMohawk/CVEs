# Negative: systemd initrd/PCR/TPM reachability

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server Docker target. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Artifacts:

```text
pocs/systemd_initrd_pcr_reachability_probe.sh
logs/systemd-initrd-pcr-reachability-20260517.out
```

## Result

No uid1001-to-root LPE was validated through the undercovered initrd, hibernate-resume, TPM/PCR, or udev-settle systemd units.

`ROOT_PROOF=no`; `/root/systemd-initrd-pcr-reachability-20260517-root` was absent after all triggers, the target stayed `running`, and no systemd units were failed.

## Default package and unit proof

Target packages:

```text
initramfs-tools  0.142ubuntu25.8
systemd          255.4-1ubuntu8.15
udev             255.4-1ubuntu8.15
```

Root unit/helper surfaces checked:

```text
initrd-parse-etc.service              systemd-fstab-generator systemd-sysroot-fstab-check
initrd-udevadm-cleanup-db.service     udevadm info --cleanup-db
initrd-switch-root.service            systemctl --no-block switch-root
systemd-hibernate-resume.service      /usr/lib/systemd/systemd-hibernate-resume
systemd-tpm2-setup-early.service      /usr/lib/systemd/systemd-tpm2-setup --early=yes
systemd-pcrphase-initrd.service       systemd-pcrextend --graceful enter-initrd
systemd-pcrphase-sysinit.service      systemd-pcrextend --graceful sysinit
systemd-pcrphase.service              systemd-pcrextend --graceful ready
systemd-pcrfs-root.service            systemd-pcrextend --graceful --file-system=/
systemd-pcrfs@.service                systemd-pcrextend --graceful --file-system=%f
systemd-udev-settle.service           udevadm settle
```

All helpers are root-owned `0755` with no file capabilities.

## Reachability blockers

The initrd and hibernate units are not live in the real-root system:

```text
initrd-parse-etc.service              AssertPathExists=/etc/initrd-release
initrd-udevadm-cleanup-db.service     AssertPathExists=/etc/initrd-release
initrd-switch-root.service            AssertPathExists=/etc/initrd-release
systemd-hibernate-resume.service      AssertPathExists=/etc/initrd-release
```

The PCR/TPM units are not live in this stock Docker target:

```text
systemd-tpm2-setup-early.service      ConditionSecurity=measured-uki
systemd-pcrphase-initrd.service       ConditionPathExists=/etc/initrd-release; ConditionSecurity=measured-uki
systemd-pcrphase-sysinit.service      ConditionPathExists=!/etc/initrd-release; ConditionSecurity=measured-uki
systemd-pcrphase.service              ConditionPathExists=!/etc/initrd-release; ConditionSecurity=measured-uki
systemd-pcrfs-root.service            ConditionPathExists=!/etc/initrd-release; ConditionSecurity=measured-uki
systemd-pcrfs@.service                ConditionPathExists=!/etc/initrd-release; ConditionSecurity=measured-uki
```

There is no TPM device:

```text
/dev/tpm0   absent
/dev/tpmrm0 absent
```

The relevant root input paths were absent or not writable to uid1001:

```text
/sysroot/etc/fstab                  absent
/run/udev/data/attacker             permission denied
/run/udev/tags/systemd/attacker     permission denied
/run/systemd/io.systemd.PCRExtend   permission denied
/sys/power/resume                   absent
```

## Attacker trigger results

As uid1001, `systemctl start` for every root unit returned interactive authentication required:

```text
initrd-parse-etc.service
initrd-udevadm-cleanup-db.service
initrd-switch-root.service
systemd-hibernate-resume.service
systemd-tpm2-setup-early.service
systemd-pcrphase-initrd.service
systemd-pcrphase-sysinit.service
systemd-pcrphase.service
systemd-pcrfs-root.service
systemd-udev-settle.service
```

Direct helper execution stayed unprivileged:

```text
systemd-fstab-generator into attacker-owned dirs  rc=0, attacker-owned output only
udevadm info --cleanup-db                         rc=0, no root marker
udevadm settle                                    rc=0, no root marker
systemd-pcrextend --graceful --file-system=$HOME  rc=1, path not a mount point
systemd-pcrextend --graceful attacker-phase       rc=0, no TPM support, no root marker
systemd-tpm2-setup --early=yes                    rc=1, Operation not supported
systemd-hibernate-resume                          rc=0, no root marker
```

Login1 power/sleep actions from the no-seat attacker also required authorization:

```text
org.freedesktop.login1.reboot      rc=2
org.freedesktop.login1.hibernate   rc=2
org.freedesktop.login1.power-off   rc=2
```

## Why this is not an LPE

These are real root boot-transition helpers, but they are not default-reachable from the normal unprivileged shell in the live stock Server target. The initrd paths require the initrd environment, PCR/TPM paths require measured UKI/TPM state, root unit starts are polkit-gated, and direct helper invocation runs with the caller's uid. No root command execution, root-owned attacker-controlled write, or privilege-bearing file descriptor was reached.

Normal scanners can over-rank these units because the root `ExecStart` lines look dangerous in isolation. The exploitable boundary is the combination of initrd assertions, measured-UKI conditions, absent TPM devices, root-owned runtime paths, and systemd manager authorization.

## Cleanup

The probe removed `/home/attacker/systemd-initrd-pcr-reachability-20260517`, `/tmp/systemd-initrd-pcr-reachability-20260517*`, and the root marker path, then reset failed state for the tested units. Final health:

```text
systemctl is-system-running -> running
systemctl --failed --no-pager -> 0 loaded units listed
```
