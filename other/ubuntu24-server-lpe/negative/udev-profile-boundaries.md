# Negative: udev MTD/ibmveth helpers and profile.d locale/gawk boundaries

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server Docker target. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Artifacts:

```text
pocs/udev_profile_boundary_probe.sh
logs/udev-profile-boundary.out
```

## Result

No uid1001-to-root LPE was validated through the default udev MTD/IBM virtual NIC rules or the default `/etc/profile.d` locale/gawk shell helpers.

The udev paths are real root hotplug boundaries, but the required MTD and IBM VIO/`ibmveth` devices are absent in the default Docker Server target, uid1001 cannot synthesize kernel uevents, and the inspected shell parser did not re-evaluate metacharacters embedded in `DEVPATH`. The profile scripts execute in the caller's shell; locale output is sanitized/quoted where corrected, and the unqualified `gawk` function path affects only the user who invokes the function.

## Default proof

Packages from the live target:

```text
udev          255.4-1ubuntu8.15
systemd       255.4-1ubuntu8.15
base-files    13ubuntu10.4
gawk          1:5.2.1-2build3
```

Root-owned udev rules/helpers:

```text
/usr/lib/udev/rules.d/75-probe_mtd.rules    0644 root:root
/usr/lib/udev/mtd_probe                     0755 root:root
/usr/lib/udev/rules.d/73-special-net-names.rules 0644 root:root
/run/udev/control                           0600 root:root socket
```

Relevant udev code/config:

```text
/usr/lib/udev/rules.d/75-probe_mtd.rules:3-5
  ACTION!="add", GOTO="mtd_probe_end"
  KERNEL=="mtd*ro", IMPORT{program}="mtd_probe $devnode"

/usr/lib/udev/rules.d/73-special-net-names.rules:10-14
  ACTION=="add", SUBSYSTEM=="net", NAME=="", DRIVERS=="ibmveth",
  PROGRAM="/bin/sh -ec 'D=$${DEVPATH#*/vio/}; D=$${D%%%%/*}; ...; echo $${D:-0}'",
  NAME="ibmveth$result"
```

Required hardware/sysfs state is absent:

```text
/sys/class/mtd absent
/sys/bus/vio absent
/sys/devices/vio absent
```

The present network devices are virtual Docker/kernel devices, not `ibmveth` devices under `/devices/vio`.

Root-owned profile scripts:

```text
/etc/profile                                0644 root:root
/etc/profile.d                             0755 root:root
/etc/profile.d/01-locale-fix.sh            0644 root:root
/usr/bin/locale-check                      0755 root:root
/etc/profile.d/gawk.sh                     0644 root:root
```

Relevant profile code:

```text
/etc/profile.d/01-locale-fix.sh:1-2
  # Make sure the locale variables are set to valid values.
  eval $(/usr/bin/locale-check C.UTF-8)

/etc/profile.d/gawk.sh:1-4
  gawkpath_default () {
    unset AWKPATH
    export AWKPATH=`gawk 'BEGIN {print ENVIRON["AWKPATH"]}'`
  }
```

## Trigger attempts

As uid1001:

```text
udevadm trigger --subsystem-match=mtd
  -> no MTD sysfs/device path existed

udevadm trigger --subsystem-match=net
  -> Failed to write 'change' to /sys/devices/.../uevent: Permission denied

udevadm test /sys/class/net/*
  -> could read the rule file, but failed to update /run/udev state and did not satisfy ibmveth predicates
```

The ibmveth shell parser was exercised with metacharacter-bearing `DEVPATH` strings under root as a canary:

```text
/devices/vio/3000;id>/root/udev_profile_boundary_root/net/eth1
/devices/vio/$(id>/root/udev_profile_boundary_root)/net/eth1
/devices/vio/`id>/root/udev_profile_boundary_root`/net/eth1
/devices/vio/3000\nid>/root/udev_profile_boundary_root/net/eth1
```

The output was data such as `;id>`, `>`, `0`, or `id>`. `/root/udev_profile_boundary_root` was not created, confirming the fragment does not re-parse expanded `DEVPATH` content as shell syntax.

Locale/profile tests:

```text
LANG='bad;id>/root/udev_profile_boundary_root' locale-check C.UTF-8 -> LANG='C.UTF-8'
LC_ALL='bad$(id>/root/udev_profile_boundary_root)' locale-check C.UTF-8 -> LC_ALL='C.UTF-8'
LC_*='en_US.UTF-8@x;id>/root/...' locale-check C.UTF-8 -> LC_*='C.UTF-8'
```

A root login-shell canary with malicious `LC_ALL` and `LANG` did not create `/root/udev_profile_boundary_root`; `LC_ALL` became `C.UTF-8`, and the malicious `LANG` value remained inert environment data.

For `gawk.sh`, uid1001 placed a fake `gawk` earlier in `PATH` and invoked `gawkpath_default` in an attacker login shell. The fake command ran only as:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

No root marker was produced.

## Why this is not a finding

The udev helpers are root-run only for kernel/device-manager events. In this default target there is no MTD class, no VIO bus, and no IBM `ibmveth` net device. A normal local user cannot write the relevant sysfs `uevent` files or the root-owned udev control/database paths. The IBM naming rule's shell fragment treats hostile `DEVPATH` content as parameter-expansion data, not as a second shell program.

The locale profile script uses `eval`, but `/usr/bin/locale-check` emits quoted replacement assignments for invalid locale variables in the tested cases, and the attacker cannot force a root login shell from a normal non-sudo account. The `gawk.sh` functions are only definitions until explicitly called, and an attacker-controlled `PATH` causes execution only in that attacker's shell. There is no default root consumer of attacker-owned `PATH` or profile state.

No root command execution, root-owned attacker-selected write, privileged group transition, or `uid=0` context was reached from uid1001.

## Cleanup

The probe removed `/root/udev_profile_boundary_root`, `/tmp/udev_profile_boundary_attacker`, and temporary files under `/tmp/udev_profile_boundary_*`, then verified:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend -> no output
```

## Why scanners may miss it

This surface looks high-risk to simple scanners because it combines root udev `IMPORT{program}`/`PROGRAM=` rules, a shell fragment, `/etc/profile.d` scripts, `eval`, and unqualified command lookup. Exploitability depends on proving kernel-event reachability, device predicates, shell re-evaluation semantics, profile execution identity, and whether attacker-controlled environment/PATH can cross into a root shell.

## Suggested fix

No LPE fix is justified from this target state. Defense-in-depth changes would be to keep udev control/sysfs event writes root-only, prefer absolute helper paths in udev rules, quote shell expansions in future rule edits, and avoid `eval` in profile scripts unless helper output is strictly quoted as `locale-check` currently emits.
