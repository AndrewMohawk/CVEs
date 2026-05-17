# Negative: systemd static and condition-gated root units

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server Docker target. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Artifacts:

```text
pocs/systemd_static_gated_units_probe.sh
logs/systemd-static-gated-units.out
```

## Result

No uid1001-to-root LPE was validated through the default static/gated systemd root units for rfkill, sleep/hibernate, Plymouth shutdown splash, rescue/emergency shell, or volatile-root initrd handling.

These units are installed by default, but they are inactive, static, hardware/initrd/container/boot-argument gated, or reachable only through privileged systemd/logind operations. Direct uid1001 starts and target isolation attempts are polkit-admin gated.

## Default proof

Packages from the live target:

```text
systemd       255.4-1ubuntu8.15
plymouth      24.004.60-1ubuntu7.1
rfkill        not installed as a package
```

The unit files are loaded from the default systemd/plymouth packages, but all tested units were `inactive/dead` and `static`:

```text
systemd-rfkill.socket
systemd-rfkill.service
systemd-suspend.service
systemd-hibernate.service
systemd-hybrid-sleep.service
systemd-suspend-then-hibernate.service
plymouth-reboot.service
plymouth-poweroff.service
plymouth-halt.service
plymouth-kexec.service
rescue.service
emergency.service
systemd-volatile-root.service
```

Relevant root execution/config paths from the target:

```text
/usr/lib/systemd/system/systemd-rfkill.socket:13,16,23
  ConditionPathExists=!/etc/initrd-release
  BindsTo=sys-devices-virtual-misc-rfkill.device
  ListenSpecial=/dev/rfkill

/usr/lib/systemd/system/systemd-rfkill.service:13,16,22-24
  ConditionPathExists=!/etc/initrd-release
  BindsTo=sys-devices-virtual-misc-rfkill.device
  ExecStart=/usr/lib/systemd/systemd-rfkill
  NoNewPrivileges=yes
  StateDirectory=systemd/rfkill

/usr/lib/systemd/system/systemd-suspend.service:17-19
  Type=oneshot
  ExecStart=/usr/lib/systemd/systemd-sleep suspend

/usr/lib/systemd/system/systemd-hibernate.service:17-19
  Type=oneshot
  ExecStart=/usr/lib/systemd/systemd-sleep hibernate

/usr/lib/systemd/system/plymouth-reboot.service:6-13
  ConditionKernelCommandLine=!plymouth.enable=0
  ConditionKernelCommandLine=!nosplash
  ConditionKernelCommandLine=splash
  ConditionVirtualization=!container
  ExecStart=/usr/sbin/plymouthd --mode=reboot --attach-to-session
  ExecStartPost=-/usr/bin/plymouth show-splash

/usr/lib/systemd/system/rescue.service:21
  ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue

/usr/lib/systemd/system/emergency.service:21
  ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency

/usr/lib/systemd/system/systemd-volatile-root.service:17,22
  AssertPathExists=/etc/initrd-release
  ExecStart=/usr/lib/systemd/systemd-volatile-root yes /sysroot
```

Default gating/input state in the Docker Server target:

```text
/dev/rfkill absent
/sys/class/rfkill absent
/sys/power/state absent
/etc/initrd-release absent
/sysroot absent
ConditionVirtualization=!container failed
ConditionKernelCommandLine=splash failed
AssertPathExists=/etc/initrd-release failed
```

The root helpers themselves are root-owned `0755`:

```text
/usr/lib/systemd/systemd-rfkill
/usr/lib/systemd/systemd-sleep
/usr/bin/plymouth
/sbin/sulogin
```

## Trigger attempts

As uid1001:

```text
systemctl start systemd-rfkill.socket
systemctl start systemd-suspend.service
systemctl start systemd-hibernate.service
systemctl start systemd-hybrid-sleep.service
systemctl start systemd-suspend-then-hibernate.service
systemctl start plymouth-reboot.service
systemctl start plymouth-poweroff.service
systemctl start rescue.service
systemctl start emergency.service
systemctl start systemd-volatile-root.service
systemctl isolate rescue.target
```

Each command returned:

```text
Interactive authentication required.
```

As uid1001, login1 capability checks showed sleep/hibernate unavailable in the container and power operations requiring authorization:

```text
CanSuspend -> Call failed: No such file or directory
CanHibernate -> Call failed: No such file or directory
CanHybridSleep -> Call failed: No such file or directory
CanSuspendThenHibernate -> Call failed: No such file or directory
CanReboot -> s "challenge"
CanPowerOff -> s "challenge"
```

All units remained inactive/dead after the trigger attempts, `systemctl is-system-running` stayed `running`, and no failed units were left behind.

## Why this is not a finding

The rfkill path requires a kernel rfkill device that is absent in the default Docker Server target, and the root service is tied to `/dev/rfkill`/`sys-devices-virtual-misc-rfkill.device`, not an attacker-created file.

The sleep/hibernate units are root oneshots, but the default target has no usable `/sys/power/state` path and uid1001 cannot start the units directly. No attacker-writable `/lib/systemd/system-sleep` hook path exists.

The Plymouth shutdown units are default-installed but fail `ConditionVirtualization=!container` and `ConditionKernelCommandLine=splash` in this target. Direct unit starts are admin-gated.

The rescue/emergency services execute sulogin-style root console flows only after privileged target isolation or boot failure paths. A normal local uid1001 shell cannot isolate into rescue/emergency targets or start those services.

The volatile-root unit is initrd-only due `AssertPathExists=/etc/initrd-release`; the default running Server target has neither that assert path nor `/sysroot`, and uid1001 cannot start the unit.

No root command execution, root-owned attacker-selected write, privileged group transition, or `uid=0` context was reached.

## Cleanup

The probe did not create persistent state. It verified:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend -> no output
```

## Why scanners may miss it

These are real root execution units with interesting names and helpers, but exploitability depends on systemd state transitions, hardware/sysfs presence, initrd phase, kernel command line, container conditions, and polkit authorization. A static unit inventory can over-rank them unless it proves the default reachability constraints.

## Suggested fix

No LPE fix is justified from this target state. Keep direct unit starts and target isolation admin-gated, keep rescue/emergency console flows bound to privileged boot/systemd transitions, and keep hardware/initrd/boot-argument conditions on the rfkill, Plymouth, and volatile-root paths.
