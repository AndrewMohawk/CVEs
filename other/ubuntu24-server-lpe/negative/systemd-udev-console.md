# Negative: systemd udev coldplug and console getty credential paths

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server Docker target  
Probe: `pocs/systemd_udev_console_probe.sh`  
Log: `logs/systemd-udev-console.out`  
Result: no validated uid1001-to-root LPE. `ROOT_PROOF=NO`.

## Default proof

Relevant default packages:

```text
login        1:4.13+dfsg1-4ubuntu3.2
systemd      255.4-1ubuntu8.15
udev         255.4-1ubuntu8.15
util-linux   2.39.3-9ubuntu6.5
```

The target remained healthy after the probe:

```text
systemctl is-system-running -> running
failed units -> 0
```

## Candidate 1: systemd-udev-trigger coldplug

Default unit state:

```text
Id=systemd-udev-trigger.service
FragmentPath=/usr/lib/systemd/system/systemd-udev-trigger.service
UnitFileState=static
ActiveState=active
SubState=exited
ConditionResult=yes
```

Default unit code:

```text
/usr/lib/systemd/system/systemd-udev-trigger.service:17
  ConditionPathIsReadWrite=/sys

/usr/lib/systemd/system/systemd-udev-trigger.service:22
  ExecStart=-udevadm trigger --type=all --action=add --prioritized-subsystem=module,block,tpmrm,net,tty,input
```

The root coldplug path is real: PID1 starts a root `udevadm trigger`, which writes
`add` uevents to kernel sysfs nodes and causes root `systemd-udevd` to process
default rules. The local attack question was whether uid1001 could retrigger it,
inject search path/environment, or write the same sysfs knobs directly.

Relevant path ownership:

```text
/sys                                                   dr-xr-xr-x root:root
/run/udev/control                                      srw------- root:root
/usr/bin/udevadm                                       -rwxr-xr-x root:root
/usr/lib/systemd/system/systemd-udev-trigger.service   -rw-r--r-- root:root
```

uid1001 could not start the unit through systemd and could not directly write
uevents:

```text
systemctl start systemd-udev-trigger.service
  Failed to start systemd-udev-trigger.service: Interactive authentication required.

udevadm trigger --type=all --action=add ...
  udevadm_trigger_rc=1
  block: Failed to write 'add' to '/sys/module/block/uevent': Permission denied
  loop: Failed to write 'add' to '/sys/module/loop/uevent': Permission denied

printf add > /sys/module/block/uevent
  Permission denied

touch /run/udev/attacker
  Permission denied
```

No root marker was created under `/root`, `/run`, or `/tmp`.

## Candidate 2: console-getty credentials/login path

Default unit state in this Docker Server target:

```text
Id=console-getty.service
FragmentPath=/usr/lib/systemd/system/console-getty.service
UnitFileState=enabled-runtime
ActiveState=inactive
SubState=dead
ConditionResult=no
TTYPath=/dev/console
ImportCredential="agetty.*" "login.*"
```

Default unit code:

```text
/usr/lib/systemd/system/console-getty.service:18
  ConditionPathExists=/dev/console

/usr/lib/systemd/system/console-getty.service:23
  ExecStart=-/sbin/agetty -o '-p -- \u' --noclear --keep-baud - 115200,38400,9600 $TERM

/usr/lib/systemd/system/console-getty.service:29
  TTYPath=/dev/console

/usr/lib/systemd/system/console-getty.service:34-35
  ImportCredential=agetty.*
  ImportCredential=login.*
```

The unit is a default Server console path, but it is condition-gated here because
the Docker target has no `/dev/console`:

```text
/run/credentials   drwxr-xr-x root:root
/dev/console       absent
/dev/tty0          crw--w---- root:tty
/sbin/agetty       -rwxr-xr-x root:root
```

uid1001 could not start the unit, seed imported credentials, or write the console
device:

```text
systemctl start console-getty.service
  Failed to start console-getty.service: Interactive authentication required.

test -w /run/credentials
  NO_WRITE_CREDS

mkdir /run/credentials/console-getty.service
  Permission denied

printf pwn > /dev/console
  Permission denied
```

No root marker was created.

## Why this is not a finding

Both units are default systemd trust boundaries. `systemd-udev-trigger.service`
does root coldplug all devices and can drive root udev rule execution, but a normal
uid1001 user cannot restart it, alter its executable/search path/environment, write
its sysfs uevent targets, or reach `/run/udev/control`. `console-getty.service`
is a default console login unit, but in this Docker Server target it is not active
because `/dev/console` is absent; its credential import directory is root-owned and
uid1001 cannot seed `agetty.*` or `login.*` credentials. This stayed below the user
bar because it produced no privileged write, execution, account/group transition,
or root proof.

## Cleanup

The probe removed marker paths:

```sh
rm -f /root/systemd_udev_console_root /run/systemd_udev_console_root /tmp/systemd_udev_console_root
```

The final health check was `running` with zero failed units.

## Why scanners may miss it

Static inspection sees root `ExecStart=-udevadm trigger ...` without an absolute
path and sees `ImportCredential=login.*` on a privileged getty service. The decisive
reachability details are runtime systemd authorization, sysfs write permissions,
`/run/udev/control` mode, the `ConditionPathExists=/dev/console` gate, and the
root-owned credential store. Those are easy to miss in generic unit-file sweeps.

## Suggested fixes

No Ubuntu Security LPE fix is warranted from this negative result. Defense-in-depth
options:

```text
systemd-udev-trigger: keep unit starts authorization-gated for non-admin users and keep /run/udev/control root-only.
systemd-udev-trigger: use an absolute ExecStart path for clarity even though systemd's execution environment is not attacker-controlled here.
console-getty: keep /run/credentials root-owned and keep console TTY devices inaccessible to normal users.
console-getty: document that ImportCredential globs must only consume manager-provided credentials, not user-writable runtime paths.
```
