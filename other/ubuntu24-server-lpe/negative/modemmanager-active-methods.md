# Negative: ModemManager active-user methods

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server Docker target.

Result: no root proof. The probe did not create
`/root/modemmanager_active_methods_root`, and cleanup left no ModemManager
process or probe temp directory behind.

Evidence: `logs/modemmanager-active-methods.out`

## Findings

ModemManager is installed (`modemmanager 1.23.4-0ubuntu2`) and its D-Bus name is
activatable, but in this Docker target the stock unit is condition-gated:

```text
LoadState=loaded
ActiveState=inactive
UnitFileState=enabled
ConditionResult=no
default_introspect_rc=124
inactive
```

The policy file does expose several active-user grants:

```text
org.freedesktop.ModemManager1.Device.Control inactive=no active=yes
org.freedesktop.ModemManager1.Contacts       inactive=no active=yes
org.freedesktop.ModemManager1.Messaging      inactive=no active=yes
org.freedesktop.ModemManager1.Voice          inactive=no active=yes
org.freedesktop.ModemManager1.Time           inactive=no active=yes
org.freedesktop.ModemManager1.Location       inactive=no active=yes
org.freedesktop.ModemManager1.USSD           inactive=no active=yes
```

A real active local TTY session confirmed those grants for `selfauth`, while
manager control stayed admin-gated:

```text
TTY=tty6
Active=yes
org.freedesktop.ModemManager1.Device.Control rc=0
org.freedesktop.ModemManager1.Messaging      rc=0
org.freedesktop.ModemManager1.Control        challenge needed / rc=2
org.freedesktop.ModemManager1.Firmware       challenge needed / rc=2
```

Because the container unit cannot auto-start, the probe started a bounded manual
daemon only to test semantics that would require a running root ModemManager.
With no hardware, only the manager object existed:

```text
/
/org
/org/freedesktop
/org/freedesktop/ModemManager1
No modems were found
```

The unprivileged object-creation path is blocked before ModemManager consumes
attacker-controlled device names. `ReportKernelEvent` has no non-root D-Bus
allow rule:

```text
ReportKernelEvent allow rule count:
0
```

Active `selfauth` attempts to report both an existing serial tty and an
attacker-created PTY were rejected by the bus:

```text
attacker_pty=/dev/pts/1
report_ttyS0_rc=1
GDBus.Error:org.freedesktop.DBus.Error.AccessDenied
report_pty_rc=1
GDBus.Error:org.freedesktop.DBus.Error.AccessDenied
```

The daemon's own scan also filtered the default serial/virtual surfaces instead
of creating modem objects:

```text
[filter] (tty/ttyS0): port filtered: tty platform driver
[filter] (tty/ptmx) port filtered: virtual device
[filter] (tty/tty6) port filtered: virtual device
```

Root-consumed ModemManager script/config locations were not writable by the
normal user. The `777` entries in the log are symlinks; their target scripts and
directories were not writable:

```text
not_writable /etc/ModemManager/fcc-unlock.d
not_writable /usr/share/ModemManager/fcc-unlock.available.d
not_writable /usr/share/ModemManager/fcc-unlock.available.d/105b
not_writable /usr/share/ModemManager/connection.available.d/99-log-event
not_writable /usr/lib/aarch64-linux-gnu/ModemManager/connection.d
```

## Conclusion

No stock default local LPE was proven. The active-user policy grants are real
but apply to modem-object methods; without hardware they expose no object, and
the D-Bus config blocks unprivileged `ReportKernelEvent` object creation. The
remaining manager methods that could rescan or alter daemon logging are
`Control`-gated, and no writable root-executed ModemManager path was reachable
from the normal non-sudo user.
