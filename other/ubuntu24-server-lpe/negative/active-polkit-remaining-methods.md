# Negative: active polkit remaining methods

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server Docker target.

Result: no root proof. The captured run did not create `/root/active_polkit_remaining_root`.

Per operator stop request, no further probing was run after the captured
`logs/active-polkit-remaining.out` evidence. The active tty launcher reached
`openvt` but timed out before recording the per-method semantic sections:

```text
## launch active tty selfauth probe
openvt_rc=124
```

Root marker check from the captured run and the requested cleanup verification:

```text
marker_post:
ROOT_PROOF=no
ls: cannot access '/root/active_polkit_remaining_root': No such file or directory

## operator-requested cleanup verification
marker_check:
ls: cannot access '/root/active_polkit_remaining_root': No such file or directory
is-system-running:
running
failed-units:
```

## Default action state captured

No `auth_self` default polkit actions were present:

```text
[auth_self] none
```

Focused root-write/root-exec surfaces were admin-gated by default:

```text
org.freedesktop.systemd1.manage-units        any=auth_admin inactive=auth_admin active=auth_admin_keep
org.freedesktop.systemd1.manage-unit-files   any=auth_admin inactive=auth_admin active=auth_admin_keep
org.freedesktop.systemd1.set-environment     any=auth_admin inactive=auth_admin active=auth_admin_keep
org.freedesktop.systemd1.reload-daemon       any=auth_admin inactive=auth_admin active=auth_admin_keep
org.freedesktop.hostname1.set-static-hostname any=auth_admin_keep inactive=auth_admin_keep active=auth_admin_keep
org.freedesktop.hostname1.set-machine-info   any=auth_admin_keep inactive=auth_admin_keep active=auth_admin_keep
org.freedesktop.locale1.set-locale           any=auth_admin_keep inactive=auth_admin_keep active=auth_admin_keep
org.freedesktop.locale1.set-keyboard         any=auth_admin_keep inactive=auth_admin_keep active=auth_admin_keep
org.freedesktop.timedate1.set-time           any=auth_admin_keep inactive=auth_admin_keep active=auth_admin_keep
org.freedesktop.timedate1.set-timezone       any=auth_admin_keep inactive=auth_admin_keep active=auth_admin_keep
org.freedesktop.timedate1.set-ntp            any=auth_admin_keep inactive=auth_admin_keep active=auth_admin_keep
org.freedesktop.resolve1.set-dns-servers     any=auth_admin inactive=auth_admin active=auth_admin_keep
org.freedesktop.resolve1.set-domains         any=auth_admin inactive=auth_admin active=auth_admin_keep
org.freedesktop.resolve1.revert              any=auth_admin inactive=auth_admin active=auth_admin_keep
org.freedesktop.network1.reload              any=auth_admin inactive=auth_admin active=auth_admin_keep
org.freedesktop.network1.reconfigure         any=auth_admin inactive=auth_admin active=auth_admin_keep
com.ubuntu.softwareproperties.applychanges   any=auth_admin inactive=auth_admin active=auth_admin_keep
org.freedesktop.bolt.enroll                  any=auth_admin inactive=auth_admin active=auth_admin_keep
org.freedesktop.bolt.authorize               any=auth_admin inactive=auth_admin active=auth_admin_keep
org.freedesktop.bolt.manage                  any=auth_admin inactive=auth_admin active=auth_admin_keep
```

Remaining non-excluded `allow_active=yes` actions captured:

```text
com.ubuntu.update-notifier.pkexec.package-system-locked any=no inactive=yes active=yes
org.freedesktop.ModemManager1.Contacts                  inactive=no active=yes
org.freedesktop.ModemManager1.Device.Control            inactive=no active=yes
org.freedesktop.ModemManager1.Location                  inactive=no active=yes
org.freedesktop.ModemManager1.Messaging                 inactive=no active=yes
org.freedesktop.ModemManager1.Time                      inactive=no active=yes
org.freedesktop.ModemManager1.USSD                      inactive=no active=yes
org.freedesktop.ModemManager1.Voice                     inactive=no active=yes
org.freedesktop.fwupd.update-hotplug-trusted            any=auth_admin inactive=no active=yes
org.freedesktop.fwupd.update-internal-trusted           any=auth_admin inactive=no active=yes
```

PackageKit, UDisks, and login1 `allow_active=yes` basics were enumerated as
`excluded-basic` in the log and were not retested here.

## Default service state captured

Relevant package versions:

```text
systemd 255.4-1ubuntu8.15
polkitd 124-2ubuntu1.24.04.3
dbus 1.14.10-4ubuntu4.1
netplan.io 1.1.2-8ubuntu1~24.04.2
software-properties-common 0.99.49.4
update-notifier-common 3.192.68.2
modemmanager 1.23.4-0ubuntu2
bolt 0.9.7-1
fwupd 1.9.34-0ubuntu1~24.04.1
```

Default reachability:

```text
io.netplan.Netplan             root netplan-dbus active on system bus
com.ubuntu.SoftwareProperties  activatable
org.freedesktop.ModemManager1  activatable, ModemManager.service inactive, ConditionResult=no
org.freedesktop.bolt           activatable, bolt.service inactive, ConditionResult=no
org.freedesktop.fwupd          activatable, fwupd.service inactive, ConditionResult=no
org.freedesktop.resolve1       active via systemd-resolved.service
org.freedesktop.network1       activatable, systemd-networkd.service inactive, ConditionResult=no
```

Root-owned state hashes before and after were unchanged for `/etc/hostname`,
`/etc/locale.conf`, `/etc/default/keyboard`, `/etc/localtime`,
`/etc/systemd/resolved.conf`, and `/etc/systemd/timesyncd.conf`. No
`/etc/machine-info` appeared, `/etc/netplan` stayed root-owned with no files,
and `/etc/apt/sources.list.d/ubuntu.sources` remained the only captured apt
source file.

## Conclusion

No LPE was validated from the captured remaining-polkit evidence. The only
decisive proof artifact requested for this pass, `/root/active_polkit_remaining_root`,
does not exist after cleanup, and `systemctl is-system-running` reports
`running` with no failed units.
