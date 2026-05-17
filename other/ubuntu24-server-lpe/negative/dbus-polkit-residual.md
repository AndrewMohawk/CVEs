# Negative: residual default D-Bus/polkit state-changing APIs

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server Docker target.

Artifacts:

```text
pocs/dbus_polkit_residual_probe.sh
logs/dbus-polkit-residual.out
```

Result: no uid1001/uid1002-to-root LPE was validated. The root proof marker
`/root/dbus_polkit_residual_root` stayed absent, root-owned config hashes were
unchanged, cleanup removed test linger/offline-update/loop state, and the target
finished with `systemctl is-system-running` reporting `running` and zero failed
units.

## Default reachability

The probe first proves package, unit, bus, action, and activation-file state.
Relevant installed packages included:

```text
dbus 1.14.10-4ubuntu4.1
fwupd 1.9.34-0ubuntu1~24.04.1
modemmanager 1.23.4-0ubuntu2
netplan.io 1.1.2-8ubuntu1~24.04.2
packagekit 1.2.8-2ubuntu1.5
packagekit-tools 1.2.8-2ubuntu1.5
polkitd 124-2ubuntu1.24.04.3
software-properties-common 0.99.49.4
systemd 255.4-1ubuntu8.15
systemd-resolved 255.4-1ubuntu8.15
systemd-timesyncd 255.4-1ubuntu8.15
udisks2 2.10.1-6ubuntu1.3
update-notifier-common 3.192.68.2
```

`accountsservice` is absent:

```text
dpkg-query: no packages found matching accountsservice
org.freedesktop.Accounts: The name org.freedesktop.Accounts was not provided by any .service files
accounts-daemon.service: LoadState=not-found
```

Default bus/service state:

```text
org.freedesktop.login1       active root systemd-logind.service
org.freedesktop.systemd1     active root PID1
org.freedesktop.resolve1     active systemd-resolved.service
org.freedesktop.UDisks2      active root udisks2.service
io.netplan.Netplan           active root netplan-dbus
com.ubuntu.SoftwareProperties active root Python service
org.freedesktop.PackageKit   activatable root packagekit.service
org.freedesktop.hostname1    activatable root systemd-hostnamed.service
org.freedesktop.locale1      activatable root systemd-localed.service
org.freedesktop.timedate1    activatable root systemd-timedated.service
org.freedesktop.network1     activatable but no dbus-org.freedesktop.network1.service alias in this target
org.freedesktop.timesync1    activatable but systemd-timesyncd is container-condition-gated
org.freedesktop.ModemManager1 activatable but condition-gated/no modem objects in this target
org.freedesktop.fwupd        activatable but container-condition-gated
org.freedesktop.bolt         activatable; no usable Thunderbolt domain/device path
```

The system bus activation directories and service/policy files are root-owned:

```text
drwxr-xr-x root:root /usr/share/dbus-1/system-services
drwxr-xr-x root:root /usr/share/dbus-1/system.d
drwxr-xr-x root:root /etc/dbus-1/system.d
644 root:root /usr/share/dbus-1/system-services/org.freedesktop.PackageKit.service
644 root:root /usr/share/dbus-1/system-services/org.freedesktop.UDisks2.service
644 root:root /usr/share/dbus-1/system-services/org.freedesktop.hostname1.service
```

`pkexec` is not installed, despite the update-notifier policy/action file being
present.

## Normal uid1001 attacker

The residual `any=yes` actions were real but bounded:

```text
org.freedesktop.login1.set-self-linger      pkcheck rc=0
org.freedesktop.login1.inhibit-delay-*      pkcheck rc=0
org.freedesktop.login1.inhibit-block-idle   pkcheck rc=0
```

`SetUserLinger(1001,true,false)` created only the fixed root-owned marker
`/var/lib/systemd/linger/attacker`; `SetUserLinger(0,true,false)` was denied.
The successful `Inhibit("shutdown", ..., "delay")` returned only an fd.

Admin/root mutators stayed blocked:

```text
systemd-run root marker: Interactive authentication required
org.freedesktop.systemd1.Manager.SetEnvironment: Access denied
org.freedesktop.DBus.UpdateActivationEnvironment: Access denied
hostnamed SetStaticHostname: Interactive authentication required
localed SetLocale: Interactive authentication required
resolved SetLinkDNS: Interactive authentication required
network1 Reload: Unit dbus-org.freedesktop.network1.service not found
netplan Config: Access denied
SoftwareProperties AddSourceFromLine: com.ubuntu.softwareproperties.applychanges
UDisks loop-setup from no-seat attacker: NotAuthorizedCanObtain
PackageKit refresh from no-seat attacker: Failed to obtain authentication
```

`timedated SetTimezone("Etc/UTC", false)` returned success only because it was a
current-state no-op. `/etc/localtime` hash and all other root-owned state hashes
matched before and after; this is not counted as a root write primitive.

## Active selfauth

The active-user path used a real tty login:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
/dev/tty2
Seat=seat0
TTY=tty2
Active=yes
State=active
```

Active `pkcheck` succeeded where policy says `active=yes`:

```text
com.ubuntu.update-notifier.pkexec.package-system-locked rc=0
org.freedesktop.login1.reboot rc=0
org.freedesktop.packagekit.system-sources-refresh rc=0
org.freedesktop.packagekit.system-network-proxy-configure rc=0
org.freedesktop.packagekit.trigger-offline-update rc=0
org.freedesktop.udisks2.loop-setup rc=0
org.freedesktop.udisks2.filesystem-mount rc=0
org.freedesktop.fwupd.update-internal-trusted rc=0
org.freedesktop.ModemManager1.Device.Control rc=0
```

The same active user still failed admin-gated mutators:

```text
org.freedesktop.systemd1.manage-units rc=2
org.freedesktop.hostname1.set-static-hostname rc=2
hostnamed SetStaticHostname: Interactive authentication required
resolved SetLinkDomains: Interactive authentication required
systemd transient root marker: timed out waiting on auth; marker absent
```

Successful active state changes stayed non-exploitable:

```text
loginctl enable-linger selfauth -> /var/lib/systemd/linger/selfauth, fixed path, removed
login1 CanReboot -> "yes", query only; no reboot was invoked
pkcon refresh force -> completed root PackageKit cache refresh, no package/source execution
PackageKit SetProxy with newline strings -> accepted as proxy values, no root file/marker
udisksctl loop-setup -> /dev/loop0, then loop-delete cleanup
```

The update-notifier helper was directly callable, but only as `selfauth`.
Placing a fake `fuser` first in `PATH` proved the unqualified helper lookup does
not become root in the default Server target because `pkexec` is absent:

```text
/tmp/dbus-polkit-residual/bin/fuser: cannot create /root/dbus_polkit_residual_root: Permission denied
```

`fwupdmgr` and ModemManager activation attempts were bounded by container/service
conditions and object absence. Bolt introspection was reachable, but no
state-changing root path was reached and the relevant manage/enroll actions are
admin-gated.

## Cleanup

Cleanup removed:

```text
/tmp/dbus-polkit-residual*
/home/selfauth/.bash_profile
/home/selfauth/dbus-polkit-residual-active.sh
/system-update
/var/lib/PackageKit/offline-update-action
/var/lib/PackageKit/prepared-update
/var/lib/systemd/linger/attacker
/var/lib/systemd/linger/selfauth
```

It also terminated the active `selfauth` session, restarted PackageKit to clear
transient proxy state, stopped condition-gated services started by activation,
reset failed units, and verified no root marker existed.

## Why scanners miss it

The interesting boundary is not just method reachability. A scanner can flag
root-owned D-Bus services, `active=yes` polkit actions, fixed root file writes
like logind linger, root PackageKit refresh, UDisks loop setup, and
update-notifier's unqualified `fuser` call. Exploitability depends on live
polkit subject state, whether the caller has an active `seat0` tty, whether the
service is actually default-active or condition-gated, whether `pkexec` exists,
and whether the root write path accepts attacker-controlled path/content. In this
target those checks reduce to fixed files, query-only actions, admin-gated
mutators, condition-gated services, or root daemons treating attacker input as
data rather than code.

## Conclusion

Negative. The remaining default-installed/default-reachable D-Bus and polkit
state-changing APIs did not provide a normal non-sudo uid1001/uid1002 user with
attacker-controlled root file write or root code execution in this target.
