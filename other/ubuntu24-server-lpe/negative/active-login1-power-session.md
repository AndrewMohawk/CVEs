# active-login1 power/session methods

Result: no validated root LPE. The active-local-seat `org.freedesktop.login1` power and reboot-target surface gives an active TTY user deliberate reboot/power scheduling authority, but the tested stock Ubuntu Server state did not expose root code execution, attacker-controlled root file writes, or privileged account/group access.

## Target proof

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, rebuilt from the same image after the first shutdown-scheduling probe stopped the container.

Package versions from the live target:

```text
ubuntu-minimal	1.539.2
ubuntu-standard	1.539.2
ubuntu-server	1.539.2
dbus	1.14.10-4ubuntu4.1
polkitd	124-2ubuntu1.24.04.3
systemd	255.4-1ubuntu8.15
systemd-sysv	255.4-1ubuntu8.15
libpam-systemd:arm64	255.4-1ubuntu8.15
```

Active non-admin TTY proof from `logs/active-login1-safe-probe.out`:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
/dev/tty1
Seat=seat0
TTY=tty1
Remote=no
Type=tty
Class=user
Active=yes
State=active
```

`attacker` and `selfauth` are normal non-sudo users. `selfauth` exists only to model active local polkit semantics; it is not in `sudo`, `adm`, `lxd`, `docker`, or other privileged groups.

## Default reachability

`systemd-logind.service` is default-enabled by systemd and owns `org.freedesktop.login1`. The system bus configuration permits ordinary clients to send the relevant methods to logind:

```text
/usr/share/dbus-1/system.d/org.freedesktop.login1.conf
129-143  PowerOff/Reboot methods allowed to org.freedesktop.login1.Manager
213-219  ScheduleShutdown and CancelScheduledShutdown allowed
221-255  Can/Set reboot target and SetWallMessage methods allowed
```

Polkit then gates the privileged effects:

```text
/usr/share/polkit-1/actions/org.freedesktop.login1.policy
168-176  power-off allows active=yes and implies set-wall-message
201-209  reboot allows active=yes and implies set-wall-message
351-392  set-reboot-* actions allow active=yes and imply reboot
395-402  set-wall-message remains auth_admin_keep even for active users
```

The service hardening is also relevant: `/usr/lib/systemd/system/systemd-logind.service` runs `/usr/lib/systemd/systemd-logind` with `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, `ReadWritePaths=/etc /run`, and `RuntimeDirectory=systemd/... systemd/shutdown`.

## Trigger commands

Safe active-seat trigger used:

```sh
docker exec -i ubuntu24-server-lpe-target bash -s <<'EOS'
id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth
cat >/home/selfauth/.bash_profile <<'SH'
/home/selfauth/active-login1-safe-probe.sh
exit
SH
systemctl stop getty@tty1.service 2>/dev/null || true
timeout 45 openvt -c 1 -s -f -w -- /bin/login -f selfauth || true
busctl call --system org.freedesktop.login1 /org/freedesktop/login1 \
  org.freedesktop.login1.Manager CancelScheduledShutdown >/dev/null 2>&1 || true
systemctl start getty@tty1.service 2>/dev/null || true
loginctl terminate-user selfauth 2>/dev/null || true
EOS
```

Inside `active-login1-safe-probe.sh`, the key method calls were:

```sh
busctl call --system org.freedesktop.login1 /org/freedesktop/login1 \
  org.freedesktop.login1.Manager SetRebootParameter s ubulpe-param-1002
busctl call --system org.freedesktop.login1 /org/freedesktop/login1 \
  org.freedesktop.login1.Manager SetRebootToBootLoaderEntry s ubulpe-entry
busctl call --system org.freedesktop.login1 /org/freedesktop/login1 \
  org.freedesktop.login1.Manager SetRebootToBootLoaderMenu t 7
busctl call --system org.freedesktop.login1 /org/freedesktop/login1 \
  org.freedesktop.login1.Manager SetRebootToFirmwareSetup b true
busctl call --system org.freedesktop.login1 /org/freedesktop/login1 \
  org.freedesktop.login1.Manager SetWallMessage sb ubulpe-wall false
when_us=$(( ( $(date +%s) + 86400 ) * 1000000 ))
busctl call --system org.freedesktop.login1 /org/freedesktop/login1 \
  org.freedesktop.login1.Manager ScheduleShutdown st reboot "$when_us"
busctl call --system org.freedesktop.login1 /org/freedesktop/login1 \
  org.freedesktop.login1.Manager CancelScheduledShutdown
```

## Observed behavior

Active `selfauth` passes polkit for several power actions:

```text
org.freedesktop.login1.set-reboot-parameter rc=0
org.freedesktop.login1.set-reboot-to-boot-loader-entry rc=0
org.freedesktop.login1.set-reboot-to-boot-loader-menu rc=0
org.freedesktop.login1.set-reboot-to-firmware-setup rc=0
org.freedesktop.login1.reboot rc=0
org.freedesktop.login1.power-off rc=0
```

The useful-looking setters did not create a privilege boundary crossing:

```text
SetRebootParameter: Reboot parameter not supported in containers, refusing.
SetRebootToBootLoaderEntry: Boot loader entry 'ubulpe-entry' is not known.
SetRebootToBootLoaderMenu: Boot loader does not support boot into boot loader menu.
SetRebootToFirmwareSetup: Firmware does not support boot into firmware.
SetWallMessage call_rc:0
WallMessage property set: Access denied
```

`ScheduleShutdown` accepts a future absolute microsecond timestamp and `CancelScheduledShutdown` clears it:

```text
when_us=1779031258000000
ScheduledShutdown: (st) "reboot" 1779031258000000
b true
ScheduledShutdownAfterCancel: (st) "" 18446744073709551615
/run/systemd/shutdown is root:root 0755 with no attacker-created payload
```

An earlier probe mistakenly passed seconds instead of microseconds to `ScheduleShutdown`; logind treated the timestamp as already due and the container stopped. That is a local active-user shutdown/DoS capability already allowed by policy, not LPE.

## Cleanup

```sh
busctl call --system org.freedesktop.login1 /org/freedesktop/login1 \
  org.freedesktop.login1.Manager CancelScheduledShutdown >/dev/null 2>&1 || true
rm -f /home/selfauth/.bash_profile /home/selfauth/active-login1-safe-probe.sh
systemctl start getty@tty1.service 2>/dev/null || true
loginctl terminate-user selfauth 2>/dev/null || true
```

Final target state after cleanup:

```text
systemctl is-system-running: running
systemctl --failed: 0 loaded units listed
```

## Why scanners may miss the interesting primitive

Generic scanners usually see only that the D-Bus methods are callable and that polkit authorizes active users for reboot/power actions. The subtle part is the interaction between active seat state, implied `set-wall-message`, reboot-target setters, boot-loader/firmware support checks, and the absolute-microsecond `ScheduleShutdown` timestamp. That required a real active TTY session and stateful method sequencing, but it still ended below the privilege-escalation bar.

## Suggested triage conclusion

No Ubuntu Security LPE report from this candidate. If hardening is desired, documentation or client-side validation should emphasize that `ScheduleShutdown` takes an absolute microsecond timestamp, because accidentally passing seconds can request an immediate shutdown. That is not a local privilege escalation from the default active-user policy model.
