# Negative: misc default daemons and helpers

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS, systemd PID 1.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no validated local privilege escalation in this misc daemon/helper slice. The tested packages are default-installed, but the exploitable-looking paths were either not default-reachable in the live target, condition/hardware-gated, executed as an unprivileged service account, or rooted in configuration/state paths not writable by uid 1001.

## Package proof

From the live target:

```text
open-vm-tools                 2:13.0.0-2~ubuntu0.24.04.1
pollinate                     4.33-3.1ubuntu1.3
networkd-dispatcher           2.2.4-1
landscape-common              24.02-0ubuntu5.7
command-not-found             23.04.0
update-manager-core           1:24.04.12
ubuntu-release-upgrader-core  1:24.04.28
byobu                         6.11-0ubuntu1
screen                        4.9.1-1ubuntu1
rsyslog                       8.2312.0-3ubuntu9.2
sysstat                       12.6.1-2
bolt                          0.9.7-1
modemmanager                  1.23.4-0ubuntu2
```

Baseline metapackages:

```text
ubuntu-minimal   1.539.2
ubuntu-server    1.539.2
ubuntu-standard  1.539.2
```

## Reachability and path ownership

Default unit state:

```text
open-vm-tools.service        enabled inactive ConditionResult=no
vgauth.service               enabled inactive ConditionResult=no
pollinate.service            enabled inactive ConditionResult=no
networkd-dispatcher.service  enabled inactive ConditionResult=no
rsyslog.service              enabled active
sysstat.service              enabled active/exited
sysstat-collect.timer        enabled active
sysstat-summary.timer        enabled active
bolt.service                 static, D-Bus activatable
ModemManager.service         enabled inactive ConditionResult=no
motd-news.timer              enabled active
update-notifier-motd.timer   enabled active
```

Relevant write boundaries:

```text
drwxr-xr-x root:root       /etc/vmware-tools
drwxr-xr-x root:root       /etc/vmware-tools/scripts
drwxr-xr-x root:root       /etc/networkd-dispatcher
drwxr-xr-x root:root       /usr/lib/networkd-dispatcher
drwxr-x--- pollinate:daemon /var/cache/pollinate
drwxr-xr-x landscape:landscape /var/lib/landscape
drwxr-xr-x root:root       /var/lib/command-not-found
drwxr-xr-x root:root       /var/lib/ubuntu-release-upgrader
drwxrwxrwt root:utmp       /run/screen
drwxrwxr-x root:syslog     /var/log
drwxr-xr-x root:root       /var/log/sysstat
drwxr-xr-x root:root       /var/lib/boltd
drwxr-xr-x root:root       /etc/ModemManager
```

An attacker-writable scan over the tested package file lists returned no package-owned writable files or directories for uid 1001.

## open-vm-tools / VGAuth

Default units:

```text
/usr/lib/systemd/system/open-vm-tools.service
ConditionVirtualization=vmware
ExecStart=/usr/bin/vmtoolsd

/usr/lib/systemd/system/vgauth.service
ConditionVirtualization=vmware
ExecStart=/usr/bin/VGAuthService
```

Live target proof:

```sh
runuser -u attacker -- vmware-checkvm
# Error: vmware-checkvm must be run inside a virtual machine on a VMware hypervisor product.

runuser -u attacker -- vmware-rpctool 'info-get guestinfo.test'
# Error: vmware-rpctool must be run inside a virtual machine on a VMware hypervisor product.

runuser -u attacker -- vmware-toolbox-cmd config set logging network.data /home/attacker/vmtools.log
# vmware-toolbox-cmd must be run inside a virtual machine.
```

The interesting script shape is real but not reachable here. `/etc/vmware-tools/power*-vm-default` and `resume/suspend` run hooks from `/etc/vmware-tools/scripts/${powerOp}-default.d` as part of VMware state changes, and `/etc/vmware-tools/scripts/vmware/network` reads `vmware-toolbox-cmd config get logging network.*` before touching/chmodding a log path. However, all shipped VMware script/config directories are root-owned, the services are inactive because `ConditionVirtualization=vmware` is false in the live target, and the local config tool refuses to operate outside VMware. No uid 1001 trigger reached root execution or a root file write.

Unresolved edge: a real VMware guest retest would be useful specifically for whether uid 1001 can influence global `vmware-toolbox-cmd config` consumed by root state-change scripts. That precondition was not default-reachable in this target.

## networkd-dispatcher

Default unit:

```text
/usr/lib/systemd/system/networkd-dispatcher.service
ConditionPathExistsGlob=|/etc/networkd-dispatcher/*/*
ConditionPathExistsGlob=|/usr/lib/networkd-dispatcher/*/*
ExecStart=/usr/bin/networkd-dispatcher $networkd_dispatcher_args
EnvironmentFile=-/etc/default/%p
```

The script directories exist but are empty and root-owned, so the unit condition is false in default state:

```text
drwxr-xr-x root:root /etc/networkd-dispatcher/{carrier,degraded,dormant,no-carrier,off,routable}.d
drwxr-xr-x root:root /usr/lib/networkd-dispatcher/{carrier,degraded,dormant,no-carrier,off,routable}.d
```

Code evidence in `/usr/bin/networkd-dispatcher`:

```text
185-224 scripts_in_path() enumerates hook names and requires parent dir mode 0755 uid 0 gid 0 plus target file mode 0755 uid 0 gid 0.
356-388 run_hooks_for_state() builds environment variables from network state and executes each hook with subprocess.Popen(script, env=script_env), not a shell.
488-492 --script-dir defaults to /etc/networkd-dispatcher:/usr/lib/networkd-dispatcher.
```

Dead end: uid 1001 cannot place a hook in either script tree, the daemon is not running by default because no hooks exist, and state variables are passed as environment to root-owned scripts only. No root code path is attacker-controlled.

## pollinate

Default unit and state:

```text
/usr/lib/systemd/system/pollinate.service
ConditionVirtualization=!container
ConditionPathExists=!/var/cache/pollinate/seeded
User=pollinate
ExecStart=/usr/bin/pollinate
CacheDirectory=pollinate
CacheDirectoryMode=0750

/var/cache/pollinate  drwxr-x--- pollinate:daemon
/etc/default/pollinate -rw-r--r-- root:root
```

Dead end: even when reachable on a non-container boot, the service runs as `pollinate`, not root. The writable cache is `pollinate:daemon`, and uid 1001 is not in `daemon`. The configured entropy device is `/dev/urandom`; no root-owned helper execution or attacker-writable config path was found.

## MOTD, release-upgrader, update-manager, command-not-found

Root timers are enabled for MOTD/release metadata:

```text
motd-news.timer active
update-notifier-motd.timer active
update-notifier-download.timer active
```

Relevant fixed paths are root-owned or service-owned:

```text
/etc/update-motd.d/*                         root:root 0755
/usr/lib/update-notifier/*                   root:root 0755
/usr/lib/ubuntu-release-upgrader/*           root:root 0755
/var/lib/landscape                           landscape:landscape 0755
/var/lib/update-notifier                     root:root 0755
/var/lib/ubuntu-release-upgrader             root:root 0755
/var/lib/command-not-found                   root:root 0755
```

Checked edges:

```text
/etc/update-motd.d/50-landscape-sysinfo writes /var/lib/landscape/landscape-sysinfo.cache, but uid 1001 cannot replace that path.
/usr/lib/ubuntu-release-upgrader/release-upgrade-motd writes /var/lib/ubuntu-release-upgrader/release-upgrade-available, not attacker-writable.
/etc/apt/apt.conf.d/50command-not-found runs /usr/lib/cnf-update-db after root apt updates; uid 1001 has no default root apt trigger and cannot write /var/lib/command-not-found.
```

The `com.ubuntu.update-notifier.pkexec.package-system-locked` policy exists and allows inactive/active callers, but this stock server image does not install `/usr/bin/pkexec`:

```sh
runuser -u attacker -- sh -lc 'PATH=/tmp/miscpath:/usr/bin:/bin pkexec /usr/lib/update-notifier/package-system-locked'
# sh: 1: pkexec: not found
```

Dead end: the MOTD/update paths are default-installed and some are timer-driven as root, but uid 1001 cannot write the scripts, stamps, config, or package metadata consumed by those helpers. The `pkexec` action is not reachable because `pkexec` is absent.

## byobu and screen

Runtime/config state:

```text
/usr/bin/screen             -rwxr-xr-x root:root
/run/screen                 drwxrwxrwt root:utmp
/etc/screenrc               -rw-r--r-- root:root
/etc/byobu                  drwxr-xr-x root:root
/etc/byobu/socketdir        -rw-r--r-- root:root, SOCKETDIR="/var/run/screen"
/etc/profile.d/Z97-byobu.sh -rw-r--r-- root:root
```

Attacker test:

```sh
runuser -u attacker -- screen -dmS miscprobe sh -c 'id > /tmp/misc_screen_id; sleep 1'
cat /tmp/misc_screen_id
# uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)

find /run/screen -maxdepth 2 -name S-attacker -printf '%M %u:%g %p\n'
# drwx------ attacker:attacker /run/screen/S-attacker
```

Dead end: `/run/screen` is sticky-world-writable, but `screen` is not setuid/setgid in this target and creates per-user socket directories mode 0700 owned by the caller. Byobu delegates to the user shell/session and has no default root daemon or root timer.

## rsyslog

Default service/config:

```text
/usr/lib/systemd/system/rsyslog.service
ExecStartPre=/usr/lib/rsyslog/reload-apparmor-profile
ExecStart=/usr/sbin/rsyslogd -n -iNONE
NoNewPrivileges=yes

/etc/rsyslog.conf
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$PrivDropToUser syslog
$PrivDropToGroup syslog
$IncludeConfig /etc/rsyslog.d/*.conf
```

State:

```text
/etc/rsyslog.conf       root:root 0644
/etc/rsyslog.d          root:root 0755
/var/log                root:syslog 0775
/var/log/syslog         syslog:adm 0640
attacker groups         attacker only
```

Dead end: uid 1001 can send log messages through `/dev/log`, but log content is not interpreted as commands. Rsyslog drops to `syslog:syslog` after startup and its config/logrotate snippets are root-owned. The attacker is not in `syslog` or `adm`, so group-writable `/var/log` is not a pivot.

## sysstat

Default service/timers:

```text
/usr/lib/systemd/system/sysstat.service          User=root ExecStart=/usr/lib/sysstat/sa1 --boot
/usr/lib/systemd/system/sysstat-collect.service  User=root ExecStart=/usr/lib/sysstat/sa1 1 1
/usr/lib/systemd/system/sysstat-summary.service  User=root ExecStart=/usr/lib/sysstat/sa2 -A
```

Code/config boundaries:

```text
/usr/lib/sysstat/sa1 lines 62-79 set SA_DIR=/var/log/sysstat, source /etc/sysstat/sysstat, and fall back to /var/log/sysstat unless SA_DIR exists.
/usr/lib/sysstat/sa2 lines 127-180 source /etc/sysstat/sysstat and write reports under SA_DIR.
/etc/sysstat/sysstat       root:root 0644
/var/log/sysstat           root:root 0755
/var/log/sysstat/sa16      root:root 0644
```

Dead end: the root timers do run, but the only configuration path and output directory are root-owned. uid 1001 cannot replace `SA_DIR`, `ZIP`, `ENDIR`, or the report files consumed by `sa1`/`sa2`.

## bolt and ModemManager

`bolt` is D-Bus activatable and did start as root when probed by uid 1001:

```text
org.freedesktop.bolt  boltd root bolt.service
```

But the policy requires admin auth for state-changing operations:

```text
org.freedesktop.bolt.enroll     allow_any=auth_admin allow_inactive=auth_admin allow_active=auth_admin_keep
org.freedesktop.bolt.authorize  allow_any=auth_admin allow_inactive=auth_admin allow_active=auth_admin_keep
org.freedesktop.bolt.manage     allow_any=auth_admin allow_inactive=auth_admin allow_active=auth_admin_keep
```

The service is sandboxed and only writes `/var/lib/boltd`, which is root-owned:

```text
ReadWritePaths=/var/lib/boltd
StateDirectory=boltd
CapabilityBoundingSet=CAP_NET_ADMIN
/var/lib/boltd drwxr-xr-x root:root
```

`ModemManager.service` is default-installed/enabled but not active in the live container:

```text
ConditionVirtualization=!container
ExecStart=/usr/sbin/ModemManager
User=root
```

Attacker probes:

```sh
runuser -u attacker -- mmcli -L
# error: couldn't find the ModemManager process in the bus

runuser -u attacker -- mmcli -m 0
# error: couldn't find the ModemManager process in the bus
```

Dead end: bolt has an activatable root daemon, but mutators are admin-gated and no Thunderbolt device path exists. ModemManager is condition/hardware-gated in this target; its non-admin policies apply to modem objects, and no modem object exists without hardware.

## Cleanup

Probe cleanup performed:

```sh
rm -f /tmp/misc_pkexec_fuser_id /tmp/misc_pkexec_env /tmp/misc_screen_id
rm -rf /tmp/miscpath
runuser -u attacker -- sh -lc 'rm -rf /home/attacker/.screen /home/attacker/.byobu /home/attacker/vmtools.log; screen -wipe >/dev/null 2>&1 || true'
systemctl stop bolt.service packagekit.service
systemctl reset-failed bolt.service packagekit.service ModemManager.service networkd-dispatcher.service open-vm-tools.service vgauth.service pollinate.service
```

Post-cleanup:

```text
bolt.service       inactive dead
packagekit.service inactive dead
ModemManager.service inactive dead
```

## Conclusion

No `notes/misc_*.md` or `pocs/misc_*` artifact was created because no root privilege increase was validated. The most useful follow-up is a VMware-backed stock Ubuntu Server retest of the `open-vm-tools` state-change logging path, but in this live stock target the VMware condition and config tool block local reachability before exploit development.
