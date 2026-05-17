# Negative audit: secureboot-db, snapd autoimport/repair/recovery, offline update one-shots

Target: `ubuntu24-server-lpe-target` (`ubuntu24-server-default-lpe:20260516-standard`)

Result: no uid1001 -> root LPE was found in the default state. The audited units are either condition-gated out on this stock Ubuntu 24.04 Server Docker target, require authenticated systemd/PolicyKit actions, or consume root-owned/non-writable seed/update paths. No `notes/<finding>.md` or `pocs/<finding>.sh` was written.

## Package/default install state

Command:

```sh
docker ps --filter name=ubuntu24-server-lpe-target --format '{{.Names}} {{.Image}} {{.Status}}'
```

Result:

```text
ubuntu24-server-lpe-target ubuntu24-server-default-lpe:20260516-standard Up 3 hours
```

Command:

```sh
docker exec ubuntu24-server-lpe-target ps -p 1 -o pid,comm,args
```

Result:

```text
    PID COMMAND         COMMAND
      1 systemd         /sbin/init
```

Command:

```sh
docker exec ubuntu24-server-lpe-target getent passwd 1001
```

Result:

```text
attacker:x:1001:1001::/home/attacker:/bin/bash
```

Command:

```sh
docker exec ubuntu24-server-lpe-target dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' ubuntu-minimal ubuntu-server ubuntu-server-minimal ubuntu-standard
```

Result:

```text
ubuntu-minimal	1.539.2	ii 
ubuntu-server	1.539.2	ii 
ubuntu-standard	1.539.2	ii 
dpkg-query: no packages found matching ubuntu-server-minimal
```

Command:

```sh
docker exec ubuntu24-server-lpe-target dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' secureboot-db snapd shim-signed grub-efi-amd64-signed fwupd update-manager-core ubuntu-release-upgrader-core unattended-upgrades cloud-init
```

Result:

```text
dpkg-query: no packages found matching shim-signed
dpkg-query: no packages found matching grub-efi-amd64-signed
cloud-init		un 
fwupd	1.9.34-0ubuntu1~24.04.1	ii 
secureboot-db	1.9build1	ii 
snapd	2.74.1+ubuntu24.04.4	ii 
ubuntu-release-upgrader-core	1:24.04.28	ii 
unattended-upgrades	2.9.1+nmu4ubuntu1	ii 
update-manager-core	1:24.04.12	ii 
```

Command:

```sh
docker exec ubuntu24-server-lpe-target apt-cache policy secureboot-db snapd fwupd update-manager-core ubuntu-release-upgrader-core unattended-upgrades
```

Result:

```text
secureboot-db:
  Installed: 1.9build1
  Candidate: 1.9build1
  Version table:
 *** 1.9build1 500
        500 http://ports.ubuntu.com/ubuntu-ports noble/main arm64 Packages
        100 /var/lib/dpkg/status
snapd:
  Installed: 2.74.1+ubuntu24.04.4
  Candidate: 2.74.1+ubuntu24.04.4
  Version table:
 *** 2.74.1+ubuntu24.04.4 500
        500 http://ports.ubuntu.com/ubuntu-ports noble-updates/main arm64 Packages
        100 /var/lib/dpkg/status
     2.73+ubuntu24.04.2 500
        500 http://ports.ubuntu.com/ubuntu-ports noble-security/main arm64 Packages
     2.62+24.04build1 500
        500 http://ports.ubuntu.com/ubuntu-ports noble/main arm64 Packages
fwupd:
  Installed: 1.9.34-0ubuntu1~24.04.1
  Candidate: 1.9.34-0ubuntu1~24.04.1
  Version table:
 *** 1.9.34-0ubuntu1~24.04.1 500
        500 http://ports.ubuntu.com/ubuntu-ports noble-updates/main arm64 Packages
        100 /var/lib/dpkg/status
     1.9.16-1 500
        500 http://ports.ubuntu.com/ubuntu-ports noble/main arm64 Packages
update-manager-core:
  Installed: 1:24.04.12
  Candidate: 1:24.04.12
  Version table:
 *** 1:24.04.12 500
        500 http://ports.ubuntu.com/ubuntu-ports noble-updates/main arm64 Packages
        100 /var/lib/dpkg/status
     1:24.04.6 500
        500 http://ports.ubuntu.com/ubuntu-ports noble/main arm64 Packages
ubuntu-release-upgrader-core:
  Installed: 1:24.04.28
  Candidate: 1:24.04.28
  Version table:
 *** 1:24.04.28 500
        500 http://ports.ubuntu.com/ubuntu-ports noble-updates/main arm64 Packages
        100 /var/lib/dpkg/status
     1:24.04.16 500
        500 http://ports.ubuntu.com/ubuntu-ports noble/main arm64 Packages
unattended-upgrades:
  Installed: 2.9.1+nmu4ubuntu1
  Candidate: 2.9.1+nmu4ubuntu1
  Version table:
 *** 2.9.1+nmu4ubuntu1 500
        500 http://ports.ubuntu.com/ubuntu-ports noble/main arm64 Packages
        100 /var/lib/dpkg/status
```

Command:

```sh
docker exec ubuntu24-server-lpe-target snap version
```

Result:

```text
snap          2.74.1+ubuntu24.04.4
snapd         2.74.1+ubuntu24.04.4
series        16
ubuntu        24.04
kernel        6.10.14-linuxkit
architecture  arm64
```

## Unit install/enabled/running/condition state

Command:

```sh
docker exec ubuntu24-server-lpe-target systemctl list-unit-files 'secureboot-db.service' 'snapd*.service' 'snapd*.timer' 'fwupd*.service' 'apt-daily*.service' 'ubuntu-advantage*.service' --no-pager
```

Result:

```text
UNIT FILE                              STATE   PRESET
apt-daily-upgrade.service              static  -
apt-daily.service                      static  -
fwupd-offline-update.service           static  -
fwupd-refresh.service                  static  -
fwupd.service                          static  -
secureboot-db.service                  enabled enabled
snapd.apparmor.service                 enabled enabled
snapd.autoimport.service               enabled enabled
snapd.core-fixup.service               enabled enabled
snapd.failure.service                  static  -
snapd.recovery-chooser-trigger.service enabled enabled
snapd.seeded.service                   enabled enabled
snapd.service                          enabled enabled
snapd.snap-repair.service              static  -
snapd.system-shutdown.service          enabled enabled
ubuntu-advantage.service               enabled enabled
snapd.snap-repair.timer                enabled enabled

17 unit files listed.
```

Command:

```sh
docker exec ubuntu24-server-lpe-target systemctl list-units 'secureboot-db.service' 'snapd*.service' 'fwupd*.service' 'apt-daily*.service' 'ubuntu-advantage*.service' --all --no-pager
```

Result:

```text
  UNIT                                   LOAD      ACTIVE   SUB    DESCRIPTION
  apt-daily-upgrade.service              loaded    inactive dead   Daily apt upgrade and clean activities
  apt-daily.service                      loaded    inactive dead   Daily apt download activities
  fwupd-refresh.service                  loaded    inactive dead   Refresh fwupd metadata and update motd
  secureboot-db.service                  loaded    inactive dead   Secure Boot updates for DB and DBX
  snapd.apparmor.service                 loaded    inactive dead   Load AppArmor profiles managed internally by snapd
  snapd.autoimport.service               loaded    inactive dead   Auto import assertions from block devices
  snapd.core-fixup.service               loaded    inactive dead   Automatically repair incorrect owner/permissions on core devices
  snapd.failure.service                  loaded    inactive dead   Failure handling of the snapd snap
  snapd.recovery-chooser-trigger.service loaded    inactive dead   Wait for the Ubuntu Core chooser trigger
  snapd.seeded.service                   loaded    active   exited Wait until snapd is fully seeded
  snapd.service                          loaded    inactive dead   Snap Daemon
  snapd.snap-repair.service              loaded    inactive dead   Automatically fetch and run repair assertions
  snapd.system-shutdown.service          loaded    inactive dead   Ubuntu core (all-snaps) system shutdown helper setup service
● ubuntu-advantage-cloud-id-shim.service not-found inactive dead   ubuntu-advantage-cloud-id-shim.service
  ubuntu-advantage.service               loaded    inactive dead   Ubuntu Pro Background Auto Attach

Legend: LOAD   -> Reflects whether the unit definition was properly loaded.
        ACTIVE -> The high-level unit activation state, i.e. generalization of SUB.
        SUB    -> The low-level unit activation state, values depend on unit type.

15 loaded units listed.
To show all installed unit files use 'systemctl list-unit-files'.
```

Command:

```sh
docker exec ubuntu24-server-lpe-target systemctl cat secureboot-db.service --no-pager
```

Result:

```text
# /usr/lib/systemd/system/secureboot-db.service
[Unit]
Description=Secure Boot updates for DB and DBX
ConditionPathExists=/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f

[Service]
Type=oneshot
ExecStartPre=-/usr/bin/chattr -i /sys/firmware/efi/efivars/KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c
ExecStartPre=-/usr/bin/chattr -i /sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f
ExecStartPre=-/usr/bin/chattr -i /sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f
ExecStart=/usr/bin/sbkeysync --no-default-keystores --keystore /usr/share/secureboot/updates --verbose
# This is expected to fail with some firmware, but that shouldn't cause
# this unit to fail. See LP: #1892797.
SuccessExitStatus=1

[Install]
WantedBy=multi-user.target
```

Command:

```sh
docker exec ubuntu24-server-lpe-target systemctl cat snapd.autoimport.service snapd.recovery-chooser-trigger.service snapd.snap-repair.service snapd.seeded.service --no-pager
```

Result:

```text
# /usr/lib/systemd/system/snapd.autoimport.service
[Unit]
Description=Auto import assertions from block devices
After=snapd.service snapd.socket snapd.seeded.service
# don't run on classic
ConditionKernelCommandLine=|snap_core
# TODO:UC20: only enable this in run mode?
ConditionKernelCommandLine=|snapd_recovery_mode

[Service]
Type=oneshot
ExecStart=/usr/bin/snap auto-import
EnvironmentFile=-/var/lib/snapd/environment/snapd.conf

[Install]
WantedBy=multi-user.target
# This cannot be started on firstboot
# X-Snapd-Snap: do-not-start

# /usr/lib/systemd/system/snapd.recovery-chooser-trigger.service
[Unit]
Description=Wait for the Ubuntu Core chooser trigger
Wants=getty-pre.target
Before=getty-pre.target
# don't run on classic or uc16/uc18
ConditionKernelCommandLine=snapd_recovery_mode
# only run when there are input devices
ConditionPathExistsGlob=/dev/input/event*

[Service]
# blocks the service startup until a trigger is detected or a timeout is hit
Type=oneshot
ExecStart=/usr/lib/snapd/snap-bootstrap recovery-chooser-trigger
RemainAfterExit=true

[Install]
WantedBy=multi-user.target

# started on boot only
# X-Snapd-Snap: do-not-start

# /usr/lib/systemd/system/snapd.snap-repair.service
[Unit]
Description=Automatically fetch and run repair assertions
Documentation=man:snap(1)
# don't run on classic
ConditionKernelCommandLine=|snap_core
ConditionKernelCommandLine=|snapd_recovery_mode

[Service]
Type=oneshot
ExecStart=/usr/lib/snapd/snap-repair run
EnvironmentFile=-/etc/environment
Environment=SNAP_REPAIR_FROM_TIMER=1
EnvironmentFile=-/var/lib/snapd/environment/snapd.conf
# There is no need to start this, the timer will run it
# X-Snapd-Snap: do-not-start

# /usr/lib/systemd/system/snapd.seeded.service
[Unit]
Description=Wait until snapd is fully seeded
After=snapd.socket
Requires=snapd.socket

[Service]
Type=oneshot
ExecStart=/usr/bin/snap wait system seed.loaded
RemainAfterExit=true

[Install]
WantedBy=multi-user.target cloud-final.service
# This is handled special in snapd
# X-Snapd-Snap: do-not-start
```

Command:

```sh
docker exec ubuntu24-server-lpe-target cat /proc/cmdline
```

Result:

```text
init=/init loglevel=1 root=/dev/vdb rootfstype=erofs ro vsyscall=emulate panic=0 eth0.dhcp eth1.dhcp linuxkit.unified_cgroup_hierarchy=1 console=hvc0   virtio_net.disable_csum=1 vpnkit.connect=connect://2/1999 com.docker.VMID=4fbac003-a656-4a95-bebf-3a971e6c6566
```

Command:

```sh
docker exec ubuntu24-server-lpe-target systemd-analyze condition 'ConditionPathExists=/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f'
```

Result:

```text
test.service: ConditionPathExists=/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f failed.
Conditions failed.
```

Command:

```sh
docker exec ubuntu24-server-lpe-target systemd-analyze condition 'ConditionKernelCommandLine=|snap_core' 'ConditionKernelCommandLine=|snapd_recovery_mode'
```

Result:

```text
test.service: ConditionKernelCommandLine=|snapd_recovery_mode failed.
test.service: ConditionKernelCommandLine=|snap_core failed.
Conditions failed.
```

Command:

```sh
docker exec ubuntu24-server-lpe-target systemctl status secureboot-db.service snapd.autoimport.service snapd.snap-repair.service --no-pager
```

Result:

```text
○ secureboot-db.service - Secure Boot updates for DB and DBX
     Loaded: loaded (/usr/lib/systemd/system/secureboot-db.service; enabled; preset: enabled)
     Active: inactive (dead)
  Condition: start condition unmet at Sat 2026-05-16 13:24:39 UTC; 21ms ago
             └─ ConditionPathExists=/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f was not met

May 16 10:23:55 fd448ecbc136 systemd[1]: secureboot-db.service - Secure Boot updates for DB and DBX was skipped because of an unmet condition check (ConditionPathExists=/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f).
May 16 13:24:39 fd448ecbc136 systemd[1]: secureboot-db.service - Secure Boot updates for DB and DBX was skipped because of an unmet condition check (ConditionPathExists=/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f).

○ snapd.autoimport.service - Auto import assertions from block devices
     Loaded: loaded (/usr/lib/systemd/system/snapd.autoimport.service; enabled; preset: enabled)
     Active: inactive (dead)
  Condition: start condition unmet at Sat 2026-05-16 13:24:39 UTC; 16ms ago
             ├─ ConditionKernelCommandLine=|snap_core was not met
             └─ ConditionKernelCommandLine=|snapd_recovery_mode was not met

May 16 10:23:56 fd448ecbc136 systemd[1]: snapd.autoimport.service - Auto import assertions from block devices was skipped because no trigger condition checks were met.
May 16 13:24:39 fd448ecbc136 systemd[1]: snapd.autoimport.service - Auto import assertions from block devices was skipped because no trigger condition checks were met.

○ snapd.snap-repair.service - Automatically fetch and run repair assertions
     Loaded: loaded (/usr/lib/systemd/system/snapd.snap-repair.service; static)
     Active: inactive (dead)
TriggeredBy: ○ snapd.snap-repair.timer
  Condition: start condition unmet at Sat 2026-05-16 13:24:39 UTC; 12ms ago
             ├─ ConditionKernelCommandLine=|snap_core was not met
             └─ ConditionKernelCommandLine=|snapd_recovery_mode was not met
       Docs: man:snap(1)

May 16 13:24:39 fd448ecbc136 systemd[1]: snapd.snap-repair.service - Automatically fetch and run repair assertions was skipped because no trigger condition checks were met.
```

Command:

```sh
docker exec ubuntu24-server-lpe-target systemctl status snapd.service snapd.socket snapd.seeded.service --no-pager
```

Result:

```text
○ snapd.service - Snap Daemon
     Loaded: loaded (/usr/lib/systemd/system/snapd.service; enabled; preset: enabled)
     Active: inactive (dead) since Sat 2026-05-16 13:17:33 UTC; 9min ago
   Duration: 8.032s
TriggeredBy: ● snapd.socket
    Process: 85635 ExecStart=/usr/lib/snapd/snapd (code=exited, status=42)
   Main PID: 85635 (code=exited, status=42)
        CPU: 71ms

May 16 13:17:25 fd448ecbc136 systemd[1]: Started snapd.service - Snap Daemon.
May 16 13:17:25 fd448ecbc136 snapd[85635]: snapmgr.go:1659: performing periodic snap downloads cache cleanup
May 16 13:17:25 fd448ecbc136 snapd[85635]: snapmgr.go:1669: cannot clean store downloads cache: open /var/lib/snapd/cache: no such file or directory
May 16 13:17:30 fd448ecbc136 snapd[85635]: standby.go:101: standby conditions met, initiating standby...
May 16 13:17:30 fd448ecbc136 snapd[85635]: daemon.go:556: gracefully waiting for running hooks
May 16 13:17:30 fd448ecbc136 snapd[85635]: daemon.go:558: done waiting for running hooks
May 16 13:17:33 fd448ecbc136 snapd[85635]: standby.go:121: standby monitoring stop requested
May 16 13:17:33 fd448ecbc136 snapd[85635]: overlord.go:543: Released state lock file
May 16 13:17:33 fd448ecbc136 snapd[85635]: daemon stop requested to wait for socket activation
May 16 13:17:33 fd448ecbc136 systemd[1]: snapd.service: Deactivated successfully.

● snapd.socket - Socket activation for snappy daemon
     Loaded: loaded (/usr/lib/systemd/system/snapd.socket; enabled; preset: enabled)
     Active: active (listening) since Sat 2026-05-16 10:23:54 UTC; 3h 2min ago
   Triggers: ● snapd.service
     Listen: /run/snapd.socket (Stream)
             /run/snapd-snap.socket (Stream)
      Tasks: 0 (limit: 9517)
     Memory: 0B (peak: 0B)
        CPU: 476us
     CGroup: /docker/fd448ecbc1369b3391fb69933b0f55af5a71ce4cbe66aa844e9905aebffa2ea1/system.slice/snapd.socket

May 16 10:23:54 fd448ecbc136 systemd[1]: Starting snapd.socket - Socket activation for snappy daemon...
May 16 10:23:54 fd448ecbc136 systemd[1]: Listening on snapd.socket - Socket activation for snappy daemon.

● snapd.seeded.service - Wait until snapd is fully seeded
     Loaded: loaded (/usr/lib/systemd/system/snapd.seeded.service; enabled; preset: enabled)
     Active: active (exited) since Sat 2026-05-16 10:23:56 UTC; 3h 2min ago
   Main PID: 261 (code=exited, status=0/SUCCESS)
        CPU: 81ms

May 16 10:23:55 fd448ecbc136 systemd[1]: Starting snapd.seeded.service - Wait until snapd is fully seeded...
May 16 10:23:56 fd448ecbc136 systemd[1]: Finished snapd.seeded.service - Wait until snapd is fully seeded.
```

## Related offline update one-shots

Command:

```sh
docker exec ubuntu24-server-lpe-target systemctl list-unit-files '*offline*' '*system-update*' '*repair*' '*secureboot*' '*autoimport*' --no-pager
```

Result:

```text
UNIT FILE                                    STATE    PRESET
fwupd-offline-update.service                 static   -
packagekit-offline-update.service            static   -
secureboot-db.service                        enabled  enabled
snapd.autoimport.service                     enabled  enabled
snapd.snap-repair.service                    static   -
system-update-cleanup.service                static   -
systemd-pcrlock-secureboot-authority.service disabled enabled
systemd-pcrlock-secureboot-policy.service    disabled enabled
system-update-pre.target                     static   -
system-update.target                         static   -
snapd.snap-repair.timer                      enabled  enabled

11 unit files listed.
```

Command:

```sh
docker exec ubuntu24-server-lpe-target systemctl cat fwupd-offline-update.service fwupd-refresh.service apt-daily.service apt-daily-upgrade.service --no-pager
```

Result:

```text
# /usr/lib/systemd/system/fwupd-offline-update.service
[Unit]
Description=Updates device firmware whilst offline
Documentation=man:fwupdmgr
ConditionPathExists=/var/lib/fwupd/pending.db
DefaultDependencies=false
Requires=sysinit.target dbus.socket
After=sysinit.target system-update-pre.target dbus.socket systemd-journald.socket
Before=shutdown.target system-update.target

[Service]
Type=oneshot
ExecStart=/usr/libexec/fwupd/fwupdoffline
FailureAction=reboot

# /usr/lib/systemd/system/fwupd-refresh.service
[Unit]
Description=Refresh fwupd metadata and update motd
Documentation=man:fwupdmgr(1)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
TimeoutStartSec=300
CacheDirectory=fwupdmgr
StandardError=null
ProtectSystem=strict
ProtectHome=read-only
User=fwupd-refresh
RestrictAddressFamilies=AF_NETLINK AF_UNIX AF_INET AF_INET6
SystemCallFilter=~@mount
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
SuccessExitStatus=2
ExecStart=/usr/bin/fwupdmgr refresh

# /usr/lib/systemd/system/apt-daily.service
[Unit]
Description=Daily apt download activities
Documentation=man:apt(8)
ConditionACPower=true
After=network.target network-online.target systemd-networkd.service NetworkManager.service connman.service

[Service]
Type=oneshot
ExecStartPre=-/usr/lib/apt/apt-helper wait-online
ExecStart=/usr/lib/apt/apt.systemd.daily update


# /usr/lib/systemd/system/apt-daily-upgrade.service
[Unit]
Description=Daily apt upgrade and clean activities
Documentation=man:apt(8)
ConditionACPower=true
After=apt-daily.service network.target network-online.target systemd-networkd.service NetworkManager.service connman.service

[Service]
Type=oneshot
ExecStartPre=-/usr/lib/apt/apt-helper wait-online
ExecStart=/usr/lib/apt/apt.systemd.daily install
KillMode=process
TimeoutStopSec=900
```

Command:

```sh
docker exec ubuntu24-server-lpe-target systemctl cat packagekit-offline-update.service system-update-cleanup.service --no-pager
```

Result:

```text
# /usr/lib/systemd/system/packagekit-offline-update.service
[Unit]
Description=Update the operating system whilst offline

DefaultDependencies=no
Requires=sysinit.target dbus.socket
After=sysinit.target dbus.socket systemd-journald.socket system-update-pre.target
Before=shutdown.target system-update.target
# See packagekit.service
ConditionPathExists=!/run/ostree-booted

[Service]
Type=oneshot
ExecStart=/usr/libexec/pk-offline-update

FailureAction=reboot

# /usr/lib/systemd/system/system-update-cleanup.service
#  SPDX-License-Identifier: LGPL-2.1-or-later
#
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

[Unit]
Description=Remove the Offline System Updates Symlink
Documentation=man:systemd.special(7) man:systemd.offline-updates(7)
After=system-update.target
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target
SuccessAction=reboot

# system-update-generator uses laccess("/system-update"), while a plain
# ConditionPathExists=/system-update uses access("/system-update"), so
# we need an alternate condition to cover the case of a dangling symlink.
#
# This service is only invoked if /system-update exists, i.e. if the
# condition tested by system-update-generator remains true and the system
# would be diverted into system-update.target again after reboot. This way
# we guard against being diverted into system-update.target again, which
# works as a safety measure, but we will not step on the toes of the
# update script if it successfully removed the symlink and scheduled a
# reboot or some other action on its own.
ConditionPathExists=|/system-update
ConditionPathIsSymbolicLink=|/system-update
ConditionPathExists=|/etc/system-update
ConditionPathIsSymbolicLink=|/etc/system-update

[Service]
Type=oneshot
ExecStart=rm -fv /system-update /etc/system-update
```

Command:

```sh
docker exec ubuntu24-server-lpe-target systemd-analyze condition 'ConditionPathExists=/var/lib/fwupd/pending.db' 'ConditionACPower=true'
```

Result:

```text
test.service: ConditionACPower=true succeeded.
test.service: ConditionPathExists=/var/lib/fwupd/pending.db failed.
Conditions failed.
```

Command:

```sh
docker exec ubuntu24-server-lpe-target systemctl cat fwupd.service --no-pager
```

Result:

```text
# /usr/lib/systemd/system/fwupd.service
[Unit]
Description=Firmware update daemon
Documentation=https://fwupd.org/
After=dbus.service
Before=display-manager.service
ConditionVirtualization=!container

[Service]
Type=dbus
TimeoutSec=180
RuntimeDirectory=motd.d
RuntimeDirectoryPreserve=yes
BusName=org.freedesktop.fwupd
ExecStart=/usr/libexec/fwupd/fwupd
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
SystemCallFilter=~@mount
Environment="GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK"
ProtectControlGroups=yes
ProtectKernelModules=yes
RestrictRealtime=yes
ReadWritePaths=-/boot/efi -/boot/EFI -/boot/grub -/efi/EFI -/sys/firmware/efi/efivars
ConfigurationDirectory=fwupd
StateDirectory=fwupd
CacheDirectory=fwupd
RestrictAddressFamilies=AF_NETLINK AF_UNIX AF_INET AF_INET6
```

Command:

```sh
docker exec ubuntu24-server-lpe-target systemctl status fwupd.service --no-pager
```

Result:

```text
○ fwupd.service - Firmware update daemon
     Loaded: loaded (/usr/lib/systemd/system/fwupd.service; static)
     Active: inactive (dead)
       Docs: https://fwupd.org/

May 16 11:05:18 fd448ecbc136 systemd[1]: fwupd.service - Firmware update daemon was skipped because of an unmet condition check (ConditionVirtualization=!container).
May 16 11:05:43 fd448ecbc136 systemd[1]: fwupd.service - Firmware update daemon was skipped because of an unmet condition check (ConditionVirtualization=!container).
May 16 11:19:31 fd448ecbc136 systemd[1]: fwupd.service - Firmware update daemon was skipped because of an unmet condition check (ConditionVirtualization=!container).
May 16 11:20:12 fd448ecbc136 systemd[1]: fwupd.service - Firmware update daemon was skipped because of an unmet condition check (ConditionVirtualization=!container).
May 16 11:20:52 fd448ecbc136 systemd[1]: fwupd.service - Firmware update daemon was skipped because of an unmet condition check (ConditionVirtualization=!container).
May 16 11:23:46 fd448ecbc136 systemd[1]: fwupd.service - Firmware update daemon was skipped because of an unmet condition check (ConditionVirtualization=!container).
May 16 12:02:18 fd448ecbc136 systemd[1]: fwupd.service - Firmware update daemon was skipped because of an unmet condition check (ConditionVirtualization=!container).
May 16 12:04:00 fd448ecbc136 systemd[1]: fwupd.service - Firmware update daemon was skipped because of an unmet condition check (ConditionVirtualization=!container).
May 16 12:07:32 fd448ecbc136 systemd[1]: fwupd.service - Firmware update daemon was skipped because of an unmet condition check (ConditionVirtualization=!container).
May 16 13:26:06 fd448ecbc136 systemd[1]: fwupd.service - Firmware update daemon was skipped because of an unmet condition check (ConditionVirtualization=!container).
```

## Root code/config paths and writeability

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc "stat -c '%A %a %U:%G %n' /usr/lib/systemd/system/secureboot-db.service /usr/lib/systemd/system/snapd.autoimport.service /usr/lib/systemd/system/snapd.recovery-chooser-trigger.service /usr/lib/systemd/system/snapd.snap-repair.service /usr/bin/sbkeysync /usr/bin/snap /usr/lib/snapd/snap-bootstrap /usr/lib/snapd/snap-repair /usr/libexec/fwupd/fwupdoffline /usr/bin/fwupdmgr /usr/lib/apt/apt.systemd.daily"
```

Result:

```text
-rw-r--r-- 644 root:root /usr/lib/systemd/system/secureboot-db.service
-rw-r--r-- 644 root:root /usr/lib/systemd/system/snapd.autoimport.service
-rw-r--r-- 644 root:root /usr/lib/systemd/system/snapd.recovery-chooser-trigger.service
-rw-r--r-- 644 root:root /usr/lib/systemd/system/snapd.snap-repair.service
-rwxr-xr-x 755 root:root /usr/bin/sbkeysync
-rwxr-xr-x 755 root:root /usr/bin/snap
-rwxr-xr-x 755 root:root /usr/lib/snapd/snap-bootstrap
-rwxr-xr-x 755 root:root /usr/lib/snapd/snap-repair
-rwxr-xr-x 755 root:root /usr/libexec/fwupd/fwupdoffline
-rwxr-xr-x 755 root:root /usr/bin/fwupdmgr
-rwxr-xr-x 755 root:root /usr/lib/apt/apt.systemd.daily
```

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc "find /usr/share/secureboot/updates -maxdepth 3 -printf '%M %u:%g %p -> %l\n' | sort"
```

Result:

```text
-rw-r--r-- root:root /usr/share/secureboot/updates/dbx/dbxupdate_arm64.bin -> 
drwxr-xr-x root:root /usr/share/secureboot/updates -> 
drwxr-xr-x root:root /usr/share/secureboot/updates/dbx -> 
```

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc "find /var/lib/snapd -maxdepth 3 \( -type d -o -type f -o -type l \) -printf '%M %u:%g %p -> %l\n' | sort | head -200"
```

Result:

```text
-rw------- root:root /var/lib/snapd/state.json -> 
-rw-r--r-- root:root /var/lib/snapd/features/classic-preserves-xdg-runtime-dir -> 
-rw-r--r-- root:root /var/lib/snapd/features/refresh-app-awareness -> 
-rw-r--r-- root:root /var/lib/snapd/maintenance.json -> 
-rw-r--r-- root:root /var/lib/snapd/state.lock -> 
-rw-r--r-- root:root /var/lib/snapd/system-key -> 
d--x--x--x root:root /var/lib/snapd/void -> 
drwx------ root:root /var/lib/snapd/cookie -> 
drwxr-xr-x root:root /var/lib/snapd -> 
drwxr-xr-x root:root /var/lib/snapd/apparmor -> 
drwxr-xr-x root:root /var/lib/snapd/apparmor/snap-confine -> 
drwxr-xr-x root:root /var/lib/snapd/assertions -> 
drwxr-xr-x root:root /var/lib/snapd/assertions/asserts-v0 -> 
drwxr-xr-x root:root /var/lib/snapd/assertions/asserts-v0/model -> 
drwxr-xr-x root:root /var/lib/snapd/assertions/private-keys-v1 -> 
drwxr-xr-x root:root /var/lib/snapd/auto-import -> 
drwxr-xr-x root:root /var/lib/snapd/dbus-1 -> 
drwxr-xr-x root:root /var/lib/snapd/dbus-1/services -> 
drwxr-xr-x root:root /var/lib/snapd/dbus-1/system-services -> 
drwxr-xr-x root:root /var/lib/snapd/desktop -> 
drwxr-xr-x root:root /var/lib/snapd/desktop/applications -> 
drwxr-xr-x root:root /var/lib/snapd/environment -> 
drwxr-xr-x root:root /var/lib/snapd/features -> 
drwxr-xr-x root:root /var/lib/snapd/firstboot -> 
drwxr-xr-x root:root /var/lib/snapd/hostfs -> 
drwxr-xr-x root:root /var/lib/snapd/inhibit -> 
drwxr-xr-x root:root /var/lib/snapd/lib -> 
drwxr-xr-x root:root /var/lib/snapd/lib/gl -> 
drwxr-xr-x root:root /var/lib/snapd/lib/gl32 -> 
drwxr-xr-x root:root /var/lib/snapd/lib/glvnd -> 
drwxr-xr-x root:root /var/lib/snapd/lib/vulkan -> 
drwxr-xr-x root:root /var/lib/snapd/snaps -> 
drwxr-xr-x root:root /var/lib/snapd/snaps/partial -> 
drwxr-xr-x root:root /var/lib/snapd/ssl -> 
drwxr-xr-x root:root /var/lib/snapd/ssl/store-certs -> 
```

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc "find /usr/share/secureboot /var/lib/snapd /var/lib/update-manager /var/lib/ubuntu-release-upgrader /boot -xdev -perm -0002 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort"
```

Result:

```text
```

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc "find /usr/bin/sbkeysync /usr/bin/snap /usr/lib/snapd /usr/libexec/fwupd -xdev \( -perm -4000 -o -perm -2000 -o -perm -0002 \) -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort"
```

Result:

```text
```

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc "stat -c '%A %a %U:%G %n' /etc/environment /var/lib/snapd/environment /var/lib/snapd/environment/snapd.conf 2>&1"
```

Result:

```text
-rw-r--r-- 644 root:root /etc/environment
drwxr-xr-x 755 root:root /var/lib/snapd/environment
stat: cannot statx '/var/lib/snapd/environment/snapd.conf': No such file or directory
```

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc "find /var/lib/PackageKit /var/cache/PackageKit -maxdepth 3 \( -type d -o -type f -o -type l \) -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort"
```

Result:

```text
-rw-r--r-- root:root /var/lib/PackageKit/transactions.db -> 
drwxr-xr-x root:root /var/cache/PackageKit -> 
drwxr-xr-x root:root /var/cache/PackageKit/downloads -> 
drwxr-xr-x root:root /var/lib/PackageKit -> 
```

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'find /dev -maxdepth 3 \( -type b -o -type c -o -type l \) -printf "%M %u:%g %p -> %l\n" 2>/dev/null | sort | sed -n "1,25p"'
```

Result:

```text
brw-rw---- root:disk /dev/loop0 -> 
brw-rw---- root:disk /dev/loop1 -> 
brw-rw---- root:disk /dev/loop2 -> 
brw-rw---- root:disk /dev/loop3 -> 
brw-rw---- root:disk /dev/loop4 -> 
brw-rw---- root:disk /dev/loop5 -> 
brw-rw---- root:disk /dev/loop6 -> 
brw-rw---- root:disk /dev/loop7 -> 
brw-rw---- root:disk /dev/nbd0 -> 
brw-rw---- root:disk /dev/nbd1 -> 
brw-rw---- root:disk /dev/nbd10 -> 
brw-rw---- root:disk /dev/nbd11 -> 
brw-rw---- root:disk /dev/nbd12 -> 
brw-rw---- root:disk /dev/nbd13 -> 
brw-rw---- root:disk /dev/nbd14 -> 
brw-rw---- root:disk /dev/nbd15 -> 
brw-rw---- root:disk /dev/nbd2 -> 
brw-rw---- root:disk /dev/nbd3 -> 
brw-rw---- root:disk /dev/nbd4 -> 
brw-rw---- root:disk /dev/nbd5 -> 
brw-rw---- root:disk /dev/nbd6 -> 
brw-rw---- root:disk /dev/nbd7 -> 
brw-rw---- root:disk /dev/nbd8 -> 
brw-rw---- root:disk /dev/nbd9 -> 
brw-rw---- root:disk /dev/ram0 -> 
```

## uid1001 trigger and seed/write probes

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target id
```

Result:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target sudo -n true
```

Result:

```text
sudo: a password is required
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'for d in /usr/share/secureboot/updates /usr/share/secureboot/updates/dbx /var/lib/snapd /var/lib/snapd/auto-import /var/lib/snapd/assertions /var/lib/snapd/assertions/asserts-v0 /var/lib/snapd/firstboot /var/lib/snapd/snaps /var/lib/snapd/snaps/partial /var/lib/fwupd /var/lib/update-manager /var/lib/ubuntu-release-upgrader /boot; do if [ -e "$d" ]; then if [ -w "$d" ]; then echo "writable $d"; else echo "not-writable $d"; fi; else echo "missing $d"; fi; done'
```

Result:

```text
not-writable /usr/share/secureboot/updates
not-writable /usr/share/secureboot/updates/dbx
not-writable /var/lib/snapd
not-writable /var/lib/snapd/auto-import
not-writable /var/lib/snapd/assertions
not-writable /var/lib/snapd/assertions/asserts-v0
not-writable /var/lib/snapd/firstboot
not-writable /var/lib/snapd/snaps
not-writable /var/lib/snapd/snaps/partial
missing /var/lib/fwupd
not-writable /var/lib/update-manager
not-writable /var/lib/ubuntu-release-upgrader
not-writable /boot
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'for f in /usr/lib/systemd/system/secureboot-db.service /usr/lib/systemd/system/snapd.autoimport.service /usr/lib/systemd/system/snapd.recovery-chooser-trigger.service /usr/lib/systemd/system/snapd.snap-repair.service /usr/bin/sbkeysync /usr/bin/snap /usr/lib/snapd/snap-bootstrap /usr/lib/snapd/snap-repair; do if [ -w "$f" ]; then echo "writable $f"; else echo "not-writable $f"; fi; done'
```

Result:

```text
not-writable /usr/lib/systemd/system/secureboot-db.service
not-writable /usr/lib/systemd/system/snapd.autoimport.service
not-writable /usr/lib/systemd/system/snapd.recovery-chooser-trigger.service
not-writable /usr/lib/systemd/system/snapd.snap-repair.service
not-writable /usr/bin/sbkeysync
not-writable /usr/bin/snap
not-writable /usr/lib/snapd/snap-bootstrap
not-writable /usr/lib/snapd/snap-repair
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'for u in secureboot-db.service snapd.autoimport.service snapd.recovery-chooser-trigger.service snapd.snap-repair.service fwupd-offline-update.service apt-daily.service apt-daily-upgrade.service; do echo "== $u =="; systemctl --no-ask-password start "$u" 2>&1 || true; done'
```

Result:

```text
== secureboot-db.service ==
Failed to start secureboot-db.service: Interactive authentication required.
See system logs and 'systemctl status secureboot-db.service' for details.
== snapd.autoimport.service ==
Failed to start snapd.autoimport.service: Interactive authentication required.
See system logs and 'systemctl status snapd.autoimport.service' for details.
== snapd.recovery-chooser-trigger.service ==
Failed to start snapd.recovery-chooser-trigger.service: Interactive authentication required.
See system logs and 'systemctl status snapd.recovery-chooser-trigger.service' for details.
== snapd.snap-repair.service ==
Failed to start snapd.snap-repair.service: Interactive authentication required.
See system logs and 'systemctl status snapd.snap-repair.service' for details.
== fwupd-offline-update.service ==
Failed to start fwupd-offline-update.service: Interactive authentication required.
See system logs and 'systemctl status fwupd-offline-update.service' for details.
== apt-daily.service ==
Failed to start apt-daily.service: Interactive authentication required.
See system logs and 'systemctl status apt-daily.service' for details.
== apt-daily-upgrade.service ==
Failed to start apt-daily-upgrade.service: Interactive authentication required.
See system logs and 'systemctl status apt-daily-upgrade.service' for details.
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'snap auto-import 2>&1 || true'
```

Result:

```text
auto-import is disabled on classic
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc '/usr/lib/snapd/snap-repair run 2>&1 || true'
```

Result:

```text
error: cannot use snap-repair on a classic system
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target snap changes
```

Result:

```text
ID   Status  Spawn               Ready               Summary
1    Done    today at 10:23 UTC  today at 10:23 UTC  Initialize system state
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'snap set system refresh.timer=00:00-01:00 2>&1 || true'
```

Result:

```text
error: access denied (try with sudo)
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'pkcon offline-trigger 2>&1 | head -80'
```

Result:

```text
Command failed: GDBus.Error:org.gtk.GDBus.UnmappedGError.Quark._pk_2dengine_2derror_2dquark.Code0: failed to obtain auth
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'fwupdmgr refresh --force 2>&1 | head -80'
```

Result:

```text
Failed to connect to daemon: Error calling StartServiceByName for org.freedesktop.fwupd: Failed to activate service 'org.freedesktop.fwupd': timed out (service_start_timeout=25000ms)
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'printf test > /usr/share/secureboot/updates/dbx/uid1001-test.bin'
```

Result:

```text
bash: line 1: /usr/share/secureboot/updates/dbx/uid1001-test.bin: Permission denied
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'printf test > /var/lib/snapd/auto-import/uid1001.assert'
```

Result:

```text
bash: line 1: /var/lib/snapd/auto-import/uid1001.assert: Permission denied
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'mkdir -p /var/lib/snapd/seed/assertions'
```

Result:

```text
mkdir: cannot create directory '/var/lib/snapd/seed': Permission denied
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'mkdir -p /var/lib/fwupd && printf test > /var/lib/fwupd/pending.db'
```

Result:

```text
mkdir: cannot create directory '/var/lib/fwupd': Permission denied
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'printf test > /boot/uid1001-offline-update'
```

Result:

```text
bash: line 1: /boot/uid1001-offline-update: Permission denied
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'ln -s /var/lib/fwupd/pending.db /system-update'
```

Result:

```text
ln: failed to create symbolic link '/system-update': Permission denied
```

Command:

```sh
docker exec -u 1001 ubuntu24-server-lpe-target bash -lc 'mkdir -p /var/lib/PackageKit && printf test > /var/lib/PackageKit/offline-update-action'
```

Result:

```text
bash: line 1: /var/lib/PackageKit/offline-update-action: Permission denied
```

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc "pkaction --verbose --action-id org.freedesktop.systemd1.manage-units 2>/dev/null | sed -n '1,120p'; pkaction --verbose --action-id org.freedesktop.packagekit.trigger-offline-update 2>/dev/null | sed -n '1,120p'; pkaction --verbose --action-id org.freedesktop.fwupd.update-internal 2>/dev/null | sed -n '1,120p'"
```

Result:

```text
org.freedesktop.systemd1.manage-units:
  description:       Manage system services or other units
  message:           Authentication is required to manage system services or other units.
  vendor:            The systemd Project
  vendor_url:        https://systemd.io
  icon:              
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   auth_admin_keep

org.freedesktop.packagekit.trigger-offline-update:
  description:       Trigger offline updates
  message:           Authentication is required to trigger offline updates
  vendor:            The PackageKit Project
  vendor_url:        https://www.freedesktop.org/software/PackageKit/
  icon:              package-x-generic
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   yes

org.freedesktop.fwupd.update-internal:
  description:       Install unsigned system firmware
  message:           Authentication is required to update the firmware on this machine
  vendor:            System firmware update
  vendor_url:        https://github.com/fwupd/fwupd
  icon:              application-x-firmware
  implicit any:      auth_admin
  implicit inactive: no
  implicit active:   auth_admin_keep
  annotation:        org.freedesktop.policykit.imply -> org.freedesktop.fwupd.update-internal-trusted
```

## Cleanup and final state

All uid1001 file-seeding attempts above failed with `Permission denied`; no test file was created in the audited root-controlled paths. I did not create persistent container files outside `/tmp`, and no PoC/finding artifacts were written because no real uid1001 -> root escalation was validated.

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'find /usr/share/secureboot/updates/dbx /var/lib/snapd/auto-import /var/lib/snapd/assertions/asserts-v0 /boot /var/lib/PackageKit -maxdepth 1 \( -name "uid1001*" -o -name "offline-update-action" -o -name "pending.db" \) 2>/dev/null'
```

Result:

```text
```

Conclusion: negative. The default-state attack surface is present but not reachable for uid1001 as a root execution or root-controlled-write primitive on this Docker target. `secureboot-db.service` is skipped without EFI variables; `snapd.autoimport.service` and `snapd.snap-repair.service` are skipped on classic/non-Ubuntu-Core kernel command lines and the direct tools return classic-system errors; recovery chooser is Ubuntu-Core/input-device gated; fwupd is container-gated and its offline pending database path is not user-writable; system-update/PackageKit trigger and state paths are root-owned and PolicyKit/systemd start operations require admin authentication.
