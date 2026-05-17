# Negative note: multipathd local IPC and udev helpers

Date: 2026-05-16
Target: `ubuntu24-server-lpe-target`
Image: `ubuntu24-server-default-lpe:20260516-standard`
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`

## Result

No uid1001-to-root local privilege escalation was validated in the stock Ubuntu 24.04 Server Docker target.

`multipath-tools` is installed by default and `multipathd.service` / `multipathd.socket` are enabled, but both are inactive in this Docker target because their default units include `ConditionVirtualization=!container`. The only multipath runtime path in `/run` is `0700 root:root`, the abstract control socket is not listening, udev control and sysfs uevent triggering reject uid1001, and all root execution/config/plugin paths checked are root-owned and not attacker-writable. uid1001 could not send commands to a live `multipathd`, start the service/socket, trigger the root udev helper path, or create/flush/reload device maps without sudo or device privileges.

## Default package and unit state

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc "dpkg-query -W -f='\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n' multipath-tools kpartx systemd udev dmsetup 2>&1"
```

Result:

```text
dmsetup	2:1.02.185-3ubuntu3.2	ii 
kpartx	0.9.4-5ubuntu8.1	ii 
multipath-tools	0.9.4-5ubuntu8.1	ii 
systemd	255.4-1ubuntu8.15	ii 
udev	255.4-1ubuntu8.15	ii 
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'systemctl is-enabled multipathd.service multipathd.socket multipath-tools.service 2>&1; systemctl is-active multipathd.service multipathd.socket multipath-tools.service 2>&1; systemctl list-unit-files "multipath*" --no-pager; systemctl list-units "multipath*" --all --no-pager'
```

Result:

```text
enabled
enabled
alias
inactive
inactive
inactive
UNIT FILE                    STATE   PRESET
multipath-tools-boot.service masked  enabled
multipath-tools.service      alias   -
multipathd.service           enabled enabled
multipathd.socket            enabled enabled

4 unit files listed.
  UNIT               LOAD   ACTIVE   SUB  DESCRIPTION
  multipathd.service loaded inactive dead Device-Mapper Multipath Device Controller
  multipathd.socket  loaded inactive dead multipathd control socket

Legend: LOAD   -> Reflects whether the unit definition was properly loaded.
        ACTIVE -> The high-level unit activation state, i.e. generalization of SUB.
        SUB    -> The low-level unit activation state, values depend on unit type.

2 loaded units listed.
To show all installed unit files use 'systemctl list-unit-files'.
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'systemctl cat multipathd.service multipathd.socket multipath-tools.service 2>&1'
```

Relevant result:

```text
# /usr/lib/systemd/system/multipathd.service
[Unit]
Description=Device-Mapper Multipath Device Controller
Before=lvm2-activation-early.service
Before=local-fs-pre.target blk-availability.service shutdown.target
Wants=systemd-udevd-kernel.socket
After=systemd-udevd-kernel.socket
After=multipathd.socket systemd-remount-fs.service
Before=initrd-cleanup.service
DefaultDependencies=no
Conflicts=shutdown.target
Conflicts=initrd-cleanup.service
ConditionKernelCommandLine=!nompath
ConditionKernelCommandLine=!multipath=off
ConditionVirtualization=!container

[Service]
Type=notify
NotifyAccess=main
ExecStartPre=-/sbin/modprobe dm-multipath
ExecStart=/sbin/multipathd -d -s
ExecReload=/sbin/multipathd reconfigure
TasksMax=infinity

[Install]
WantedBy=sysinit.target
Also=multipathd.socket

# /usr/lib/systemd/system/multipathd.socket
[Unit]
Description=multipathd control socket
DefaultDependencies=no
ConditionKernelCommandLine=!nompath
ConditionKernelCommandLine=!multipath=off
ConditionVirtualization=!container
Before=sockets.target

[Socket]
ListenStream=@/org/kernel/linux/storage/multipathd

[Install]
WantedBy=sockets.target
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'systemd-analyze condition ConditionVirtualization=!container ConditionKernelCommandLine=!nompath ConditionKernelCommandLine=!multipath=off 2>&1'
```

Result:

```text
test.service: ConditionKernelCommandLine=!multipath=off succeeded.
test.service: ConditionKernelCommandLine=!nompath succeeded.
test.service: ConditionVirtualization=!container failed.
Conditions failed.
```

Root trying to start the socket/service also only records a skipped condition:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'systemctl start multipathd.socket 2>&1; printf "exit=%s\n" "$?"; systemctl start multipathd.service 2>&1; printf "exit=%s\n" "$?"; systemctl status multipathd.service multipathd.socket --no-pager 2>&1 | sed -n "1,80p"'
```

```text
exit=0
exit=0
○ multipathd.service - Device-Mapper Multipath Device Controller
     Loaded: loaded (/usr/lib/systemd/system/multipathd.service; enabled; preset: enabled)
     Active: inactive (dead)
TriggeredBy: ○ multipathd.socket
  Condition: start condition unmet at Sat 2026-05-16 13:26:00 UTC; 3ms ago
             └─ ConditionVirtualization=!container was not met

May 16 13:26:00 fd448ecbc136 systemd[1]: multipathd.service - Device-Mapper Multipath Device Controller was skipped because of an unmet condition check (ConditionVirtualization=!container).

○ multipathd.socket - multipathd control socket
     Loaded: loaded (/usr/lib/systemd/system/multipathd.socket; enabled; preset: enabled)
     Active: inactive (dead)
   Triggers: ● multipathd.service
  Condition: start condition unmet at Sat 2026-05-16 13:26:00 UTC; 8ms ago
             └─ ConditionVirtualization=!container was not met
     Listen: @/org/kernel/linux/storage/multipathd (Stream)

May 16 13:26:00 fd448ecbc136 systemd[1]: multipathd.socket - multipathd control socket was skipped because of an unmet condition check (ConditionVirtualization=!container).
```

## Runtime sockets and config paths

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'find /run -maxdepth 3 \( -name "*multipath*" -o -path "/run/multipath*" \) -exec ls -ld {} + 2>&1; ss -xlpn 2>/dev/null | grep -i multipath || true; grep -a multipath /proc/net/unix || true'
```

Result:

```text
drwx------ 2 root root 40 May 16 10:23 /run/multipath
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'stat -c "%A %U %G %n" /run /run/multipath /run/udev /run/udev/control 2>&1'
```

Result:

```text
drwxr-xr-x root root /run
drwx------ root root /run/multipath
drwxr-xr-x root root /run/udev
srw------- root root /run/udev/control
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'stat -c "%A %U %G %n" /etc/multipath.conf /etc/multipath /etc/multipath/conf.d /lib/multipath /lib/modules-load.d/multipath.conf /usr/lib/tmpfiles.d/multipath.conf 2>&1; sed -n "1,120p" /etc/multipath.conf 2>&1; sed -n "1,80p" /usr/lib/tmpfiles.d/multipath.conf 2>&1; sed -n "1,80p" /lib/modules-load.d/multipath.conf 2>&1'
```

Result:

```text
-rw-r--r-- root root /etc/multipath.conf
stat: cannot statx '/etc/multipath': No such file or directory
stat: cannot statx '/etc/multipath/conf.d': No such file or directory
drwxr-xr-x root root /lib/multipath
-rw-r--r-- root root /lib/modules-load.d/multipath.conf
-rw-r--r-- root root /usr/lib/tmpfiles.d/multipath.conf
defaults {
    user_friendly_names yes
}
d /run/multipath 0700 root root -
# load dm-multipath early, both multipathd and multipath depend on it
# (note that multipath may be called from udev rules!)
dm-multipath
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'for p in /sbin/multipath /sbin/multipathd /sbin/mpathpersist /sbin/kpartx /usr/lib/udev/scsi_id /usr/lib/udev/rules.d/60-multipath.rules; do [ -e "$p" ] && stat -c "%A %U %G %n" "$p"; done'
```

Result:

```text
-rwxr-xr-x root root /sbin/multipath
-rwxr-xr-x root root /sbin/multipathd
-rwxr-xr-x root root /sbin/mpathpersist
-rwxr-xr-x root root /sbin/kpartx
-rwxr-xr-x root root /usr/lib/udev/scsi_id
-rw-r--r-- root root /usr/lib/udev/rules.d/60-multipath.rules
```

## uid1001 control-channel and map-mutation tests

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc '
runuser -u attacker -- sh -lc "id"
runuser -u attacker -- sh -lc "timeout 5s multipath -ll"; printf "exit=%s\n" "$?"
runuser -u attacker -- sh -lc "timeout 5s multipath -F"; printf "exit=%s\n" "$?"
runuser -u attacker -- sh -lc "timeout 5s multipath -r"; printf "exit=%s\n" "$?"
runuser -u attacker -- sh -lc "timeout 5s multipath -d -v2"; printf "exit=%s\n" "$?"
runuser -u attacker -- sh -lc "timeout 5s multipathd show maps"; printf "exit=%s\n" "$?"
runuser -u attacker -- sh -lc "timeout 5s multipathd reconfigure"; printf "exit=%s\n" "$?"
runuser -u attacker -- sh -lc "timeout 5s multipathd -k \"show maps\""; printf "exit=%s\n" "$?"
runuser -u attacker -- sh -lc "timeout 5s systemctl start multipathd.service"; printf "exit=%s\n" "$?"
runuser -u attacker -- sh -lc "timeout 5s systemctl start multipathd.socket"; printf "exit=%s\n" "$?"
'
```

Result:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
need to be root
exit=1
need to be root
exit=1
need to be root
exit=1
need to be root
exit=1
exit=1
exit=1
ERROR: failed to connect to multipathd
exit=1
Failed to start multipathd.service: Interactive authentication required.
See system logs and 'systemctl status multipathd.service' for details.
exit=1
Failed to start multipathd.socket: Interactive authentication required.
See system logs and 'systemctl status multipathd.socket' for details.
exit=1
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc '
runuser -u attacker -- python3 - <<"PY"
import socket
for name, address in [
    ("abstract multipathd", "\0/org/kernel/linux/storage/multipathd"),
    ("/run/multipathd.sock", "/run/multipathd.sock"),
    ("/run/multipath/control", "/run/multipath/control"),
]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(2)
        s.connect(address)
        print(f"{name}: CONNECT_OK")
    except Exception as e:
        print(f"{name}: {type(e).__name__}: {e}")
    finally:
        s.close()
PY
'
```

Result:

```text
abstract multipathd: ConnectionRefusedError: [Errno 111] Connection refused
/run/multipathd.sock: FileNotFoundError: [Errno 2] No such file or directory
/run/multipath/control: PermissionError: [Errno 13] Permission denied
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'runuser -u attacker -- sh -lc "timeout 5s multipathd -d -s"; printf "exit=%s\n" "$?"; runuser -u attacker -- sh -lc "timeout 5s /sbin/multipathd -d -v3"; printf "exit=%s\n" "$?"'
```

Result:

```text
need to be root
exit=1
need to be root
exit=1
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'runuser -u attacker -- sh -lc "timeout 5s dmsetup create mpath_ipc_test --table \"0 1 zero\""; printf "exit=%s\n" "$?"; runuser -u attacker -- sh -lc "timeout 5s kpartx -av /dev/vda"; printf "exit=%s\n" "$?"; runuser -u attacker -- sh -lc "timeout 5s mpathpersist --in --read-keys /dev/vda"; printf "exit=%s\n" "$?"'
```

Result:

```text
exit=1
device-mapper: version ioctl on   failed: Permission denied
Incompatible libdevmapper 1.02.185 (2022-05-18) and kernel driver (unknown version).
Command failed.
device-mapper: version ioctl on   failed: Permission denied
Incompatible libdevmapper 1.02.185 (2022-05-18) and kernel driver (unknown version).
device mapper prerequisites not met
exit=1
need to be root
exit=1
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'runuser -u attacker -- sh -lc "test -r /dev/vda"; printf "/dev/vda readable exit=%s\n" "$?"; runuser -u attacker -- sh -lc "test -w /dev/vda"; printf "/dev/vda writable exit=%s\n" "$?"; runuser -u attacker -- sh -lc "head -c 1 /dev/vda >/dev/null"; printf "head /dev/vda exit=%s\n" "$?"; runuser -u attacker -- sh -lc "test -w /dev/mapper/control"; printf "/dev/mapper/control writable exit=%s\n" "$?"'
```

Result:

```text
/dev/vda readable exit=1
/dev/vda writable exit=1
head: cannot open '/dev/vda' for reading: Permission denied
head /dev/vda exit=1
/dev/mapper/control writable exit=0
```

Although `/dev/mapper/control` is mode `0666`, the actual device-mapper ioctl path rejected uid1001, and no `mpath_ipc_test` map appeared:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'ls -l /dev/mapper /dev/dm-* /dev/vda /dev/vdb /dev/loop0 2>&1; dmsetup ls --tree 2>&1'
```

```text
ls: cannot access '/dev/dm-*': No such file or directory
brw-rw---- 1 root disk   7,  0 May 16 10:23 /dev/loop0
brw-rw---- 1 root disk 254,  0 May 16 10:23 /dev/vda
brw-rw---- 1 root disk 254, 16 May 16 10:23 /dev/vdb

/dev/mapper:
total 0
crw-rw-rw- 1 root root 10, 236 May 16 10:23 control
No devices found
```

## uid1001 influence over root config/helper paths

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc '
runuser -u attacker -- sh -lc "printf attacker >> /etc/multipath.conf"; printf "exit=%s\n" "$?"
runuser -u attacker -- sh -lc "mkdir -p /etc/multipath/conf.d"; printf "exit=%s\n" "$?"
runuser -u attacker -- sh -lc "printf attacker > /run/multipath/attacker.conf"; printf "exit=%s\n" "$?"
runuser -u attacker -- sh -lc "printf attacker > /lib/multipath/attacker.so"; printf "exit=%s\n" "$?"
runuser -u attacker -- sh -lc "printf attacker > /usr/lib/udev/rules.d/60-multipath.rules"; printf "exit=%s\n" "$?"
'
```

Result:

```text
sh: 1: cannot create /etc/multipath.conf: Permission denied
exit=2
mkdir: cannot create directory '/etc/multipath': Permission denied
exit=1
sh: 1: cannot create /run/multipath/attacker.conf: Permission denied
exit=2
sh: 1: cannot create /lib/multipath/attacker.so: Permission denied
exit=2
sh: 1: cannot create /usr/lib/udev/rules.d/60-multipath.rules: Permission denied
exit=2
```

## Udev helper path

Package-owned udev rules invoke fixed absolute paths:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'grep -RIn "multipath -u\|systemd-run\|systemctl stop cancel\|multipath -U\|kpartx -un\|kpartx_id" /usr/lib/udev/rules.d/56-dm-mpath.rules /usr/lib/udev/rules.d/56-dm-parts.rules /usr/lib/udev/rules.d/60-multipath.rules /usr/lib/udev/rules.d/95-kpartx.rules'
```

```text
/usr/lib/udev/rules.d/56-dm-mpath.rules:29:# Don't run multipath -U during "coldplug" after switching root,
/usr/lib/udev/rules.d/56-dm-mpath.rules:33:# Check the map state directly with multipath -U.
/usr/lib/udev/rules.d/56-dm-mpath.rules:35:PROGRAM=="$env{MPATH_SBIN_PATH}/multipath -U -v1 %k", GOTO="paths_ok"
/usr/lib/udev/rules.d/56-dm-mpath.rules:102:# kpartx_id is very robust, it works for suspended maps and maps
/usr/lib/udev/rules.d/56-dm-mpath.rules:104:TEST=="/usr/lib/udev/kpartx_id", \
/usr/lib/udev/rules.d/56-dm-mpath.rules:105:	IMPORT{program}=="kpartx_id %M %m $env{DM_UUID}"
/usr/lib/udev/rules.d/56-dm-parts.rules:29:# kpartx_id is very robust, it works for suspended maps and maps
/usr/lib/udev/rules.d/56-dm-parts.rules:31:IMPORT{program}=="kpartx_id %M %m $env{DM_UUID}"
/usr/lib/udev/rules.d/60-multipath.rules:29:# multipath -u needs to know if this device has ever been exported
/usr/lib/udev/rules.d/60-multipath.rules:32:# multipath -u sets DM_MULTIPATH_DEVICE_PATH and,
/usr/lib/udev/rules.d/60-multipath.rules:34:IMPORT{program}="$env{MPATH_SBIN_PATH}/multipath -u %k"
/usr/lib/udev/rules.d/60-multipath.rules:46:# multipath -u has indicated this is "maybe" multipath.
/usr/lib/udev/rules.d/60-multipath.rules:74:RUN+="/usr/bin/systemd-run --unit=cancel-multipath-wait-$kernel --description 'cancel waiting for multipath siblings of $kernel' --no-block --timer-property DefaultDependencies=no --timer-property Conflicts=shutdown.target --timer-property Before=shutdown.target --timer-property Conflicts=initrd-cleanup.service --timer-property Before=initrd-cleanup.service --timer-property AccuracySec=500ms --property DefaultDependencies=no --property Conflicts=shutdown.target --property Before=shutdown.target --property Conflicts=initrd-cleanup.service --property Before=initrd-cleanup.service --on-active=$env{FIND_MULTIPATHS_WAIT_UNTIL} /usr/bin/udevadm trigger --action=add $sys$devpath"
/usr/lib/udev/rules.d/60-multipath.rules:89:	RUN+="/usr/bin/systemctl stop cancel-multipath-wait-$kernel.timer"
/usr/lib/udev/rules.d/95-kpartx.rules:42:RUN+="/sbin/kpartx -un -p -part /dev/$name"
```

Relevant udev service/socket boundary:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'systemctl is-active systemd-udevd.service systemd-udevd-control.socket systemd-udevd-kernel.socket 2>&1; systemctl cat systemd-udevd.service systemd-udevd-control.socket systemd-udevd-kernel.socket 2>&1 | sed -n "1,180p"'
```

```text
active
active
active
# /usr/lib/systemd/system/systemd-udevd.service
[Service]
CapabilityBoundingSet=~CAP_SYS_TIME CAP_WAKE_ALARM
Delegate=pids
DelegateSubgroup=udev
Type=notify-reload
Sockets=systemd-udevd-control.socket systemd-udevd-kernel.socket
Restart=always
RestartSec=0
ExecStart=/usr/lib/systemd/systemd-udevd
KillMode=mixed
TasksMax=infinity
PrivateMounts=yes
ProtectHostname=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallFilter=@system-service @module @raw-io bpf
SystemCallFilter=~@clock
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native
LockPersonality=yes
IPAddressDeny=any
WatchdogSec=3min

# /usr/lib/systemd/system/systemd-udevd-control.socket
[Socket]
Service=systemd-udevd.service
ListenSequentialPacket=/run/udev/control
SocketMode=0600
PassCredentials=yes
RemoveOnStop=yes

# /usr/lib/systemd/system/systemd-udevd-kernel.socket
[Socket]
Service=systemd-udevd.service
ReceiveBuffer=128M
ListenNetlink=kobject-uevent 1
PassCredentials=yes
```

uid1001 cannot use udev control, cannot trigger block-device uevents, and a debug-only `udevadm test` does not run `RUN` keys:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'runuser -u attacker -- sh -lc "udevadm control --ping"; printf "ping exit=%s\n" "$?"; runuser -u attacker -- sh -lc "udevadm control --reload"; printf "reload exit=%s\n" "$?"; runuser -u attacker -- sh -lc "udevadm trigger --action=add --sysname-match=loop0"; printf "trigger exit=%s\n" "$?"; runuser -u attacker -- sh -lc "udevadm test /sys/class/block/loop0 2>&1 | tail -n 28"; printf "test exit=%s\n" "$?"'
```

Result:

```text
Failed to send a ping message: Permission denied
ping exit=1
Failed to send reload request: Permission denied
reload exit=1
loop0: Failed to write 'add' to '/sys/devices/virtual/block/loop0/uevent': Permission denied
trigger exit=1
loop0: Starting 'bcache-export-cached /dev/loop0'
Successfully forked off '(spawn)' as PID 87845.
Skipping PR_SET_MM, as we don't have privileges.
loop0: Process 'bcache-export-cached /dev/loop0' succeeded.
loop0: Preserve permissions of /dev/loop0, uid=0, gid=6, mode=0660
loop0: Failed to adjust timestamp of node /dev/loop0: Permission denied
loop0: Failed to create lock file for stack directory '/run/udev/links/disk\x2fby-diskseq\x2f50': Permission denied
loop0: Failed to create/update device symlink '/dev/disk/by-diskseq/50', ignoring: Permission denied
loop0: Failed to create symlink '/dev/block/7:0' to '/dev/loop0': Permission denied
loop0: Failed to create device symlink '/dev/block/7:0': Permission denied
Unload kernel module index.
Unloaded link configuration context.
This program is for debugging only, it does not run any program
specified by a RUN key. It may show incorrect results, because
some values may be different, or not available at a simulation run.

DEVPATH=/devices/virtual/block/loop0
DEVNAME=/dev/loop0
DEVTYPE=disk
DISKSEQ=50
MAJOR=7
MINOR=0
ACTION=add
SUBSYSTEM=block
TAGS=:systemd:
DEVLINKS=/dev/disk/by-diskseq/50
CURRENT_TAGS=:systemd:
SYSTEMD_READY=0
test exit=0
```

The direct `systemd-run` / `systemctl stop cancel-multipath-wait-*` paths from the multipath udev rule are also not directly invokable by uid1001:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'runuser -u attacker -- sh -lc "systemd-run --unit=cancel-multipath-wait-attacker --description attacker --no-block /usr/bin/id"; printf "exit=%s\n" "$?"; runuser -u attacker -- sh -lc "systemctl stop cancel-multipath-wait-loop0.timer"; printf "exit=%s\n" "$?"'
```

```text
Failed to start transient service unit: Interactive authentication required.
exit=1
Failed to stop cancel-multipath-wait-loop0.timer: Interactive authentication required.
See system logs and 'systemctl status cancel-multipath-wait-loop0.timer' for details.
exit=1
```

The Docker target also has no `sd*`, `dasd*`, or `nvme*` block device that would naturally pass the `60-multipath.rules` kernel-name gate:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'ls -ld /sys/class/block /sys/class/block/* 2>&1 | sed -n "1,80p"'
```

```text
drwxr-xr-x 2 root root 0 May 16 10:23 /sys/class/block
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/loop0 -> ../../devices/virtual/block/loop0
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/loop1 -> ../../devices/virtual/block/loop1
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/loop2 -> ../../devices/virtual/block/loop2
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/loop3 -> ../../devices/virtual/block/loop3
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/loop4 -> ../../devices/virtual/block/loop4
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/loop5 -> ../../devices/virtual/block/loop5
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/loop6 -> ../../devices/virtual/block/loop6
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/loop7 -> ../../devices/virtual/block/loop7
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd0 -> ../../devices/virtual/block/nbd0
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd1 -> ../../devices/virtual/block/nbd1
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd10 -> ../../devices/virtual/block/nbd10
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd11 -> ../../devices/virtual/block/nbd11
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd12 -> ../../devices/virtual/block/nbd12
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd13 -> ../../devices/virtual/block/nbd13
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd14 -> ../../devices/virtual/block/nbd14
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd15 -> ../../devices/virtual/block/nbd15
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd2 -> ../../devices/virtual/block/nbd2
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd3 -> ../../devices/virtual/block/nbd3
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd4 -> ../../devices/virtual/block/nbd4
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd5 -> ../../devices/virtual/block/nbd5
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd6 -> ../../devices/virtual/block/nbd6
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd7 -> ../../devices/virtual/block/nbd7
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd8 -> ../../devices/virtual/block/nbd8
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/nbd9 -> ../../devices/virtual/block/nbd9
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram0 -> ../../devices/virtual/block/ram0
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram1 -> ../../devices/virtual/block/ram1
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram10 -> ../../devices/virtual/block/ram10
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram11 -> ../../devices/virtual/block/ram11
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram12 -> ../../devices/virtual/block/ram12
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram13 -> ../../devices/virtual/block/ram13
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram14 -> ../../devices/virtual/block/ram14
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram15 -> ../../devices/virtual/block/ram15
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram2 -> ../../devices/virtual/block/ram2
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram3 -> ../../devices/virtual/block/ram3
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram4 -> ../../devices/virtual/block/ram4
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram5 -> ../../devices/virtual/block/ram5
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram6 -> ../../devices/virtual/block/ram6
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram7 -> ../../devices/virtual/block/ram7
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram8 -> ../../devices/virtual/block/ram8
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/ram9 -> ../../devices/virtual/block/ram9
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/vda -> ../../devices/platform/40000000.pci/pci0000:00/0000:00:06.0/virtio3/block/vda
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/vda1 -> ../../devices/platform/40000000.pci/pci0000:00/0000:00:06.0/virtio3/block/vda/vda1
lrwxrwxrwx 1 root root 0 May 16 10:23 /sys/class/block/vdb -> ../../devices/platform/40000000.pci/pci0000:00/0000:00:07.0/virtio4/block/vdb
```

## Cleanup

Temporary files created only under `/tmp` in the container were removed:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'rm -rf /tmp/multipath-tools-* /tmp/multipathd-local-ipc-apt-source.out /tmp/multipathd-local-ipc-owned; find /tmp -maxdepth 1 \( -name "multipathd-local-ipc*" -o -name "multipath-tools-*" -o -name "mpath_ipc_test*" \) -print 2>&1'
```

Result was empty.

Final state check:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'systemctl reset-failed multipathd.service multipathd.socket cancel-multipath-wait-attacker.service cancel-multipath-wait-loop0.timer 2>&1 || true; systemctl is-active multipathd.service multipathd.socket 2>&1'
```

Result:

```text
Failed to reset failed state of unit cancel-multipath-wait-attacker.service: Unit cancel-multipath-wait-attacker.service not loaded.
Failed to reset failed state of unit cancel-multipath-wait-loop0.timer: Unit cancel-multipath-wait-loop0.timer not loaded.
inactive
inactive
```

No `notes/<finding>.md` or `pocs/<finding>.sh` was written because the audit did not produce a root proof or cleanup-requiring exploit path.
