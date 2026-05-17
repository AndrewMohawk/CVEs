# Negative: systemd boot/shutdown/static units

Date: 2026-05-16

Target: Docker-only `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 Server userspace, systemd PID 1.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Status: no uid1001-to-root LPE was found in this boot/shutdown/static unit slice.

Scope: focused on enabled/static root units, system-update/offline-update activation, shutdown/finalrd activation, marker-file units, root-consumed environment/source files, unqualified helper/PATH behavior, and symlink/hardlink placement. Root timers/tmpfiles/logrotate and D-Bus/polkit API behavior were not re-triaged except where needed to prove this slice's reachability boundary.

## Default install and reachability proof

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'printf "%s\n" "### runtime"; systemctl is-system-running; printf "%s\n" "### attacker"; id attacker; printf "%s\n" "### os"; . /etc/os-release; printf "%s %s %s\n" "$PRETTY_NAME" "$VERSION_CODENAME" "$VERSION_ID"; printf "%s\n" "### packages"; dpkg-query -W systemd snapd fwupd packagekit secureboot-db ufw mdadm e2fsprogs util-linux finalrd lvm2 2>/dev/null | sort'
```

Result:

```text
### runtime
running
### attacker
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
### os
Ubuntu 24.04.4 LTS noble 24.04
### packages
e2fsprogs	1.47.0-2.4~exp1ubuntu4.1
finalrd	9build1
fwupd	1.9.34-0ubuntu1~24.04.1
lvm2	2.03.16-3ubuntu3.2
mdadm	4.3-1ubuntu2.1
packagekit	1.2.8-2ubuntu1.5
secureboot-db	1.9build1
snapd	2.74.1+ubuntu24.04.4
systemd	255.4-1ubuntu8.15
ufw	0.36.2-6
util-linux	2.39.3-9ubuntu6.5
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'units="secureboot-db.service fwupd-offline-update.service packagekit-offline-update.service system-update-cleanup.service snapd.autoimport.service snapd.recovery-chooser-trigger.service snapd.core-fixup.service snapd.system-shutdown.service ldconfig.service systemd-binfmt.service systemd-pstore.service finalrd.service blk-availability.service ufw.service e2scrub_reap.service e2scrub_all.service fstrim.service mdmonitor.service mdmonitor-oneshot.service mdcheck_start.service mdcheck_continue.service mdadm-grow-continue@.service mdadm-last-resort@.service rc-local.service plymouth-switch-root-initramfs.service systemd-repart.service systemd-modules-load.service systemd-hwdb-update.service lxd-agent.service"; systemctl list-unit-files $units --no-pager; printf "%s\n" "### active/all loaded"; systemctl list-units $units --all --no-pager'
```

Result:

```text
UNIT FILE                              STATE   PRESET
blk-availability.service               enabled enabled
e2scrub_all.service                    static  -
e2scrub_reap.service                   enabled enabled
finalrd.service                        enabled enabled
fstrim.service                         static  -
fwupd-offline-update.service           static  -
ldconfig.service                       static  -
lxd-agent.service                      static  -
mdadm-grow-continue@.service           static  -
mdadm-last-resort@.service             static  -
mdcheck_continue.service               static  -
mdcheck_start.service                  static  -
mdmonitor-oneshot.service              static  -
mdmonitor.service                      static  -
packagekit-offline-update.service      static  -
plymouth-switch-root-initramfs.service static  -
rc-local.service                       static  -
secureboot-db.service                  enabled enabled
snapd.autoimport.service               enabled enabled
snapd.core-fixup.service               enabled enabled
snapd.recovery-chooser-trigger.service enabled enabled
snapd.system-shutdown.service          enabled enabled
system-update-cleanup.service          static  -
systemd-binfmt.service                 static  -
systemd-hwdb-update.service            static  -
systemd-modules-load.service           static  -
systemd-pstore.service                 enabled enabled
systemd-repart.service                 static  -
ufw.service                            enabled enabled

29 unit files listed.
### active/all loaded
  UNIT                                   LOAD   ACTIVE   SUB    DESCRIPTION
  blk-availability.service               loaded active   exited Availability of block devices
  e2scrub_all.service                    loaded inactive dead   Online ext4 Metadata Check for All Filesystems
  e2scrub_reap.service                   loaded inactive dead   Remove Stale Online ext4 Metadata Check Snapshots
  finalrd.service                        loaded active   exited Create final runtime dir for shutdown pivot root
  fstrim.service                         loaded inactive dead   Discard unused blocks on filesystems from /etc/fstab
  ldconfig.service                       loaded active   exited Rebuild Dynamic Linker Cache
  rc-local.service                       loaded inactive dead   /etc/rc.local Compatibility
  secureboot-db.service                  loaded inactive dead   Secure Boot updates for DB and DBX
  snapd.autoimport.service               loaded inactive dead   Auto import assertions from block devices
  snapd.core-fixup.service               loaded inactive dead   Automatically repair incorrect owner/permissions on core devices
  snapd.recovery-chooser-trigger.service loaded inactive dead   Wait for the Ubuntu Core chooser trigger
  snapd.system-shutdown.service          loaded inactive dead   Ubuntu core (all-snaps) system shutdown helper setup service
  systemd-binfmt.service                 loaded active   exited Set Up Additional Binary Formats
  systemd-hwdb-update.service            loaded inactive dead   Rebuild Hardware Database
  systemd-modules-load.service           loaded active   exited Load Kernel Modules
  systemd-pstore.service                 loaded inactive dead   Platform Persistent Storage Archival
  systemd-repart.service                 loaded inactive dead   Repartition Root Disk
  ufw.service                            loaded active   exited Uncomplicated firewall

Legend: LOAD   -> Reflects whether the unit definition was properly loaded.
        ACTIVE -> The high-level unit activation state, i.e. generalization of SUB.
        SUB    -> The low-level unit activation state, values depend on unit type.

18 loaded units listed.
To show all installed unit files use 'systemctl list-unit-files'.
```

Filtered dependency proof for the reviewed roots:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'for t in sysinit.target multi-user.target system-update.target final.target poweroff.target reboot.target halt.target kexec.target; do printf "### %s\n" "$t"; systemctl list-dependencies --plain --all "$t" 2>/dev/null | grep -E "(secureboot-db|fwupd-offline-update|packagekit-offline-update|system-update-cleanup|snapd\.autoimport|snapd\.recovery-chooser-trigger|snapd\.core-fixup|snapd\.system-shutdown|ldconfig|systemd-binfmt|systemd-pstore|finalrd|blk-availability|ufw|e2scrub_reap|e2scrub_all|fstrim|mdcheck|mdmonitor|rc-local|plymouth-switch-root-initramfs|systemd-repart|systemd-modules-load|systemd-hwdb-update|lxd-agent)" || true; done'
```

Result:

```text
### sysinit.target
  blk-availability.service
  finalrd.service
  ldconfig.service
  systemd-binfmt.service
  systemd-hwdb-update.service
  systemd-modules-load.service
  systemd-pstore.service
  systemd-repart.service
### multi-user.target
  blk-availability.service
  finalrd.service
  ldconfig.service
  systemd-binfmt.service
  systemd-hwdb-update.service
  systemd-modules-load.service
  systemd-pstore.service
  systemd-repart.service
  e2scrub_reap.service
  secureboot-db.service
  snapd.autoimport.service
  snapd.core-fixup.service
  snapd.recovery-chooser-trigger.service
  ufw.service
  e2scrub_all.timer
  fstrim.timer
### system-update.target
  fwupd-offline-update.service
  blk-availability.service
  finalrd.service
  ldconfig.service
  systemd-binfmt.service
  systemd-hwdb-update.service
  systemd-modules-load.service
  systemd-pstore.service
  systemd-repart.service
  packagekit-offline-update.service
  system-update-cleanup.service
### final.target
  snapd.system-shutdown.service
### poweroff.target
  plymouth-switch-root-initramfs.service
  snapd.system-shutdown.service
### reboot.target
  plymouth-switch-root-initramfs.service
  snapd.system-shutdown.service
### halt.target
  plymouth-switch-root-initramfs.service
  snapd.system-shutdown.service
### kexec.target
  plymouth-switch-root-initramfs.service
  snapd.system-shutdown.service
```

Important installed symlinks:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'for p in /etc/systemd/system/multi-user.target.wants/secureboot-db.service /etc/systemd/system/multi-user.target.wants/snapd.autoimport.service /etc/systemd/system/multi-user.target.wants/snapd.core-fixup.service /etc/systemd/system/multi-user.target.wants/snapd.recovery-chooser-trigger.service /etc/systemd/system/multi-user.target.wants/ufw.service /etc/systemd/system/sysinit.target.wants/finalrd.service /etc/systemd/system/sysinit.target.wants/blk-availability.service /etc/systemd/system/final.target.wants/snapd.system-shutdown.service /usr/lib/systemd/system/system-update.target.wants/fwupd-offline-update.service /usr/lib/systemd/system/system-update.target.wants/packagekit-offline-update.service /usr/lib/systemd/system/poweroff.target.wants/plymouth-switch-root-initramfs.service; do if [ -e "$p" ] || [ -L "$p" ]; then ls -l "$p"; else echo "MISSING $p"; fi; done'
```

Result:

```text
lrwxrwxrwx 1 root root 45 May 16 10:22 /etc/systemd/system/multi-user.target.wants/secureboot-db.service -> /usr/lib/systemd/system/secureboot-db.service
lrwxrwxrwx 1 root root 48 May 16 10:22 /etc/systemd/system/multi-user.target.wants/snapd.autoimport.service -> /usr/lib/systemd/system/snapd.autoimport.service
lrwxrwxrwx 1 root root 48 May 16 10:22 /etc/systemd/system/multi-user.target.wants/snapd.core-fixup.service -> /usr/lib/systemd/system/snapd.core-fixup.service
lrwxrwxrwx 1 root root 62 May 16 10:22 /etc/systemd/system/multi-user.target.wants/snapd.recovery-chooser-trigger.service -> /usr/lib/systemd/system/snapd.recovery-chooser-trigger.service
lrwxrwxrwx 1 root root 35 May 16 10:22 /etc/systemd/system/multi-user.target.wants/ufw.service -> /usr/lib/systemd/system/ufw.service
lrwxrwxrwx 1 root root 39 May 16 10:22 /etc/systemd/system/sysinit.target.wants/finalrd.service -> /usr/lib/systemd/system/finalrd.service
lrwxrwxrwx 1 root root 48 May 16 10:22 /etc/systemd/system/sysinit.target.wants/blk-availability.service -> /usr/lib/systemd/system/blk-availability.service
lrwxrwxrwx 1 root root 53 May 16 10:22 /etc/systemd/system/final.target.wants/snapd.system-shutdown.service -> /usr/lib/systemd/system/snapd.system-shutdown.service
lrwxrwxrwx 1 root root 31 Mar 13 03:54 /usr/lib/systemd/system/system-update.target.wants/fwupd-offline-update.service -> ../fwupd-offline-update.service
lrwxrwxrwx 1 root root 36 Apr 20 12:20 /usr/lib/systemd/system/system-update.target.wants/packagekit-offline-update.service -> ../packagekit-offline-update.service
lrwxrwxrwx 1 root root 41 Feb 25  2025 /usr/lib/systemd/system/poweroff.target.wants/plymouth-switch-root-initramfs.service -> ../plymouth-switch-root-initramfs.service
```

## Unit trust-boundary notes

Key unit lines:

```text
/usr/lib/systemd/system/secureboot-db.service
3  ConditionPathExists=/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f
7  ExecStartPre=-/usr/bin/chattr -i /sys/firmware/efi/efivars/KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c
8  ExecStartPre=-/usr/bin/chattr -i /sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f
9  ExecStartPre=-/usr/bin/chattr -i /sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f
10 ExecStart=/usr/bin/sbkeysync --no-default-keystores --keystore /usr/share/secureboot/updates --verbose

/usr/lib/systemd/system/fwupd-offline-update.service
4  ConditionPathExists=/var/lib/fwupd/pending.db
12 ExecStart=/usr/libexec/fwupd/fwupdoffline

/usr/lib/systemd/system/packagekit-offline-update.service
4  DefaultDependencies=no
5  Requires=sysinit.target dbus.socket
6  After=sysinit.target dbus.socket systemd-journald.socket system-update-pre.target
7  Before=shutdown.target system-update.target
9  ConditionPathExists=!/run/ostree-booted
13 ExecStart=/usr/libexec/pk-offline-update

/usr/lib/systemd/system/system-update-cleanup.service
30 ConditionPathExists=|/system-update
31 ConditionPathIsSymbolicLink=|/system-update
32 ConditionPathExists=|/etc/system-update
33 ConditionPathIsSymbolicLink=|/etc/system-update
37 ExecStart=rm -fv /system-update /etc/system-update

/usr/lib/systemd/system/snapd.autoimport.service
5  ConditionKernelCommandLine=|snap_core
7  ConditionKernelCommandLine=|snapd_recovery_mode
11 ExecStart=/usr/bin/snap auto-import
12 EnvironmentFile=-/var/lib/snapd/environment/snapd.conf

/usr/lib/systemd/system/snapd.recovery-chooser-trigger.service
6  ConditionKernelCommandLine=snapd_recovery_mode
8  ConditionPathExistsGlob=/dev/input/event*
13 ExecStart=/usr/lib/snapd/snap-bootstrap recovery-chooser-trigger

/usr/lib/systemd/system/snapd.core-fixup.service
5  ConditionKernelCommandLine=|snap_core
6  ConditionKernelCommandLine=|snapd_recovery_mode
11 ExecStart=/usr/lib/snapd/snapd.core-fixup.sh

/usr/lib/systemd/system/snapd.system-shutdown.service
6  ConditionKernelCommandLine=|snap_core
7  ConditionKernelCommandLine=|snapd_recovery_mode
8  ConditionPathExists=!/usr/bin/finalrd
10 ConditionPathExists=/usr/lib/snapd/system-shutdown
15 ExecStart=/bin/mount /run -o remount,exec
16 ExecStart=/bin/mkdir -p /run/initramfs
17 ExecStart=/bin/cp /usr/lib/snapd/system-shutdown /run/initramfs/shutdown

/usr/lib/systemd/system/ldconfig.service
14 ConditionNeedsUpdate=|/etc
15 ConditionFileNotEmpty=|!/etc/ld.so.cache
26 ExecStart=/sbin/ldconfig -X

/usr/lib/systemd/system/systemd-binfmt.service
21 ConditionPathIsMountPoint=/proc/sys/fs/binfmt_misc
22 ConditionDirectoryNotEmpty=|/lib/binfmt.d
23 ConditionDirectoryNotEmpty=|/usr/lib/binfmt.d
24 ConditionDirectoryNotEmpty=|/usr/local/lib/binfmt.d
25 ConditionDirectoryNotEmpty=|/etc/binfmt.d
26 ConditionDirectoryNotEmpty=|/run/binfmt.d
31 ExecStart=/usr/lib/systemd/systemd-binfmt
32 ExecStop=/usr/lib/systemd/systemd-binfmt --unregister

/usr/lib/systemd/system/systemd-pstore.service
13 ConditionDirectoryNotEmpty=/sys/fs/pstore
14 ConditionVirtualization=!container
23 ExecStart=/usr/lib/systemd/systemd-pstore
25 StateDirectory=systemd/pstore

/usr/lib/systemd/system/finalrd.service
15 ExecStart=/bin/true
16 ExecStop=/usr/bin/finalrd

/usr/bin/finalrd
7  export DESTDIR=/run/initramfs
16 [ ! -x $DESTDIR/bin/sh ] || exit 0
22 mount -o remount,exec /run
53 systemd-tmpfiles --create /usr/lib/finalrd/finalrd-static.conf /run/finalrd-libs.conf
60 for d in /usr/share/finalrd /etc/finalrd /run/finalrd
64     run-parts -v --regex='^.*\.finalrd$' --arg=setup -- $d || :
65     find $d -executable -name '*.finalrd' -exec cp -- "{}" $DESTDIR/lib/systemd/system-shutdown \;
69 ldconfig -r $DESTDIR

/usr/lib/systemd/system/blk-availability.service
10 ExecStop=/usr/sbin/blkdeactivate -u -l wholevg -m disablequeueing -r wait

/usr/sbin/blkdeactivate
37 MDADM="/sbin/mdadm"
38 MOUNTPOINT="/bin/mountpoint"
39 MPATHD="/sbin/multipathd"
40 UMOUNT="/bin/umount"
43 sbindir="/usr/sbin"
44 DMSETUP="$sbindir/dmsetup"
45 LVM="$sbindir/lvm"

/usr/lib/systemd/system/ufw.service
12 ExecStart=/usr/lib/ufw/ufw-init start quiet
13 ExecStop=/usr/lib/ufw/ufw-init stop

/usr/lib/ufw/ufw-init
35 . "${rootdir}/etc/ufw/ufw.conf"
41 . "${rootdir}/lib/ufw/ufw-init-functions"

/usr/lib/ufw/ufw-init-functions
21 PATH="/sbin:/bin:/usr/sbin:/usr/bin"
23 for s in "${DATA_DIR}/etc/default/ufw" "${DATA_DIR}/etc/ufw/ufw.conf" ; do
25         . "$s"
125        if [ -x "$RULES_PATH/before.init" ]; then
126            if ! "$RULES_PATH/before.init" start ; then
167            BEFORE_RULES="$RULES_PATH/before${type}.rules"
168            AFTER_RULES="$RULES_PATH/after${type}.rules"
169            USER_RULES="$USER_PATH/user${type}.rules"
386        if [ ! -z "$IPT_SYSCTL" ] && [ -s "$IPT_SYSCTL" ]; then
387            sysctl -e -q -p $IPT_SYSCTL || true

/usr/lib/systemd/system/e2scrub_reap.service
20 ExecStart=/sbin/e2scrub_all -A -r

/usr/lib/systemd/system/e2scrub_all.service
11 ExecStart=/sbin/e2scrub_all

/sbin/e2scrub_all
21 PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
32 conffile="/etc/e2scrub.conf"
34 test -f "${conffile}" && . "${conffile}"
77 if [ -n "${SERVICE_MODE}" -a "${periodic_e2scrub}" -ne 1 ]; then
86     if ! readlink -q -s -e /dev/mapper/*.e2scrub* > /dev/null; then
172        if [ "${reap}" -ne 1 ] && type systemctl > /dev/null 2>&1; then
174            ${DBG} systemctl start "e2scrub@${tgt_esc}" 2> /dev/null
182        ${DBG} "/sbin/e2scrub" ${scrub_args} "${tgt}"

/usr/lib/systemd/system/fstrim.service
4  ConditionVirtualization=!container
8  ExecStart=/sbin/fstrim --listed-in /etc/fstab:/proc/self/mountinfo --verbose --quiet-unsupported

/usr/lib/systemd/system/mdcheck_continue.service
10 ConditionPathExistsGlob=/var/lib/mdcheck/MD_UUID_*
16 ExecStart=/usr/share/mdadm/mdcheck --continue --duration ${MDADM_CHECK_DURATION}

/usr/share/mdadm/mdcheck
31 # To support '--continue', arrays are identified by UUID and the 'sync_completed'
32 # value is stored  in /var/lib/mdcheck/$UUID
68 tmp=/var/lib/mdcheck/.md-check-$$
73 mkdir -p /var/lib/mdcheck
74 find /var/lib/mdcheck -name "MD_UUID*" -type f -mtime +180 -exec rm {} \;
91 mdadm --detail --export "$dev" | grep '^MD_UUID=' > $tmp || continue
92 source $tmp
93 fl="/var/lib/mdcheck/MD_UUID_$MD_UUID"
111 echo $start > $fl

/usr/lib/systemd/system/mdmonitor-oneshot.service
13 EnvironmentFile=-/etc/default/mdadm
14 ExecStart=sh -c '[ "$AUTOSCAN" != "true" ] || /sbin/mdadm --monitor --oneshot --scan'

/usr/lib/systemd/system/rc-local.service
15 ConditionFileIsExecutable=/etc/rc.local
20 ExecStart=/etc/rc.local start

/usr/lib/systemd/system/plymouth-switch-root-initramfs.service
8  ConditionPathExists=|/run/initramfs/bin/sh
9  ConditionPathExists=|/run/initramfs/shutdown
19 ExecStart=-/usr/bin/plymouth update-root-fs --new-root-dir=/run/initramfs

/usr/lib/systemd/system/systemd-repart.service
14 ConditionVirtualization=!container
15 ConditionDirectoryNotEmpty=|/usr/lib/repart.d
16 ConditionDirectoryNotEmpty=|/usr/local/lib/repart.d
17 ConditionDirectoryNotEmpty=|/etc/repart.d
18 ConditionDirectoryNotEmpty=|/run/repart.d
32 ExecStart=/usr/bin/systemd-repart --dry-run=no

/usr/lib/systemd/system/systemd-modules-load.service
16 ConditionCapability=CAP_SYS_MODULE
17 ConditionDirectoryNotEmpty=|/lib/modules-load.d
18 ConditionDirectoryNotEmpty=|/usr/lib/modules-load.d
19 ConditionDirectoryNotEmpty=|/usr/local/lib/modules-load.d
20 ConditionDirectoryNotEmpty=|/etc/modules-load.d
21 ConditionDirectoryNotEmpty=|/run/modules-load.d
28 ExecStart=/usr/lib/systemd/systemd-modules-load

/usr/lib/systemd/system/systemd-hwdb-update.service
14 ConditionNeedsUpdate=/etc
15 ConditionPathExists=|!/usr/lib/udev/hwdb.bin
16 ConditionPathExists=|/etc/udev/hwdb.bin
17 ConditionDirectoryNotEmpty=|/etc/udev/hwdb.d/
28 ExecStart=systemd-hwdb update

/usr/lib/systemd/system/lxd-agent.service
12 WorkingDirectory=-/run/lxd_agent
13 ExecStartPre=/lib/systemd/lxd-agent-setup
14 ExecStart=/run/lxd_agent/lxd-agent
```

Dead-end summary by family:

```text
secureboot-db.service: EFI condition is absent in this Docker target. Its keystore is /usr/share/secureboot/updates, root-owned 0755.
fwupd-offline-update.service: static under system-update.target and additionally requires /var/lib/fwupd/pending.db. /var/lib/fwupd is absent and uid1001 cannot create it under /var/lib.
packagekit-offline-update.service: static under system-update.target. Offline diversion requires root-created /system-update or /etc/system-update plus PackageKit state under root-owned /var/lib/PackageKit.
system-update-cleanup.service: only removes /system-update and /etc/system-update. uid1001 cannot create either path or hijack rm through systemd's root-owned binary search path.
snapd.autoimport/core-fixup/recovery-chooser/system-shutdown: enabled but gated to Ubuntu Core/recovery cmdline. The target cmdline has neither snap_core nor snapd_recovery_mode. snap auto-import reports disabled on classic.
ldconfig.service: root boot unit, but reads root-owned /etc/ld.so.conf.d and root-owned library dirs. uid1001 cannot write /usr/local/lib.
systemd-binfmt.service: reads /lib, /usr/lib, /usr/local/lib, /etc, /run binfmt.d dirs. uid1001 cannot create /run/binfmt.d or write any existing config dir.
systemd-pstore.service: disabled by container virtualization and /sys/fs/pstore is not attacker-writable.
finalrd.service and plymouth-switch-root-initramfs.service: shutdown path consumes /run/initramfs and optional hooks in /run/finalrd, /etc/finalrd, /usr/share/finalrd. uid1001 cannot create /run/initramfs or /run/finalrd; existing hooks are root-owned.
blk-availability.service: shutdown ExecStop calls blkdeactivate with absolute helper paths for mdadm, mountpoint, multipathd, umount, dmsetup, lvm.
ufw.service: sources /etc/ufw/ufw.conf, /etc/default/ufw, and optional before/after init hooks from root-owned /etc/ufw. The helper resets PATH to root-owned system dirs.
mdadm/e2scrub/fstrim: mdcheck state lives in /var/lib/mdcheck and md devices/sysfs are not attacker-createable; e2scrub config is /etc/e2scrub.conf root-owned; fstrim is gated out in container and reads /etc/fstab plus /proc/self/mountinfo.
rc-local.service: generator/condition path is /etc/rc.local; uid1001 cannot create it.
systemd-repart/modules-load/hwdb-update/lxd-agent: marker/config dirs under /run, /etc, /usr/local, /usr/lib, or /var/lib are not attacker-writable; systemd-repart is also container-gated.
```

## Attacker write and marker placement probes

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'echo "### cmdline"; cat /proc/cmdline; echo "### key dirs/files"; for p in / /etc /system-update /etc/system-update /var/lib/fwupd /var/lib/fwupd/pending.db /var/cache/fwupd /var/lib/PackageKit /var/cache/PackageKit /var/lib/snapd /var/lib/snapd/environment /var/lib/snapd/environment/snapd.conf /run /run/initramfs /run/finalrd /run/binfmt.d /etc/binfmt.d /usr/lib/binfmt.d /usr/local/lib/binfmt.d /sys/fs/pstore /usr/share/secureboot /usr/share/secureboot/updates /etc/ld.so.conf /etc/ld.so.conf.d /usr/local/lib /etc/ufw /lib/ufw /var/lib/mdcheck /etc/default/mdadm /etc/e2scrub.conf /boot /boot/uboot /writable /writable/system-data; do if [ -e "$p" ] || [ -L "$p" ]; then stat -Lc "%A %U:%G %n -> %N" "$p"; else echo "MISSING $p"; fi; done'
```

Result:

```text
### cmdline
init=/init loglevel=1 root=/dev/vdb rootfstype=erofs ro vsyscall=emulate panic=0 eth0.dhcp eth1.dhcp linuxkit.unified_cgroup_hierarchy=1 console=hvc0   virtio_net.disable_csum=1 vpnkit.connect=connect://2/1999 com.docker.VMID=4fbac003-a656-4a95-bebf-3a971e6c6566
### key dirs/files
drwxr-xr-x root:root / -> '/'
drwxr-xr-x root:root /etc -> '/etc'
MISSING /system-update
MISSING /etc/system-update
MISSING /var/lib/fwupd
MISSING /var/lib/fwupd/pending.db
MISSING /var/cache/fwupd
drwxr-xr-x root:root /var/lib/PackageKit -> '/var/lib/PackageKit'
drwxr-xr-x root:root /var/cache/PackageKit -> '/var/cache/PackageKit'
drwxr-xr-x root:root /var/lib/snapd -> '/var/lib/snapd'
drwxr-xr-x root:root /var/lib/snapd/environment -> '/var/lib/snapd/environment'
MISSING /var/lib/snapd/environment/snapd.conf
drwxr-xr-x root:root /run -> '/run'
MISSING /run/initramfs
MISSING /run/finalrd
MISSING /run/binfmt.d
drwxr-xr-x root:root /etc/binfmt.d -> '/etc/binfmt.d'
drwxr-xr-x root:root /usr/lib/binfmt.d -> '/usr/lib/binfmt.d'
MISSING /usr/local/lib/binfmt.d
dr-xr-xr-x root:root /sys/fs/pstore -> '/sys/fs/pstore'
drwxr-xr-x root:root /usr/share/secureboot -> '/usr/share/secureboot'
drwxr-xr-x root:root /usr/share/secureboot/updates -> '/usr/share/secureboot/updates'
-rw-r--r-- root:root /etc/ld.so.conf -> '/etc/ld.so.conf'
drwxr-xr-x root:root /etc/ld.so.conf.d -> '/etc/ld.so.conf.d'
drwxr-xr-x root:root /usr/local/lib -> '/usr/local/lib'
drwxr-xr-x root:root /etc/ufw -> '/etc/ufw'
drwxr-xr-x root:root /lib/ufw -> '/lib/ufw'
MISSING /var/lib/mdcheck
-rw-r--r-- root:root /etc/default/mdadm -> '/etc/default/mdadm'
-rw-r--r-- root:root /etc/e2scrub.conf -> '/etc/e2scrub.conf'
drwxr-xr-x root:root /boot -> '/boot'
MISSING /boot/uboot
MISSING /writable
MISSING /writable/system-data
```

Command:

```sh
docker exec --user 1001:1001 ubuntu24-server-lpe-target sh -lc 'id; for p in / /etc /system-update /etc/system-update /var/lib/fwupd /var/lib/fwupd/pending.db /var/cache/fwupd /var/lib/PackageKit /var/cache/PackageKit /var/lib/snapd /var/lib/snapd/environment /var/lib/snapd/environment/snapd.conf /run /run/initramfs /run/finalrd /run/binfmt.d /etc/binfmt.d /usr/lib/binfmt.d /usr/local/lib/binfmt.d /sys/fs/pstore /usr/share/secureboot/updates /etc/ld.so.conf.d /usr/local/lib /etc/ufw /lib/ufw /var/lib/mdcheck /etc/default/mdadm /etc/e2scrub.conf /boot /boot/uboot /writable /writable/system-data; do if [ -d "$p" ]; then if touch "$p/.uid1001_write_test" 2>/tmp/systemd_probe_err; then rm -f "$p/.uid1001_write_test"; echo "WRITE-DIR $p"; else printf "NO-DIR %s :: %s\n" "$p" "$(cat /tmp/systemd_probe_err)"; fi; elif [ -e "$p" ] || [ -L "$p" ]; then if [ -w "$p" ]; then echo "WRITE-FILE $p"; else echo "NO-FILE $p :: not writable"; fi; else parent=$(dirname "$p"); base=$(basename "$p"); if touch "$parent/.uid1001_create_${base}" 2>/tmp/systemd_probe_err; then rm -f "$parent/.uid1001_create_${base}"; echo "CREATE-IN-PARENT $p"; else printf "NO-CREATE %s :: %s\n" "$p" "$(cat /tmp/systemd_probe_err)"; fi; fi; done; rm -f /tmp/systemd_probe_err'
```

Result:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
NO-DIR / :: touch: cannot touch '//.uid1001_write_test': Permission denied
NO-DIR /etc :: touch: cannot touch '/etc/.uid1001_write_test': Permission denied
NO-CREATE /system-update :: touch: cannot touch '//.uid1001_create_system-update': Permission denied
NO-CREATE /etc/system-update :: touch: cannot touch '/etc/.uid1001_create_system-update': Permission denied
NO-CREATE /var/lib/fwupd :: touch: cannot touch '/var/lib/.uid1001_create_fwupd': Permission denied
NO-CREATE /var/lib/fwupd/pending.db :: touch: cannot touch '/var/lib/fwupd/.uid1001_create_pending.db': No such file or directory
NO-CREATE /var/cache/fwupd :: touch: cannot touch '/var/cache/.uid1001_create_fwupd': Permission denied
NO-DIR /var/lib/PackageKit :: touch: cannot touch '/var/lib/PackageKit/.uid1001_write_test': Permission denied
NO-DIR /var/cache/PackageKit :: touch: cannot touch '/var/cache/PackageKit/.uid1001_write_test': Permission denied
NO-DIR /var/lib/snapd :: touch: cannot touch '/var/lib/snapd/.uid1001_write_test': Permission denied
NO-DIR /var/lib/snapd/environment :: touch: cannot touch '/var/lib/snapd/environment/.uid1001_write_test': Permission denied
NO-CREATE /var/lib/snapd/environment/snapd.conf :: touch: cannot touch '/var/lib/snapd/environment/.uid1001_create_snapd.conf': Permission denied
NO-DIR /run :: touch: cannot touch '/run/.uid1001_write_test': Permission denied
NO-CREATE /run/initramfs :: touch: cannot touch '/run/.uid1001_create_initramfs': Permission denied
NO-CREATE /run/finalrd :: touch: cannot touch '/run/.uid1001_create_finalrd': Permission denied
NO-CREATE /run/binfmt.d :: touch: cannot touch '/run/.uid1001_create_binfmt.d': Permission denied
NO-DIR /etc/binfmt.d :: touch: cannot touch '/etc/binfmt.d/.uid1001_write_test': Permission denied
NO-DIR /usr/lib/binfmt.d :: touch: cannot touch '/usr/lib/binfmt.d/.uid1001_write_test': Permission denied
NO-CREATE /usr/local/lib/binfmt.d :: touch: cannot touch '/usr/local/lib/.uid1001_create_binfmt.d': Permission denied
NO-DIR /sys/fs/pstore :: touch: cannot touch '/sys/fs/pstore/.uid1001_write_test': No such file or directory
NO-DIR /usr/share/secureboot/updates :: touch: cannot touch '/usr/share/secureboot/updates/.uid1001_write_test': Permission denied
NO-DIR /etc/ld.so.conf.d :: touch: cannot touch '/etc/ld.so.conf.d/.uid1001_write_test': Permission denied
NO-DIR /usr/local/lib :: touch: cannot touch '/usr/local/lib/.uid1001_write_test': Permission denied
NO-DIR /etc/ufw :: touch: cannot touch '/etc/ufw/.uid1001_write_test': Permission denied
NO-DIR /lib/ufw :: touch: cannot touch '/lib/ufw/.uid1001_write_test': Permission denied
NO-CREATE /var/lib/mdcheck :: touch: cannot touch '/var/lib/.uid1001_create_mdcheck': Permission denied
NO-FILE /etc/default/mdadm :: not writable
NO-FILE /etc/e2scrub.conf :: not writable
NO-DIR /boot :: touch: cannot touch '/boot/.uid1001_write_test': Permission denied
NO-CREATE /boot/uboot :: touch: cannot touch '/boot/.uid1001_create_uboot': Permission denied
NO-CREATE /writable :: touch: cannot touch '//.uid1001_create_writable': Permission denied
NO-CREATE /writable/system-data :: touch: cannot touch '/writable/.uid1001_create_system-data': No such file or directory
```

Additional adjacent marker/static paths:

```sh
docker exec --user 1001:1001 ubuntu24-server-lpe-target sh -lc 'id; for p in /etc/rc.local /run/initramfs /run/initramfs/bin /run/initramfs/shutdown /run/finalrd /run/lxd_agent /run/lxd_agent/lxd-agent /run/modules-load.d /etc/modules-load.d /usr/local/lib/modules-load.d /run/repart.d /etc/repart.d /usr/local/lib/repart.d /usr/lib/repart.d /run/tmpfiles.d /etc/udev/hwdb.d /usr/lib/udev/hwdb.d /etc/networkd-dispatcher /run/extensions /var/lib/extensions /etc/extensions /.extra/sysext; do if [ -d "$p" ]; then if touch "$p/.uid1001_write_test" 2>/tmp/systemd_marker_err; then rm -f "$p/.uid1001_write_test"; echo "WRITE-DIR $p"; else printf "NO-DIR %s :: %s\n" "$p" "$(cat /tmp/systemd_marker_err)"; fi; elif [ -e "$p" ] || [ -L "$p" ]; then if [ -w "$p" ]; then echo "WRITE-FILE $p"; else echo "NO-FILE $p :: not writable"; fi; else parent=$(dirname "$p"); base=$(basename "$p"); if touch "$parent/.uid1001_create_${base}" 2>/tmp/systemd_marker_err; then rm -f "$parent/.uid1001_create_${base}"; echo "CREATE-IN-PARENT $p"; else printf "NO-CREATE %s :: %s\n" "$p" "$(cat /tmp/systemd_marker_err)"; fi; fi; done; rm -f /tmp/systemd_marker_err'
```

Result:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
NO-CREATE /etc/rc.local :: touch: cannot touch '/etc/.uid1001_create_rc.local': Permission denied
NO-CREATE /run/initramfs :: touch: cannot touch '/run/.uid1001_create_initramfs': Permission denied
NO-CREATE /run/initramfs/bin :: touch: cannot touch '/run/initramfs/.uid1001_create_bin': No such file or directory
NO-CREATE /run/initramfs/shutdown :: touch: cannot touch '/run/initramfs/.uid1001_create_shutdown': No such file or directory
NO-CREATE /run/finalrd :: touch: cannot touch '/run/.uid1001_create_finalrd': Permission denied
NO-CREATE /run/lxd_agent :: touch: cannot touch '/run/.uid1001_create_lxd_agent': Permission denied
NO-CREATE /run/lxd_agent/lxd-agent :: touch: cannot touch '/run/lxd_agent/.uid1001_create_lxd-agent': No such file or directory
NO-CREATE /run/modules-load.d :: touch: cannot touch '/run/.uid1001_create_modules-load.d': Permission denied
NO-DIR /etc/modules-load.d :: touch: cannot touch '/etc/modules-load.d/.uid1001_write_test': Permission denied
NO-CREATE /usr/local/lib/modules-load.d :: touch: cannot touch '/usr/local/lib/.uid1001_create_modules-load.d': Permission denied
NO-CREATE /run/repart.d :: touch: cannot touch '/run/.uid1001_create_repart.d': Permission denied
NO-CREATE /etc/repart.d :: touch: cannot touch '/etc/.uid1001_create_repart.d': Permission denied
NO-CREATE /usr/local/lib/repart.d :: touch: cannot touch '/usr/local/lib/.uid1001_create_repart.d': Permission denied
NO-CREATE /usr/lib/repart.d :: touch: cannot touch '/usr/lib/.uid1001_create_repart.d': Permission denied
NO-CREATE /run/tmpfiles.d :: touch: cannot touch '/run/.uid1001_create_tmpfiles.d': Permission denied
NO-DIR /etc/udev/hwdb.d :: touch: cannot touch '/etc/udev/hwdb.d/.uid1001_write_test': Permission denied
NO-DIR /usr/lib/udev/hwdb.d :: touch: cannot touch '/usr/lib/udev/hwdb.d/.uid1001_write_test': Permission denied
NO-DIR /etc/networkd-dispatcher :: touch: cannot touch '/etc/networkd-dispatcher/.uid1001_write_test': Permission denied
NO-CREATE /run/extensions :: touch: cannot touch '/run/.uid1001_create_extensions': Permission denied
NO-CREATE /var/lib/extensions :: touch: cannot touch '/var/lib/.uid1001_create_extensions': Permission denied
NO-CREATE /etc/extensions :: touch: cannot touch '/etc/.uid1001_create_extensions': Permission denied
NO-CREATE /.extra/sysext :: touch: cannot touch '/.extra/.uid1001_create_sysext': No such file or directory
```

## Symlink, hardlink, and unqualified helper probes

Command:

```sh
docker exec --user 1001:1001 ubuntu24-server-lpe-target sh -lc 'id; echo "### symlink probes"; for p in /system-update /etc/system-update /run/initramfs /run/finalrd /run/binfmt.d /run/repart.d /run/modules-load.d /var/lib/fwupd/pending.db /var/lib/mdcheck/MD_UUID_probe; do ln -s /root/systemd_lpe_probe "$p" 2>&1 && { echo "SYMLINKED $p"; rm -f "$p"; } || true; done; echo "### hardlink probes"; for p in /system-update /etc/system-update /run/initramfs/shadow_hardlink /var/lib/mdcheck/MD_UUID_shadow /usr/share/secureboot/updates/shadow_hardlink; do ln /etc/shadow "$p" 2>&1 && { echo "HARDLINKED $p"; rm -f "$p"; } || true; done; echo "### link sysctls"; /sbin/sysctl fs.protected_hardlinks fs.protected_symlinks fs.protected_regular fs.protected_fifos 2>/dev/null'
```

Result:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
### symlink probes
ln: failed to create symbolic link '/system-update': Permission denied
ln: failed to create symbolic link '/etc/system-update': Permission denied
ln: failed to create symbolic link '/run/initramfs': Permission denied
ln: failed to create symbolic link '/run/finalrd': Permission denied
ln: failed to create symbolic link '/run/binfmt.d': Permission denied
ln: failed to create symbolic link '/run/repart.d': Permission denied
ln: failed to create symbolic link '/run/modules-load.d': Permission denied
ln: failed to create symbolic link '/var/lib/fwupd/pending.db': No such file or directory
ln: failed to create symbolic link '/var/lib/mdcheck/MD_UUID_probe': No such file or directory
### hardlink probes
ln: failed to create hard link '/system-update' => '/etc/shadow': Operation not permitted
ln: failed to create hard link '/etc/system-update' => '/etc/shadow': Operation not permitted
ln: failed to create hard link '/run/initramfs/shadow_hardlink' => '/etc/shadow': No such file or directory
ln: failed to create hard link '/var/lib/mdcheck/MD_UUID_shadow' => '/etc/shadow': No such file or directory
ln: failed to create hard link '/usr/share/secureboot/updates/shadow_hardlink' => '/etc/shadow': Operation not permitted
### link sysctls
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 1
```

Systemd unqualified executable search path and attacker writeability:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'echo "### systemd binary search path"; systemd-path search-binaries-default 2>&1 || true; echo "### PATH dirs"; for p in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do stat -Lc "%A %U:%G %n" "$p"; done'; docker exec --user 1001:1001 ubuntu24-server-lpe-target sh -lc 'echo "### attacker PATH dir writes"; for p in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do touch "$p/.uid1001_path_test" 2>/tmp/pathprobe_err && { rm -f "$p/.uid1001_path_test"; echo "WRITE-DIR $p"; } || printf "NO-DIR %s :: %s\n" "$p" "$(cat /tmp/pathprobe_err)"; done; rm -f /tmp/pathprobe_err'
```

Result:

```text
### systemd binary search path
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
### PATH dirs
drwxr-xr-x root:root /usr/local/sbin
drwxr-xr-x root:root /usr/local/bin
drwxr-xr-x root:root /usr/sbin
drwxr-xr-x root:root /usr/bin
drwxr-xr-x root:root /sbin
drwxr-xr-x root:root /bin
### attacker PATH dir writes
NO-DIR /usr/local/sbin :: touch: cannot touch '/usr/local/sbin/.uid1001_path_test': Permission denied
NO-DIR /usr/local/bin :: touch: cannot touch '/usr/local/bin/.uid1001_path_test': Permission denied
NO-DIR /usr/sbin :: touch: cannot touch '/usr/sbin/.uid1001_path_test': Permission denied
NO-DIR /usr/bin :: touch: cannot touch '/usr/bin/.uid1001_path_test': Permission denied
NO-DIR /sbin :: touch: cannot touch '/sbin/.uid1001_path_test': Permission denied
NO-DIR /bin :: touch: cannot touch '/bin/.uid1001_path_test': Permission denied
```

## Offline update and snap direct trigger checks

uid1001 cannot directly start the system units:

```sh
docker exec --user 1001:1001 ubuntu24-server-lpe-target sh -lc 'for u in fwupd-offline-update.service packagekit-offline-update.service system-update-cleanup.service rc-local.service finalrd.service blk-availability.service snapd.autoimport.service systemd-binfmt.service; do echo "### systemctl start $u"; systemctl start "$u" 2>&1 | sed -n "1,5p"; done'
```

Result:

```text
### systemctl start fwupd-offline-update.service
Failed to start fwupd-offline-update.service: Interactive authentication required.
See system logs and 'systemctl status fwupd-offline-update.service' for details.
### systemctl start packagekit-offline-update.service
Failed to start packagekit-offline-update.service: Interactive authentication required.
See system logs and 'systemctl status packagekit-offline-update.service' for details.
### systemctl start system-update-cleanup.service
Failed to start system-update-cleanup.service: Interactive authentication required.
See system logs and 'systemctl status system-update-cleanup.service' for details.
### systemctl start rc-local.service
Failed to start rc-local.service: Interactive authentication required.
See system logs and 'systemctl status rc-local.service' for details.
### systemctl start finalrd.service
Failed to start finalrd.service: Interactive authentication required.
See system logs and 'systemctl status finalrd.service' for details.
### systemctl start blk-availability.service
Failed to start blk-availability.service: Interactive authentication required.
See system logs and 'systemctl status blk-availability.service' for details.
### systemctl start snapd.autoimport.service
Failed to start snapd.autoimport.service: Interactive authentication required.
See system logs and 'systemctl status snapd.autoimport.service' for details.
### systemctl start systemd-binfmt.service
Failed to start systemd-binfmt.service: Interactive authentication required.
See system logs and 'systemctl status systemd-binfmt.service' for details.
```

No-state helper traces show the offline helpers check `/system-update`; without the root-created marker/state there is no attacker-controlled package/firmware transaction consumed:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'echo "### fwupdoffline file trace"; timeout 8 strace -f -e trace=file /usr/libexec/fwupd/fwupdoffline 2>&1 | grep -E "fwupd|pending|offline|/var|/run|/etc|system-update" | sed -n "1,160p"; echo "exit=${PIPESTATUS:-n/a}"'
```

Result:

```text
### fwupdoffline file trace
execve("/usr/libexec/fwupd/fwupdoffline", ["/usr/libexec/fwupd/fwupdoffline"], 0xffffda5f5e08 /* 6 vars */) = 0
faccessat(AT_FDCWD, "/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/fwupd-1.9.34/libfwupd.so.2", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
newfstatat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/fwupd-1.9.34/", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib/aarch64-linux-gnu/libfwupd.so.2", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/fwupd-1.9.34/libfwupdplugin.so", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/fwupd-1.9.34/libfwupdutil.so", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/fwupd-1.9.34/libgio-2.0.so.0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/fwupd-1.9.34/libgobject-2.0.so.0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/fwupd-1.9.34/libglib-2.0.so.0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/fwupd-1.9.34/libsqlite3.so.0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/aarch64-linux-gnu/fwupd-1.9.34/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
newfstatat(AT_FDCWD, "/etc/gnutls/config", {st_mode=S_IFREG|0644, st_size=119, ...}, 0) = 0
openat(AT_FDCWD, "/etc/gnutls/config", O_RDONLY|O_CLOEXEC) = 3
faccessat(AT_FDCWD, "/etc/selinux/config", F_OK) = -1 ENOENT (No such file or directory)
readlinkat(AT_FDCWD, "/system-update", 0xaaaacd2d0130, 256) = -1 ENOENT (No such file or directory)
exit=n/a
```

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'echo "### pk-offline-update file trace"; timeout 8 strace -f -e trace=file /usr/libexec/pk-offline-update 2>&1 | grep -E "PackageKit|offline|system-update|prepared|/var|/run|/etc" | sed -n "1,220p"; echo "exit=${PIPESTATUS:-n/a}"'
```

Result:

```text
### pk-offline-update file trace
execve("/usr/libexec/pk-offline-update", ["/usr/libexec/pk-offline-update"], 0xffffdf050f88 /* 6 vars */) = 0
faccessat(AT_FDCWD, "/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
faccessat(AT_FDCWD, "/etc/selinux/config", F_OK) = -1 ENOENT (No such file or directory)
readlinkat(AT_FDCWD, "/system-update", 0xaaaaf4385350, 256) = -1 ENOENT (No such file or directory)
exit=n/a
```

Direct helper no-state results:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'echo "### direct helper dry/no-state results"; for c in "/usr/libexec/fwupd/fwupdoffline" "/usr/libexec/pk-offline-update" "/usr/bin/snap auto-import" "/usr/lib/snapd/snap-bootstrap recovery-chooser-trigger" "/usr/lib/snapd/snapd.core-fixup.sh"; do echo "### $c"; timeout 5 sh -c "$c" 2>&1 | sed -n "1,40p"; echo rc=$?; done'
```

Result:

```text
### direct helper dry/no-state results
### /usr/libexec/fwupd/fwupdoffline
rc=0
### /usr/libexec/pk-offline-update
rc=0
### /usr/bin/snap auto-import
auto-import is disabled on classic
rc=0
### /usr/lib/snapd/snap-bootstrap recovery-chooser-trigger
cmd_recovery_chooser_trigger.go:91: trigger wait timeout 10s
cmd_recovery_chooser_trigger.go:92: device timeout 2s
cmd_recovery_chooser_trigger.go:93: marker file /run/snapd-recovery-chooser-triggered
triggerwatch.go:113: waiting for trigger key: KEY_1
cmd_recovery_chooser_trigger.go:108: no matching input devices
rc=0
### /usr/lib/snapd/snapd.core-fixup.sh
rc=0
```

Snap/media inputs are root-owned and classic auto-import is disabled:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'echo "### snap/media paths"; for p in /media /mnt /var/lib/snapd/assertions /var/lib/snapd/seed /var/lib/snapd/snaps /run/snapd.socket /run/snapd-snap.socket /run/snapd-recovery-chooser-triggered /dev/input; do if [ -e "$p" ] || [ -L "$p" ]; then stat -Lc "%A %U:%G %n" "$p"; [ -d "$p" ] && find "$p" -maxdepth 1 -mindepth 1 -printf "%M %u:%g %p -> %l\n" 2>/dev/null | sed -n "1,25p"; else echo "MISSING $p"; fi; done'; docker exec --user 1001:1001 ubuntu24-server-lpe-target sh -lc 'echo "### attacker snap/media writes"; for p in /media /mnt /var/lib/snapd/assertions /var/lib/snapd/seed /var/lib/snapd/snaps /run/snapd-recovery-chooser-triggered /dev/input; do if [ -d "$p" ]; then touch "$p/.uid1001_write_test" 2>/tmp/snapprobe_err && rm -f "$p/.uid1001_write_test" && echo "WRITE-DIR $p" || printf "NO-DIR %s :: %s\n" "$p" "$(cat /tmp/snapprobe_err)"; elif [ -e "$p" ] || [ -L "$p" ]; then [ -w "$p" ] && echo "WRITE-FILE $p" || echo "NO-FILE $p :: not writable"; else parent=$(dirname "$p"); base=$(basename "$p"); touch "$parent/.uid1001_create_${base}" 2>/tmp/snapprobe_err && rm -f "$parent/.uid1001_create_${base}" && echo "CREATE-IN-PARENT $p" || printf "NO-CREATE %s :: %s\n" "$p" "$(cat /tmp/snapprobe_err)"; fi; done; rm -f /tmp/snapprobe_err'
```

Result:

```text
### snap/media paths
drwxr-xr-x root:root /media
drwxr-xr-x root:root /mnt
drwxr-xr-x root:root /var/lib/snapd/assertions
drwxr-xr-x root:root /var/lib/snapd/assertions/private-keys-v1 -> 
drwxr-xr-x root:root /var/lib/snapd/assertions/asserts-v0 -> 
MISSING /var/lib/snapd/seed
drwxr-xr-x root:root /var/lib/snapd/snaps
drwxr-xr-x root:root /var/lib/snapd/snaps/partial -> 
srw-rw-rw- root:root /run/snapd.socket
srw-rw-rw- root:root /run/snapd-snap.socket
MISSING /run/snapd-recovery-chooser-triggered
drwxr-xr-x root:root /dev/input
crw-rw---- root:input /dev/input/mice -> 
### attacker snap/media writes
NO-DIR /media :: touch: cannot touch '/media/.uid1001_write_test': Permission denied
NO-DIR /mnt :: touch: cannot touch '/mnt/.uid1001_write_test': Permission denied
NO-DIR /var/lib/snapd/assertions :: touch: cannot touch '/var/lib/snapd/assertions/.uid1001_write_test': Permission denied
NO-CREATE /var/lib/snapd/seed :: touch: cannot touch '/var/lib/snapd/.uid1001_create_seed': Permission denied
NO-DIR /var/lib/snapd/snaps :: touch: cannot touch '/var/lib/snapd/snaps/.uid1001_write_test': Permission denied
NO-CREATE /run/snapd-recovery-chooser-triggered :: touch: cannot touch '/run/.uid1001_create_snapd-recovery-chooser-triggered': Permission denied
NO-DIR /dev/input :: touch: cannot touch '/dev/input/.uid1001_write_test': Permission denied
```

## Specific config/input path checks

Secure Boot:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'echo "### secureboot paths"; for p in /sys/firmware/efi /sys/firmware/efi/efivars /sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f /usr/share/secureboot/updates; do if [ -e "$p" ] || [ -L "$p" ]; then stat -Lc "%A %U:%G %n" "$p"; find "$p" -maxdepth 1 -mindepth 1 -printf "%M %u:%g %p -> %l\n" 2>/dev/null | sed -n "1,40p"; else echo "MISSING $p"; fi; done; echo "### sbkeysync help"; /usr/bin/sbkeysync --help 2>&1 | sed -n "1,80p"'
```

Result:

```text
### secureboot paths
MISSING /sys/firmware/efi
MISSING /sys/firmware/efi/efivars
MISSING /sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f
drwxr-xr-x root:root /usr/share/secureboot/updates
drwxr-xr-x root:root /usr/share/secureboot/updates/dbx -> 
### sbkeysync help
Usage: sbkeysync [options]
Update EFI key databases from the filesystem

Options:
	--efivars-path <dir>  Path to efivars mountpoint
	                       (or regular directory for testing)
	--verbose             Print verbose progress information
	--dry-run             Don't update firmware key databases
	--pk                  Set PK
	--keystore <dir>      Read keys from <dir>/{db,dbx,KEK}/*
	                       (can be specified multiple times,
	                       first dir takes precedence)
	--no-default-keystores
	                      Don't read keys from the default
	                       keystore dirs
```

binfmt:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'echo "### binfmt config"; for p in /proc/sys/fs/binfmt_misc /lib/binfmt.d /usr/lib/binfmt.d /usr/local/lib/binfmt.d /etc/binfmt.d /run/binfmt.d; do if [ -e "$p" ] || [ -L "$p" ]; then stat -Lc "%A %U:%G %n" "$p"; find "$p" -maxdepth 1 -mindepth 1 -printf "%M %u:%g %p -> %l\n" 2>/dev/null | sed -n "1,50p"; else echo "MISSING $p"; fi; done'
```

Result:

```text
### binfmt config
drwxr-xr-x root:root /proc/sys/fs/binfmt_misc
-rw-r--r-- root:root /proc/sys/fs/binfmt_misc/python3.12 -> 
--w------- root:root /proc/sys/fs/binfmt_misc/register -> 
-rw-r--r-- root:root /proc/sys/fs/binfmt_misc/status -> 
drwxr-xr-x root:root /lib/binfmt.d
-rw-r--r-- root:root /lib/binfmt.d/python3.12.conf -> 
drwxr-xr-x root:root /usr/lib/binfmt.d
-rw-r--r-- root:root /usr/lib/binfmt.d/python3.12.conf -> 
MISSING /usr/local/lib/binfmt.d
drwxr-xr-x root:root /etc/binfmt.d
MISSING /run/binfmt.d
```

finalrd:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'echo "### finalrd paths"; for p in /usr/share/finalrd /etc/finalrd /run/finalrd /usr/lib/finalrd/finalrd-static.conf /run/finalrd-libs.conf /run/initramfs; do if [ -e "$p" ] || [ -L "$p" ]; then stat -Lc "%A %U:%G %n" "$p"; find "$p" -maxdepth 1 -mindepth 1 -printf "%M %u:%g %p -> %l\n" 2>/dev/null | sed -n "1,30p"; else echo "MISSING $p"; fi; done'
```

Result:

```text
### finalrd paths
drwxr-xr-x root:root /usr/share/finalrd
-rwxr-xr-x root:root /usr/share/finalrd/mdadm.finalrd -> 
-rwxr-xr-x root:root /usr/share/finalrd/open-iscsi.finalrd -> 
MISSING /etc/finalrd
MISSING /run/finalrd
-rw-r--r-- root:root /usr/lib/finalrd/finalrd-static.conf
MISSING /run/finalrd-libs.conf
MISSING /run/initramfs
```

UFW:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'echo "### ufw config perms"; for p in /etc/ufw /etc/ufw/ufw.conf /etc/default/ufw /etc/ufw/before.init /etc/ufw/after.init /etc/ufw/before.rules /etc/ufw/after.rules /etc/ufw/user.rules /etc/ufw/sysctl.conf /lib/ufw/ufw-init-functions; do if [ -e "$p" ] || [ -L "$p" ]; then stat -Lc "%A %U:%G %n" "$p"; else echo "MISSING $p"; fi; done'
```

Result:

```text
### ufw config perms
drwxr-xr-x root:root /etc/ufw
-rw-r--r-- root:root /etc/ufw/ufw.conf
-rw-r--r-- root:root /etc/default/ufw
-rw-r----- root:root /etc/ufw/before.init
-rw-r----- root:root /etc/ufw/after.init
-rw-r----- root:root /etc/ufw/before.rules
-rw-r----- root:root /etc/ufw/after.rules
-rw-r----- root:root /etc/ufw/user.rules
-rw-r--r-- root:root /etc/ufw/sysctl.conf
-rwxr-xr-x root:root /lib/ufw/ufw-init-functions
```

mdadm/e2scrub/fstrim:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'echo "### mdadm/e2scrub/fstrim path perms"; for p in /var/lib/mdcheck /etc/default/mdadm /usr/share/mdadm/mdcheck /dev/md0 /dev/md /sys/devices/virtual/block /etc/e2scrub.conf /sbin/e2scrub_all /etc/fstab /proc/self/mountinfo; do if [ -e "$p" ] || [ -L "$p" ]; then stat -Lc "%A %U:%G %n" "$p"; else echo "MISSING $p"; fi; done; echo "### md devices"; ls -l /dev/md* 2>&1 | sed -n "1,40p"'
```

Result:

```text
### mdadm/e2scrub/fstrim path perms
MISSING /var/lib/mdcheck
-rw-r--r-- root:root /etc/default/mdadm
-rwxr-xr-x root:root /usr/share/mdadm/mdcheck
MISSING /dev/md0
MISSING /dev/md
drwxr-xr-x root:root /sys/devices/virtual/block
-rw-r--r-- root:root /etc/e2scrub.conf
-rwxr-xr-x root:root /sbin/e2scrub_all
-rw-r--r-- root:root /etc/fstab
-r--r--r-- root:root /proc/self/mountinfo
### md devices
ls: cannot access '/dev/md*': No such file or directory
```

Command:

```sh
docker exec --user 1001:1001 ubuntu24-server-lpe-target sh -lc 'id; for p in /dev /dev/md999 /dev/md/evil /sys/dev/block /sys/block; do if [ -d "$p" ]; then if touch "$p/.uid1001_write_test" 2>/tmp/devprobe_err; then rm -f "$p/.uid1001_write_test"; echo "WRITE-DIR $p"; else printf "NO-DIR %s :: %s\n" "$p" "$(cat /tmp/devprobe_err)"; fi; elif [ -e "$p" ] || [ -L "$p" ]; then if [ -w "$p" ]; then echo "WRITE-FILE $p"; else echo "NO-FILE $p :: not writable"; fi; else parent=$(dirname "$p"); base=$(basename "$p"); if touch "$parent/.uid1001_create_${base}" 2>/tmp/devprobe_err; then rm -f "$parent/.uid1001_create_${base}"; echo "CREATE-IN-PARENT $p"; else printf "NO-CREATE %s :: %s\n" "$p" "$(cat /tmp/devprobe_err)"; fi; fi; done; rm -f /tmp/devprobe_err'
```

Result:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
NO-DIR /dev :: touch: cannot touch '/dev/.uid1001_write_test': Permission denied
NO-CREATE /dev/md999 :: touch: cannot touch '/dev/.uid1001_create_md999': Permission denied
NO-CREATE /dev/md/evil :: touch: cannot touch '/dev/md/.uid1001_create_evil': No such file or directory
NO-DIR /sys/dev/block :: touch: cannot touch '/sys/dev/block/.uid1001_write_test': Permission denied
NO-DIR /sys/block :: touch: cannot touch '/sys/block/.uid1001_write_test': Permission denied
```

## Cleanup

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'echo "### cleanup check"; rm -f /tmp/systemd_probe_err /tmp/systemd_marker_err /tmp/.uid1001_write_test /tmp/.uid1001_create_* 2>/dev/null || true; for p in /run/snapd-recovery-chooser-triggered /run/initramfs /run/finalrd /system-update /etc/system-update /var/lib/fwupd/pending.db; do if [ -e "$p" ] || [ -L "$p" ]; then ls -ld "$p"; else echo "absent $p"; fi; done; find / -xdev \( -name ".uid1001_write_test" -o -name ".uid1001_create_*" \) -print 2>/dev/null | sed -n "1,40p"'
```

Result:

```text
### cleanup check
absent /run/snapd-recovery-chooser-triggered
absent /run/initramfs
absent /run/finalrd
absent /system-update
absent /etc/system-update
absent /var/lib/fwupd/pending.db
```

Conclusion: the reviewed default enabled/static boot, shutdown, final, system-update, and marker-file units are reachable as root only through root-owned activation state or default boot/shutdown ordering. uid1001 cannot create the markers, cannot write consumed environment/source/cache/config paths, cannot place symlink/hardlink race targets, cannot hijack unqualified helpers through systemd/script PATH directories, and cannot manually start the root units without authentication. No exploit artifact was created.
