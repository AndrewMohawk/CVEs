# systemd template and instance boundary audit

Target: `ubuntu24-server-lpe-target`  
Scope: default Ubuntu 24.04 Server systemd template/instance/root unit transitions, especially `/usr/lib/systemd/system/*@.service`, socket/path/timer activations, generators, and `%i`/`%I`/`%f` ExecStart expansion from unprivileged D-Bus, udev, login1, storage, and timers.  
Attacker: uid `1001(attacker)`, groups `attacker` only, no sudo/admin/lxd/disk.

Verdict: negative. I did not validate a uid1001 -> root LPE, and no root proof file was created.

## Default-installed proof

Live target:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'id attacker; sed -n "1,8p" /etc/os-release; systemctl --version | head -1'
```

Observed:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_ID="24.04"
VERSION_CODENAME=noble
systemd 255 (255.4-1ubuntu8.15)
```

Relevant installed package versions:

```text
apport                  2.28.1-0ubuntu3.8
dbus                    1.14.10-4ubuntu4.1
e2fsprogs               1.47.0-2.4~exp1ubuntu4.1
lvm2                    2.03.16-3ubuntu3.2
lxd-installer           4ubuntu0.1
mdadm                   4.3-1ubuntu2.1
multipath-tools         0.9.4-5ubuntu8.1
polkitd                 124-2ubuntu1.24.04.3
systemd                 255.4-1ubuntu8.15
systemd-sysv            255.4-1ubuntu8.15
usb-modeswitch          2.6.1-3ubuntu3
xfsprogs                6.6.0-1ubuntu2.1
```

Default template services found under `/usr/lib/systemd/system`/`/lib/systemd/system`:

```text
apport-coredump-hook@.service
apport-forward@.service
container-getty@.service
e2scrub@.service
e2scrub_fail@.service
getty@.service
lxd-installer@.service
mdadm-grow-continue@.service
mdadm-last-resort@.service
mdmon@.service
modprobe@.service
serial-getty@.service
systemd-backlight@.service
systemd-fsck@.service
systemd-growfs@.service
systemd-journald@.service
systemd-networkd-wait-online@.service
systemd-pcrextend@.service
systemd-pcrfs@.service
systemd-sysext@.service
usb_modeswitch@.service
user-runtime-dir@.service
user@.service
xfs_scrub@.service
xfs_scrub_fail@.service
```

Specifier-bearing root-relevant lines:

```text
apport-coredump-hook@.service: ExecStart=/usr/share/apport/apport --from-systemd-coredump %i
e2scrub@.service: ExecStart=/sbin/e2scrub -t %I
mdadm-grow-continue@.service: ExecStart=/sbin/mdadm --grow --continue /dev/%I
mdadm-last-resort@.service: ExecStart=/sbin/mdadm --run /dev/%i
mdmon@.service: ExecStart=/sbin/mdmon --foreground --offroot --takeover %I
modprobe@.service: ExecStart=-/sbin/modprobe -abq %i
systemd-backlight@.service: ExecStart=/usr/lib/systemd/systemd-backlight load %i
systemd-fsck@.service: ExecStart=/usr/lib/systemd/systemd-fsck %f
systemd-growfs@.service: ExecStart=/usr/lib/systemd/systemd-growfs %f
systemd-journald@.service: ExecStart=/usr/lib/systemd/systemd-journald %i
systemd-networkd-wait-online@.service: ExecStart=/usr/lib/systemd/systemd-networkd-wait-online -i %i
systemd-pcrfs@.service: ExecStart=/usr/lib/systemd/systemd-pcrextend --graceful --file-system=%f
usb_modeswitch@.service: ExecStart=/usr/sbin/usb_modeswitch_dispatcher --switch-mode %i
user-runtime-dir@.service: ExecStart=/usr/lib/systemd/systemd-user-runtime-dir start %i
user@.service: User=%i
xfs_scrub@.service: ExecStart=/usr/sbin/xfs_scrub -b -n %f
```

## Direct systemd1 start boundary

`org.freedesktop.systemd1.manage-units` requires admin authentication:

```text
implicit any:      auth_admin
implicit inactive: auth_admin
implicit active:   auth_admin_keep
```

No-session uid1001 check:

```text
Authorization requires authentication but no agent is available.
pkcheck_rc=2
```

Direct template starts and transient root command attempts were denied:

```sh
runuser -u attacker -- busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss modprobe@fuse.service replace
runuser -u attacker -- busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss systemd-fsck@dev-vda1.service replace
runuser -u attacker -- busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss user@0.service replace
runuser -u attacker -- systemd-run --unit systemd-template-probe /bin/sh -c 'id > /tmp/systemd-template-root-proof'
```

Observed:

```text
Call failed: Interactive authentication required.
Call failed: Interactive authentication required.
Call failed: Interactive authentication required.
Failed to start transient service unit: Interactive authentication required.
stat: cannot statx '/tmp/systemd-template-root-proof': No such file or directory
```

Raw path traversal unit names are rejected before unit activation, and escaped names remain escaped unit identifiers:

```text
UNIT=systemd-backlight@backlight:../../tmp/lpe.service
Call failed: Unit name systemd-backlight@backlight:../../tmp/lpe.service is not valid.
UNIT=systemd-journald@../../tmp/lpe.service
Call failed: Unit name systemd-journald@../../tmp/lpe.service is not valid.
systemd-fsck@tmp-a\x3bid.service
systemd-growfs@tmp-a\x20b.service
systemd-backlight@backlight:..-..-tmp-lpe.service
```

## Socket activation

The default Accept/socket edges do not expose attacker-controlled template names to uid1001:

```text
/run/apport.socket                 srw------- root:root
/run/lxd-installer.socket          srw-rw---- root:lxd
/run/systemd/io.systemd.sysext     srw------- root:root
/run/systemd/io.systemd.PCRExtend  missing
/run/systemd/journal.probe/stdout  missing
/run/systemd/journal.probe/socket  missing
```

uid1001 connect attempts:

```text
CONNECT /run/apport.socket: PermissionError: [Errno 13] Permission denied
CONNECT /run/lxd-installer.socket: PermissionError: [Errno 13] Permission denied
CONNECT /run/systemd/io.systemd.sysext: PermissionError: [Errno 13] Permission denied
CONNECT /run/systemd/io.systemd.PCRExtend: FileNotFoundError: [Errno 2] No such file or directory
CONNECT /run/systemd/journal.probe/stdout: FileNotFoundError: [Errno 2] No such file or directory
CONNECT /run/systemd/journal.probe/socket: FileNotFoundError: [Errno 2] No such file or directory
```

`lxd-installer@.service` is socket-activated but the socket is `root:lxd 0660`; uid1001 is not in `lxd`. `systemd-journald@.socket` would point to `/run/systemd/journal.%i/...`, but no namespace socket exists unless root/systemd already instantiated it.

## login1 user@ boundary

`loginctl enable-linger attacker` is allowed for self and starts `user-runtime-dir@1001.service` and `user@1001.service`. This is a root-managed transition, but the instance is the caller's numeric UID and `user@.service` runs with `User=%i`, not as root.

Observed:

```text
enable_self_rc=0
user-runtime-dir@1001.service: ExecStart=/usr/lib/systemd/systemd-user-runtime-dir start 1001
user@1001.service: Main PID ... /usr/lib/systemd/systemd --user
/run/user/1001: attacker:attacker
/var/lib/systemd/linger/attacker: root:root
```

Arbitrary/root instances were denied:

```text
Could not enable linger: Interactive authentication required.
root_linger_rc=1
Could not enable linger: Interactive authentication required.
other_linger_rc=1
```

No path from login1 gave uid1001 control over `user@0.service` or an arbitrary `user@<instance>`.

## udev and storage-derived instances

Default udev rules do instantiate templates from kernel/device-derived names:

```text
99-systemd.rules: systemd-backlight@backlight:$name.service
63-md-raid-arrays.rules: mdmon@%c.service
63-md-raid-arrays.rules: mdadm-grow-continue@%c.service
64-md-raid-assembly.rules: mdadm-last-resort@$env{MD_DEVICE}.timer
69-lvm.rules: systemd-run --unit lvm-activate-$env{LVM_VG_NAME_COMPLETE} /usr/sbin/lvm vgchange ...
```

The live instantiated units were fixed boot/kernel names:

```text
blockdev@dev-vda1.target
getty@tty1.service
modprobe@configfs.service
modprobe@dm_mod.service
modprobe@drm.service
modprobe@efi_pstore.service
modprobe@fuse.service
modprobe@loop.service
```

uid1001 lacks the primitives needed to create attacker-named kernel block/net/backlight/md/lvm devices or storage activations:

```text
CapEff: 0000000000000000
/run/udev/control     srw------- root:root
/dev/loop-control     crw-rw---- root:disk
/dev/mapper/control   crw-rw-rw- root:root
mknod: /tmp/lpeblock: Operation not permitted
losetup: /tmp/lpe-loop.img: failed to set up loop device: Permission denied
Error setting up loop device ... UDisks2.Error.NotAuthorizedCanObtain
RTNETLINK answers: Operation not permitted
device-mapper ... Permission denied
```

`udevadm trigger --dry-run` as uid1001 can list existing sysfs devices, but those names are pre-existing kernel names. It did not give control over a new template instance name.

## Path, timer, coredump, and generator inputs

Timer/path/generator inputs were root-controlled:

```text
PATH=/usr/lib/systemd/system drwxr-xr-x root:root write_rc=1
PATH=/etc/systemd/system     drwxr-xr-x root:root write_rc=1
PATH=/run/systemd/generator  drwxr-xr-x root:root write_rc=1
PATH=/proc/cmdline           -r--r--r-- root:root write_rc=1
PATH=/etc/fstab              -rw-r--r-- root:root write_rc=1
PATH=/etc/crypttab           -rw-r--r-- root:root write_rc=1
PATH=/etc/init.d             drwxr-xr-x root:root write_rc=1
PATH=/var/lib/snapd          drwxr-xr-x root:root write_rc=1
PATH=/var/lib/apport         drwxr-xr-x root:root write_rc=1
PATH=/run/systemd/ask-password drwxr-xr-x root:root write_rc=1
```

`/var/crash` is writable, but the default Apport path/timer was inactive because `/var/lib/apport/autoreport` is missing and uid1001 cannot create it:

```text
apport-autoreport.path: ConditionPathExists=/var/lib/apport/autoreport was not met
apport-autoreport.timer: ConditionPathExists=/var/lib/apport/autoreport was not met
touch: cannot touch '/var/lib/apport/autoreport': Permission denied
```

`apport-coredump-hook@.service` is installed, but this container had no `systemd-coredump@.service` unit and kernel coredumps were not routed through systemd-coredump:

```text
UNIT FILE                     STATE  PRESET
apport-coredump-hook@.service static -
Unit systemd-coredump.socket could not be found.
core_pattern=core
```

Generated units contained no live `@` or `%i/%I/%f` output under `/run/systemd/generator*` during the probe.

## Root proof status

The probe attempted the standard root proof path:

```sh
runuser -u attacker -- systemd-run --unit systemd-template-probe /bin/sh -c 'id > /tmp/systemd-template-root-proof'
stat -Lc '%A %U:%G %s %n' /tmp/systemd-template-root-proof
```

Observed:

```text
Failed to start transient service unit: Interactive authentication required.
stat: cannot statx '/tmp/systemd-template-root-proof': No such file or directory
```

Root proof exists: no.
