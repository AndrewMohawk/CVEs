# Negative: package-specific default helper boundaries

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server Docker target  
Probe: `pocs/package_specific_helpers_probe.sh`  
Log: `logs/package-specific-helpers.out`  
Result: no validated uid1001-to-root LPE. `ROOT_PROOF=NO`.

## Default proof

Relevant default packages:

```text
adduser                         3.137ubuntu1
busybox-initramfs               1:1.36.1-6ubuntu3.1
hdparm                          9.65+ds-1build1
init-system-helpers             1.66ubuntu1
klibc-utils                     2.0.13-4ubuntu0.2
libpam-cap:arm64                1:2.66-5ubuntu2.4
libselinux1:arm64               3.5-2ubuntu2.1
sg3-utils                       1.46-3ubuntu4
sg3-utils-udev                  1.46-3ubuntu4
thin-provisioning-tools         0.9.0-2ubuntu5.1
```

The target remained healthy after the probe:

```text
systemctl is-system-running -> running
failed units -> 0
```

## Candidate 1: libpam-cap default PAM grant

Default package integration:

```text
/etc/pam.d/common-auth:25
  auth optional pam_cap.so

/usr/share/pam-configs/capability:6
  optional pam_cap.so
```

The consumed config and module are root-owned:

```text
/etc/security/capability.conf                         -rw-r--r-- root:root
/usr/lib/aarch64-linux-gnu/security/pam_cap.so        -rw-r--r-- root:root
```

The default config ends with the restrictive rule:

```text
none  *
```

uid1001 cannot rewrite the config, and a normal attacker shell had no effective,
ambient, or inheritable capabilities:

```text
/etc/security/capability.conf: Permission denied
Current: =
Ambient set =
Current IAB:
```

## Candidate 2: init-system-helpers dpkg/systemd bridge

Default helper paths:

```text
/usr/bin/deb-systemd-helper       -rwxr-xr-x root:root
/usr/bin/deb-systemd-invoke       -rwxr-xr-x root:root
/usr/sbin/invoke-rc.d             -rwxr-xr-x root:root
/usr/sbin/update-rc.d             -rwxr-xr-x root:root
/var/lib/systemd/deb-systemd-helper-enabled  drwxr-xr-x root:root
/etc/systemd/system               drwxr-xr-x root:root
```

Risky code paths are present:

```text
/usr/bin/deb-systemd-helper:101
  SYSTEM_INSTANCE_ENABLED_STATE_DIR => '/var/lib/systemd/deb-systemd-helper-enabled'

/usr/bin/deb-systemd-helper:186-190
  record_in_statefile(...)

/usr/bin/deb-systemd-helper:352
  record_in_statefile($dsh_state, $service_link)

/usr/bin/deb-systemd-invoke:148
  system('systemctl', '--quiet', @instance_args, $action, @start_units)

/usr/bin/deb-systemd-invoke:186
  exec('systemctl', @ARGV)
```

Direct uid1001 attempts did not cross privilege:

```text
deb-systemd-helper enable cron.service
  /usr/bin/deb-systemd-helper was not called from dpkg. Exiting.

deb-systemd-invoke restart cron.service
  /usr/sbin/policy-rc.d returned 101, not running 'restart cron.service'

deb-systemd-invoke --no-dbus daemon-reload
  kill: (1): Operation not permitted
```

With attacker-controlled `DPKG_ROOT=/tmp/dsh-root`, the helper only wrote an
attacker-owned scratch tree under `/tmp/dsh-root`; no host root-owned systemd state
or root marker changed.

## Candidate 3: sg3-utils udev import/symlink rules

Default active path:

```text
systemd-udevd.service          active
systemd-udevd-kernel.socket    active
```

Root-owned udev rules and helpers:

```text
/usr/lib/udev/rules.d/55-scsi-sg3_id.rules        root:root
/usr/lib/udev/rules.d/58-scsi-sg3_symlink.rules   root:root
/usr/bin/sg_inq                                   root:root
/usr/bin/sg_vpd                                   root:root
```

The root udev rules import SCSI metadata through `sg_inq`:

```text
/usr/lib/udev/rules.d/55-scsi-sg3_id.rules:57
  IMPORT{program}="/usr/bin/sg_inq --export --inhex=$env{.SYSFS_PATH}/inquiry --raw"

/usr/lib/udev/rules.d/55-scsi-sg3_id.rules:62-63
  IMPORT{program}="/usr/bin/sg_inq --export --inhex=.../vpd_pg80|vpd_pg83 --raw"

/usr/lib/udev/rules.d/55-scsi-sg3_id.rules:70-74
  IMPORT{program}="/usr/bin/sg_inq --export ..."
```

uid1001 cannot edit the rules or trigger kernel block/scsi uevents:

```text
/usr/lib/udev/rules.d/55-scsi-sg3_id.rules: Permission denied
udevadm trigger --subsystem-match=block -> Permission denied
sg_inq --export /tmp/non-scsi-probe -> No such file or directory
```

No attacker-controlled SCSI inquiry data reached root udev in the default local
non-sudo model.

## Candidate 4: hdparm udev config parser

Default root udev rule:

```text
/usr/lib/udev/rules.d/85-hdparm.rules:1
  ACTION=="add", SUBSYSTEM=="block", KERNEL=="[sh]d[a-z]", RUN+="/lib/udev/hdparm"
```

Default helper/config paths:

```text
/usr/lib/udev/hdparm                  root:root
/lib/hdparm/hdparm-functions          root:root
/etc/hdparm.conf                      root:root
/sbin/hdparm                          root:root
```

The helper parses `/etc/hdparm.conf` and executes:

```text
/usr/lib/udev/hdparm
  . /lib/hdparm/hdparm-functions
  OPTIONS=`hdparm_options $DEVNAME`
  /sbin/hdparm -q $OPTIONS $DEVNAME
```

The shipped config explicitly warns that non-comment text is parsed, but the file
is not attacker-writable:

```text
/etc/hdparm.conf: Permission denied
udevadm trigger --subsystem-match=block -> Permission denied
DEVNAME=/tmp/fake-disk /usr/lib/udev/hdparm -> ran only as uid1001
```

No root `hdparm` invocation consumed attacker-controlled config or device metadata.

## Candidate 5: initramfs hooks and storage metadata helpers

Default packages install root-owned tools and initramfs hooks:

```text
/usr/sbin/pdata_tools
/usr/sbin/thin_check
/usr/sbin/cache_check
/usr/share/initramfs-tools/hooks/thin-provisioning-tools
/usr/share/initramfs-tools/hooks/zz-busybox-initramfs
/usr/share/initramfs-tools/hooks/klibc-utils
/usr/lib/initramfs-tools/bin/busybox
/usr/lib/klibc/bin/sh
/usr/lib/klibc-*.so
```

Relevant root hook code:

```text
/usr/share/initramfs-tools/hooks/thin-provisioning-tools:17-23
  copies pdata_tools and creates initramfs symlinks

/usr/share/initramfs-tools/hooks/zz-busybox-initramfs
  copies busybox and creates applet hardlinks

/usr/share/initramfs-tools/hooks/klibc-utils:115-130
  copies /usr/lib/klibc/bin/* and /usr/lib/klibc-*.so with cp -pL
```

uid1001 cannot edit the hooks or trigger their privileged initramfs build path.
Direct execution of `thin_check` against attacker data only produced parser errors,
and direct execution of the busybox hook with attacker `DESTDIR=/tmp/initramfs-attacker`
wrote only attacker-owned `/tmp` files:

```text
udevadm trigger --subsystem-match=block -> Permission denied
thin_check /tmp/thin-fake.meta -> bad checksum in superblock
/usr/share/initramfs-tools/hooks/zz-busybox-initramfs: Permission denied
DESTDIR=/tmp/initramfs-attacker ... -> attacker-owned scratch tree only
```

## Candidate 6: libselinux1 tmpfiles state

Default tmpfiles rule:

```text
/usr/lib/tmpfiles.d/libselinux1.conf:4
  d /run/setrans 0755 root root - -
```

Default state:

```text
systemd-tmpfiles-setup.service   active
systemd-tmpfiles-clean.timer     enabled
/run/setrans                     drwxr-xr-x root:root
/usr/lib/tmpfiles.d/libselinux1.conf  -rw-r--r-- root:root
```

uid1001 cannot write the directory or replace the tmpfiles rule:

```text
touch /run/setrans/attacker -> Permission denied
/usr/lib/tmpfiles.d/libselinux1.conf: Permission denied
systemd-tmpfiles --create ... -> no privilege crossing as uid1001
```

## Candidate 7: adduser root account-management helper

Default helper/config paths:

```text
/etc/adduser.conf                         root:root
/usr/sbin/adduser                         root:root
/usr/sbin/addgroup                        root:root
/usr/share/perl5/Debian/AdduserCommon.pm  root:root
/etc/skel                                 root:root
```

Interesting default code paths include:

```text
/usr/sbin/adduser:830
  system($passwd, $new_name)

/usr/sbin/adduser:979
  system('sh' => '-c', 'zsysctl ...')

/usr/sbin/adduser:996-1007
  skeleton copy/chown/chmod path

/usr/sbin/adduser:1222-1231
  home directory ownership and permissions path

/usr/sbin/adduser:1247
  NAME_REGEX validation
```

Direct uid1001 execution is explicitly blocked before any account mutation:

```text
/etc/adduser.conf: Permission denied
adduser --system --no-create-home pkspecprobe
  fatal: Only root may add a user or group to the system.

adduser --system --home /root/pkspecprobe --shell /bin/sh pkspecprobe2
  fatal: Only root may add a user or group to the system.
```

No passwd/group entry was created.

## Why this is not a finding

These packages expose real root-adjacent trust boundaries: PAM capability grants,
dpkg-to-systemd state helpers, root udev metadata import helpers, root block-device
configuration, initramfs hook copy logic, tmpfiles creation, and account-management
helpers. In the default Ubuntu Server state, uid1001 cannot control the root-owned
configs, rules, state directories, initramfs hooks, or package-maintainer triggers.
Direct helper execution stayed in the attacker's uid, and attacker-selected
`DPKG_ROOT`/`DESTDIR` paths affected only attacker-owned scratch directories. No
root marker was created and no privileged group/account transition occurred.

## Cleanup

The probe removed its scratch paths:

```sh
rm -rf /tmp/dsh-root /tmp/initramfs-attacker /tmp/thin-fake.meta
rm -f /root/package_specific_helpers_root
```

The final health check was `running` with zero failed units.

## Why scanners may miss it

Generic SAST can flag these as high-signal shapes: root udev `IMPORT{program}`,
root helpers parsing shell-like config, root maintainer helpers writing systemd
state, PAM modules granting capabilities, and hooks copying symlink-sensitive files.
The missed question is whether a normal non-sudo local user can seed the consumed
inputs in a stock Server state. Here, each viable input was either root-owned,
kernel-owned, dpkg-owned, or only reachable during a privileged package/initramfs
operation.

## Suggested fixes

No Ubuntu Security LPE fix is warranted from this negative result. Defense-in-depth
options:

```text
libpam-cap: keep capability.conf restrictive and root-owned; document that removing "none *" can create surprising grants.
init-system-helpers: keep dpkg caller checks and root-owned state directories; reject attacker-controlled DPKG_ROOT in privileged contexts.
sg3-utils/hdparm: keep udev rules root-owned; sanitize imported metadata before symlink/env use.
initramfs hooks: avoid following untrusted symlinks in hook copy paths and keep hooks root-owned.
libselinux1: keep /run/setrans non-writable by unprivileged users.
adduser: keep early root-only checks before config-driven file copy or command execution paths.
```
