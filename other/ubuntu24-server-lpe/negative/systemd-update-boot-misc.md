# systemd boot/update miscellaneous surfaces

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server default Docker target. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Verdict: no uid1001 -> root LPE was found in the remaining default boot/update surfaces: `systemd-ask-password-*`, `systemd-binfmt`, `systemd-confext`, `systemd-repart`, `systemd-sysupdate`, `system-update-cleanup` / `system-update.target`, or `snapd.autoimport`.

## Package and default state

Baseline proof:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'cat /etc/os-release; uname -a; id attacker; dpkg-query -W ubuntu-minimal ubuntu-standard ubuntu-server systemd snapd; apt-get -s full-upgrade | tail -n 5'
```

Evidence:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_ID="24.04"
VERSION_CODENAME=noble
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
snapd           2.74.1+ubuntu24.04.4
systemd         255.4-1ubuntu8.15
ubuntu-minimal  1.539.2
ubuntu-server   1.539.2
ubuntu-standard 1.539.2
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
```

Default unit inventory:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'systemctl list-unit-files "systemd-ask-password*" "systemd-binfmt*" "systemd-confext*" "systemd-repart*" "systemd-sysupdate*" "system-update-cleanup*" "system-update.target" "snapd.autoimport*" --no-pager; systemctl list-units "systemd-ask-password*" "systemd-binfmt*" "systemd-confext*" "systemd-repart*" "systemd-sysupdate*" "system-update-cleanup*" "system-update.target" "snapd.autoimport*" --all --no-pager'
```

Key default state:

```text
systemd-ask-password-console.path     static   loaded active waiting
systemd-ask-password-wall.path        static   loaded active waiting
systemd-binfmt.service                static   loaded active exited
systemd-confext.service               disabled installed, inactive
systemd-repart.service                static   installed, inactive
systemd-sysupdate.service             indirect installed, inactive
systemd-sysupdate.timer               disabled installed, inactive
system-update-cleanup.service         static   installed, inactive
system-update.target                  static   installed, inactive
snapd.autoimport.service              enabled  installed, inactive
```

`systemctl show` condition/state evidence:

```text
systemd-ask-password-console.path: ActiveState=active SubState=waiting ConditionResult=yes
systemd-ask-password-wall.path:    ActiveState=active SubState=waiting ConditionResult=yes
systemd-binfmt.service:            ActiveState=active SubState=exited  ConditionResult=yes ExecMainStatus=0
systemd-confext.service:           ActiveState=inactive ConditionResult=no
systemd-repart.service:            ActiveState=inactive ConditionResult=no
systemd-sysupdate.service:         ActiveState=inactive ConditionResult=no
systemd-sysupdate.timer:           UnitFileState=disabled ConditionResult=no
system-update-cleanup.service:     ActiveState=inactive ConditionResult=no
snapd.autoimport.service:          UnitFileState=enabled ActiveState=inactive ConditionResult=no
```

Package ownership:

```text
systemd: /usr/lib/systemd/system/systemd-ask-password-console.path
systemd: /usr/lib/systemd/system/systemd-ask-password-wall.path
systemd: /usr/lib/systemd/system/systemd-binfmt.service
systemd: /usr/lib/systemd/system/systemd-confext.service
systemd: /usr/lib/systemd/system/systemd-repart.service
systemd: /usr/lib/systemd/system/systemd-sysupdate.service
systemd: /usr/lib/systemd/system/system-update-cleanup.service
systemd: /usr/lib/systemd/system/system-update.target
snapd:   /lib/systemd/system/snapd.autoimport.service
```

## Unit/config trust boundaries

Relevant unit line references from the target:

```text
/usr/lib/systemd/system/systemd-ask-password-console.path:24-26
  [Path]
  DirectoryNotEmpty=/run/systemd/ask-password
  MakeDirectory=yes

/usr/lib/systemd/system/systemd-ask-password-console.service:23-24
  [Service]
  ExecStart=systemd-tty-ask-password-agent --watch --console

/usr/lib/systemd/system/systemd-ask-password-wall.path:21-23
  [Path]
  DirectoryNotEmpty=/run/systemd/ask-password
  MakeDirectory=yes

/usr/lib/systemd/system/systemd-ask-password-wall.service:15-17
  [Service]
  ExecStartPre=-systemctl stop systemd-ask-password-console.path systemd-ask-password-console.service systemd-ask-password-plymouth.path systemd-ask-password-plymouth.service
  ExecStart=systemd-tty-ask-password-agent --wall

/usr/lib/systemd/system/systemd-binfmt.service:21-32
  ConditionPathIsMountPoint=/proc/sys/fs/binfmt_misc
  ConditionDirectoryNotEmpty=|/usr/lib/binfmt.d
  ConditionDirectoryNotEmpty=|/etc/binfmt.d
  ConditionDirectoryNotEmpty=|/run/binfmt.d
  ExecStart=/usr/lib/systemd/systemd-binfmt
  ExecStop=/usr/lib/systemd/systemd-binfmt --unregister

/usr/lib/systemd/system/systemd-confext.service:14-19,29-31
  ConditionCapability=CAP_SYS_ADMIN
  ConditionDirectoryNotEmpty=|/run/confexts
  ConditionDirectoryNotEmpty=|/var/lib/confexts
  ConditionDirectoryNotEmpty=|/usr/local/lib/confexts
  ConditionDirectoryNotEmpty=|/usr/lib/confexts
  ExecStart=systemd-confext refresh
  ExecReload=systemd-confext refresh
  ExecStop=systemd-confext unmerge

/usr/lib/systemd/system/systemd-repart.service:14-18,32-37
  ConditionVirtualization=!container
  ConditionDirectoryNotEmpty=|/usr/lib/repart.d
  ConditionDirectoryNotEmpty=|/etc/repart.d
  ConditionDirectoryNotEmpty=|/run/repart.d
  ExecStart=/usr/bin/systemd-repart --dry-run=no
  SuccessExitStatus=76
  SuccessExitStatus=77

/usr/lib/systemd/system/systemd-sysupdate.service:15,20-31
  ConditionVirtualization=!container
  ExecStart=/usr/lib/systemd/systemd-sysupdate update
  CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_FSETID CAP_MKNOD CAP_SETFCAP CAP_SYS_ADMIN CAP_SETPCAP CAP_DAC_OVERRIDE CAP_LINUX_IMMUTABLE
  NoNewPrivileges=yes
  RestrictNamespaces=net

/usr/lib/systemd/system/systemd-sysupdate.timer:16,23-30
  ConditionVirtualization=!container
  OnBootSec=15min
  OnUnitActiveSec=2h
  OnCalendar=Sat
  WantedBy=timers.target

/usr/lib/systemd/system/system-update-cleanup.service:19-37
  ConditionPathExists=|/system-update
  ConditionPathIsSymbolicLink=|/system-update
  ConditionPathExists=|/etc/system-update
  ConditionPathIsSymbolicLink=|/etc/system-update
  ExecStart=rm -fv /system-update /etc/system-update

/usr/lib/systemd/system/system-update.target:14-17
  Requires=sysinit.target
  After=sysinit.target system-update-pre.target
  AllowIsolate=yes
  Wants=system-update-cleanup.service

/usr/lib/systemd/system/snapd.autoimport.service:3-12,15-17
  After=snapd.service snapd.socket snapd.seeded.service
  ConditionKernelCommandLine=|snap_core
  ConditionKernelCommandLine=|snapd_recovery_mode
  ExecStart=/usr/bin/snap auto-import
  EnvironmentFile=-/var/lib/snapd/environment/snapd.conf
  WantedBy=multi-user.target
  X-Snapd-Snap: do-not-start
```

Default directory/file permissions:

```text
drwxr-xr-x root:root /run/systemd/ask-password
drwxr-xr-x root:root /etc/binfmt.d
drwxr-xr-x root:root /usr/lib/binfmt.d
drwxr-xr-x root:root /proc/sys/fs/binfmt_misc
--w------- root:root /proc/sys/fs/binfmt_misc/register
drwxr-xr-x root:root /usr/local
drwxr-xr-x root:root /usr/local/bin
drwxr-xr-x root:root /usr/local/sbin
drwxr-xr-x root:root /run/systemd/system
drwxr-xr-x root:root /run/snapd
drwxr-xr-x root:root /var/lib/snapd
```

Missing by default under root-owned parents: `/run/confexts`, `/var/lib/confexts`, `/usr/local/lib/confexts`, `/usr/lib/confexts`, `/etc/repart.d`, `/run/repart.d`, `/usr/lib/repart.d`, `/etc/sysupdate.d`, `/run/sysupdate.d`, `/usr/lib/sysupdate.d`, `/var/lib/systemd/sysupdate`, `/system-update`, `/etc/system-update`, `/run/systemd/system/system-update.target.wants`.

The only default binfmt config is root-owned:

```text
/usr/lib/binfmt.d/python3.12.conf:1
  :python3.12:M::\xcb\x0d\x0d\x0a::/usr/bin/python3.12:
```

## Attacker trigger results

All triggers below were run as uid1001 with `docker exec -u attacker ubuntu24-server-lpe-target ...`.

Ask-password path/service:

```sh
id
touch /run/systemd/ask-password/ask.attacker
mkdir -p /run/systemd/ask-password/attacker-dir
timeout 2s systemd-ask-password --timeout=1 "attacker prompt"
timeout 2s systemd-tty-ask-password-agent --query
systemctl start systemd-ask-password-console.service
systemctl start systemd-ask-password-wall.service
```

Evidence:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
touch: cannot touch '/run/systemd/ask-password/ask.attacker': Permission denied
mkdir: cannot create directory '/run/systemd/ask-password/attacker-dir': Permission denied
Failed to query password: Permission denied
Failed to start systemd-ask-password-console.service: Interactive authentication required.
Failed to start systemd-ask-password-wall.service: Interactive authentication required.
```

Binfmt:

```sh
touch /etc/binfmt.d/attacker.conf
touch /usr/lib/binfmt.d/attacker.conf
printf ':attacker:M::ZZ::/bin/sh:F\n' > /proc/sys/fs/binfmt_misc/register
/usr/lib/systemd/systemd-binfmt
/usr/lib/systemd/systemd-binfmt --unregister
systemctl start systemd-binfmt.service
```

Evidence:

```text
touch: cannot touch '/etc/binfmt.d/attacker.conf': Permission denied
touch: cannot touch '/usr/lib/binfmt.d/attacker.conf': Permission denied
/proc/sys/fs/binfmt_misc/register: Permission denied
Failed to start systemd-binfmt.service: Interactive authentication required.
```

Post-test root check showed the attacker did not unregister the default binfmt entry:

```text
/proc/sys/fs/binfmt_misc/status: enabled
/proc/sys/fs/binfmt_misc/python3.12:
  enabled
  interpreter /usr/bin/python3.12
  magic cb0d0d0a
```

Confext, repart, and sysupdate:

```sh
mkdir -p /run/confexts /var/lib/confexts /usr/local/lib/confexts /usr/lib/confexts
mkdir -p /etc/repart.d /run/repart.d /usr/lib/repart.d
mkdir -p /etc/sysupdate.d /run/sysupdate.d /usr/lib/sysupdate.d /var/lib/systemd/sysupdate
timeout 5s systemd-confext refresh
timeout 5s systemd-repart --dry-run=yes
timeout 5s /usr/lib/systemd/systemd-sysupdate check-new
timeout 5s /usr/lib/systemd/systemd-sysupdate update
systemctl start systemd-confext.service
systemctl start systemd-repart.service
systemctl start systemd-sysupdate.service
systemctl start systemd-sysupdate-reboot.service
```

Evidence:

```text
mkdir: cannot create directory '/run/confexts': Permission denied
mkdir: cannot create directory '/var/lib/confexts': Permission denied
mkdir: cannot create directory '/usr/local/lib/confexts': Permission denied
mkdir: cannot create directory '/usr/lib/confexts': Permission denied
mkdir: cannot create directory '/etc/repart.d': Permission denied
mkdir: cannot create directory '/run/repart.d': Permission denied
mkdir: cannot create directory '/usr/lib/repart.d': Permission denied
mkdir: cannot create directory '/etc/sysupdate.d': Permission denied
mkdir: cannot create directory '/run/sysupdate.d': Permission denied
mkdir: cannot create directory '/usr/lib/sysupdate.d': Permission denied
mkdir: cannot create directory '/var/lib/systemd/sysupdate': Permission denied
Need to be privileged.
Failed to discover root block device.
No transfer definitions found.
No transfer definitions found.
Failed to start systemd-confext.service: Interactive authentication required.
Failed to start systemd-repart.service: Interactive authentication required.
Failed to start systemd-sysupdate.service: Interactive authentication required.
Failed to start systemd-sysupdate-reboot.service: Interactive authentication required.
```

Unqualified `ExecStart=` path abuse check for `systemd-confext` and `rm`:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'systemd-path search-binaries-default; stat -Lc "%A %U:%G %n" /usr/local/bin /usr/local/sbin; systemctl show-environment | grep ^PATH='
docker exec -u attacker ubuntu24-server-lpe-target bash -lc 'touch /usr/local/bin/rm; touch /usr/local/bin/systemd-confext; touch /usr/local/sbin/rm; touch /usr/local/sbin/systemd-confext; systemctl set-environment PATH=/home/attacker:/usr/local/bin:/usr/bin'
```

Evidence:

```text
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
drwxr-xr-x root:root /usr/local/bin
drwxr-xr-x root:root /usr/local/sbin
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
touch: cannot touch '/usr/local/bin/rm': Permission denied
touch: cannot touch '/usr/local/bin/systemd-confext': Permission denied
touch: cannot touch '/usr/local/sbin/rm': Permission denied
touch: cannot touch '/usr/local/sbin/systemd-confext': Permission denied
Failed to set environment: Access denied
```

System-update target and cleanup:

```sh
ln -s /tmp/attacker-system-update-target /system-update
ln -s /tmp/attacker-system-update-target /etc/system-update
mkdir -p /run/systemd/system/system-update.target.wants
systemctl start system-update-cleanup.service
systemctl isolate system-update.target
systemctl start system-update.target
```

Evidence:

```text
ln: failed to create symbolic link '/system-update': Permission denied
ln: failed to create symbolic link '/etc/system-update': Permission denied
mkdir: cannot create directory '/run/systemd/system/system-update.target.wants': Permission denied
Failed to start system-update-cleanup.service: Interactive authentication required.
Failed to start system-update.target: Interactive authentication required.
Failed to start system-update.target: Interactive authentication required.
```

Snap auto-import:

```sh
cat /proc/cmdline
systemctl start snapd.autoimport.service
timeout 10s snap auto-import
```

Evidence:

```text
init=/init loglevel=1 root=/dev/vdb rootfstype=erofs ro vsyscall=emulate panic=0 eth0.dhcp eth1.dhcp linuxkit.unified_cgroup_hierarchy=1 console=hvc0 virtio_net.disable_csum=1 vpnkit.connect=connect://2/1999 com.docker.VMID=...
Failed to start snapd.autoimport.service: Interactive authentication required.
auto-import is disabled on classic
```

`snap auto-import` help confirms the relevant root-side behavior is importing trusted assertions from mounted devices through `auto-import.assert`, but the default service is kernel-command-line gated and a normal user cannot start the service or provide root-visible block-device state:

```text
The auto-import command searches available mounted devices looking for
assertions that are signed by trusted authorities, and potentially
performs system changes based on them.
```

## Cleanup

No persistent files were created by the attacker probes. Verification:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'for p in /run/systemd/ask-password/ask.attacker /run/systemd/ask-password/attacker-dir /run/systemd/ask-password-wall /run/binfmt.d/attacker.conf /etc/binfmt.d/attacker.conf /usr/lib/binfmt.d/attacker.conf /etc/confexts /run/confexts /var/lib/confexts /usr/local/lib/confexts /usr/lib/confexts /etc/repart.d /run/repart.d /usr/lib/repart.d /usr/local/lib/repart.d /etc/sysupdate.d /run/sysupdate.d /usr/lib/sysupdate.d /usr/local/lib/sysupdate.d /var/lib/systemd/sysupdate /system-update /etc/system-update /run/systemd/system/system-update.target.wants /usr/local/bin/rm /usr/local/bin/systemd-confext /usr/local/sbin/rm /usr/local/sbin/systemd-confext; do [ -e "$p" ] && ls -ld "$p"; done; true'
```

Output was empty.

## Conclusion

These surfaces are worth manual review because they combine root boot-time helpers, path activation, offline-update generator state, root config drop-ins, and unqualified service command names. In the stock Ubuntu 24.04 Server default Docker state, the attacker cannot write the watched/config/generator paths, cannot influence the system manager environment, cannot start the root units through systemd/polkit, and direct helper execution stays unprivileged or condition-gated. No root proof or privileged service-account escalation was obtained.

Potential hardening only: use absolute paths for `ExecStart=systemd-confext ...` and `ExecStart=rm ...` to remove ambiguity for reviewers. This did not produce an exploit here because systemd resolves simple executable names through a fixed search path and every directory in that path is root-owned and non-writable to uid1001.
