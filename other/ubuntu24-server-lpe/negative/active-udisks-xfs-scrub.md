# active UDisks XFS loop mounts versus xfs_scrub timers

Result: no root LPE proof. A normal active local user can create and mount attacker-owned XFS loop images through UDisks, and the root `xfs_scrub_all` scheduler sees those mountpoints, but this did not produce root command execution or root-owned writes in the stock Ubuntu 24.04 Server Docker target.

## Target and defaults

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS.

Relevant package versions:

```text
polkitd  124-2ubuntu1.24.04.3
systemd  255.4-1ubuntu8.15
udisks2  2.10.1-6ubuntu1.3
xfsprogs 6.6.0-1ubuntu2.1
```

`xfs_scrub_all.timer` exists but is disabled and inactive by default in this target. The service and template are present as static units:

```text
/usr/lib/systemd/system/xfs_scrub_all.timer  UnitFileState=disabled
/usr/lib/systemd/system/xfs_scrub_all.service ExecStart=/usr/sbin/xfs_scrub_all
/usr/lib/systemd/system/xfs_scrub@.service ExecStart=/usr/sbin/xfs_scrub -b -n %f
```

Important boundary: `xfs_scrub_all.service` is root only as the scheduler. `xfs_scrub@.service` runs the scrubber as `User=nobody` with `NoNewPrivileges=yes`, `ProtectSystem=full`, `ProtectHome=read-only`, and bounded ambient capabilities.

There is no `/etc/xfs_scrub.conf` or `/etc/xfs_scrub` config in the package. The shipped scrub paths are `/usr/sbin/xfs_scrub`, `/usr/sbin/xfs_scrub_all`, `/usr/libexec/xfsprogs/xfs_scrub_fail`, and the systemd units under `/usr/lib/systemd/system/`.

UDisks is active and reachable for active-seat users:

```text
org.freedesktop.udisks2.filesystem-mount allow_active=yes
org.freedesktop.udisks2.loop-setup       allow_active=yes
```

## Trigger

Probe:

```sh
./pocs/active_udisks_xfs_scrub_probe.sh ubuntu24-server-lpe-target
```

The probe logs `selfauth` into an active tty session and creates XFS images with labels intended to stress mountpoint and unit escaping:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
/dev/tty1
Seat=seat0
Active=yes
```

UDisks accepted the loop setup and mount from that non-sudo active user:

```text
Mounted /dev/loop0 at /media/selfauth/XFSOK
Mounted /dev/loop1 at /media/selfauth/dot.service
Mounted /dev/loop2 at /media/selfauth/space name
Mounted /dev/loop3 at /media/selfauth/--help
```

The Docker target had only `/dev/loop0` through `/dev/loop7` device nodes and two unrelated loop minors were already occupied, so the harness created `/dev/loop8` through `/dev/loop15` as a Docker accommodation and removed only those created nodes during cleanup. The attack path itself still used only active-user UDisks loop setup and filesystem mount.

## Root scrub behavior

`/usr/sbin/xfs_scrub_all` enumerates XFS mountpoints via `lsblk -J` and schedules `xfs_scrub@.service` through `systemd-escape --template xfs_scrub@.service --path`.

With the attacker-controlled XFS mounts present, both direct service-mode execution and `systemctl start xfs_scrub_all.service` reached the attacker mountpoints, but failed before launching useful scrub instances because Ubuntu's packaged `/usr/sbin/xfs_scrub_all` references undefined Python names:

```text
Scrubbing /media/selfauth/--help...
Scrubbing /media/selfauth/XFSOK...
Scrubbing /media/selfauth/dot.service...
Scrubbing /media/selfauth/space name...
NameError: name 'path' is not defined
NameError: name 'debug' is not defined
```

Direct starts of the instance template showed the exact command path and escaping behavior for all tested mountpoints:

```text
xfs_scrub@media-selfauth-XFSOK.service
ExecStart=/usr/sbin/xfs_scrub -b -n /media/selfauth/XFSOK
User=nobody

xfs_scrub@media-selfauth-dot.service.service
ExecStart=/usr/sbin/xfs_scrub -b -n /media/selfauth/dot.service
User=nobody

xfs_scrub@media-selfauth-space\x20name.service
ExecStart=/usr/sbin/xfs_scrub -b -n /media/selfauth/space name
User=nobody

xfs_scrub@media-selfauth-\x2d\x2dhelp.service
ExecStart=/usr/sbin/xfs_scrub -b -n /media/selfauth/--help
User=nobody
```

Each direct instance ran `xfs_scrub` as `nobody`, did not reinterpret the mountpoint as options or unit directives, and aborted because the Docker kernel does not expose the XFS online metadata scrub facility:

```text
Error: /media/selfauth/--help: Kernel metadata scrubbing facility is not available.
Info: /media/selfauth/--help: Scrub aborted after phase 1.
```

Root proof markers were absent:

```text
ls: cannot access '/root/active_udisks_xfs_scrub_root': No such file or directory
ls: cannot access '/tmp/active_udisks_xfs_scrub_root': No such file or directory
```

## Cleanup and conclusion

The probe unmounted and deleted the UDisks loops, removed the harness-created loop device nodes, restarted/reset UDisks after its loop cleanup, reset failed scrub units, and removed the test home directory. Final verification:

```text
losetup -a | grep active-udisks-xfs-scrub: no output
findmnt -rn -t xfs ... active-udisks-xfs-scrub: no output
systemctl is-active udisks2.service: active
systemctl is-system-running: running
systemctl --failed --no-legend: no output
```

Triage conclusion: no Ubuntu Security LPE from this candidate. The reachable surface is real, but `xfs_scrub_all.timer` is disabled by default, the root scheduler currently crashes on mounted XFS filesystems instead of executing an attacker-influenced root command, and the scrub template runs as `nobody` with the mountpoint passed as a single escaped path argument.
