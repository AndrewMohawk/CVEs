# Negative: filesystem maintenance helpers and timers

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, Docker-only Ubuntu 24.04.4 Server userspace target after full upgrade. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no uid1001-to-root LPE validated. Several filesystem/storage maintenance packages are default-installed and some root timers are default-enabled, but attacker-controlled paths either are not consumed by the root service, require root-owned block devices/LVM/MD state, or are condition-gated.

## Package proof

```text
e2fsprogs 1.47.0-2.4~exp1ubuntu4.1
lvm2      2.03.16-3ubuntu3.2
mdadm     4.3-1ubuntu2.1
systemd   255.4-1ubuntu8.15
util-linux 2.39.3-9ubuntu6.5
xfsprogs  6.6.0-1ubuntu2.1
```

## Default timers and services

```text
e2scrub_all.timer   loaded active waiting
e2scrub_all.service loaded inactive dead
fstrim.timer        enabled but skipped in Docker by ConditionVirtualization=!container
mdcheck_start.timer enabled but inactive; WantedBy=mdmonitor.service
mdmonitor.service   static inactive
xfs_scrub_all.timer disabled in this Docker target
```

Line refs:

```text
/usr/lib/systemd/system/e2scrub_all.timer:6 OnCalendar=Sun *-*-* 03:10:00
/usr/lib/systemd/system/e2scrub_all.timer:8 Persistent=true
/usr/lib/systemd/system/e2scrub_all.service:4 ConditionCapability=CAP_SYS_ADMIN
/usr/lib/systemd/system/e2scrub_all.service:5 ConditionCapability=CAP_SYS_RAWIO
/usr/lib/systemd/system/e2scrub_all.service:10 Environment=SERVICE_MODE=1
/usr/lib/systemd/system/e2scrub_all.service:11 ExecStart=/sbin/e2scrub_all
/usr/lib/systemd/system/e2scrub@.service:12 PrivateTmp=yes
/usr/lib/systemd/system/e2scrub@.service:13 AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_RAWIO
/usr/lib/systemd/system/e2scrub@.service:19 ExecStart=/sbin/e2scrub -t %I
/usr/lib/systemd/system/fstrim.timer:4 ConditionVirtualization=!container
/usr/lib/systemd/system/fstrim.service:8 ExecStart=/sbin/fstrim --listed-in /etc/fstab:/proc/self/mountinfo --verbose --quiet-unsupported
/usr/lib/systemd/system/mdcheck_start.service:15 Environment="MDADM_CHECK_DURATION=6 hours"
/usr/lib/systemd/system/mdcheck_start.service:16 ExecStart=/usr/share/mdadm/mdcheck --duration ${MDADM_CHECK_DURATION}
```

Code refs checked:

```text
/sbin/e2scrub_all:21 sets fixed PATH
/sbin/e2scrub_all:23 rejects non-root
/sbin/e2scrub_all:32 sources only /etc/e2scrub.conf
/sbin/e2scrub_all:118 obtains LVM paths from lvs
/sbin/e2scrub_all:123 parses lsblk output for ext filesystems
/sbin/e2scrub_all:174 starts escaped e2scrub@ instance
/sbin/e2scrub:26 sets fixed PATH
/sbin/e2scrub:28 rejects non-root
/sbin/e2scrub:37 sources only /etc/e2scrub.conf
/sbin/e2scrub:216 creates LVM snapshot with lvcreate
/usr/share/mdadm/mdcheck:68 tmp=/var/lib/mdcheck/.md-check-$$
/usr/share/mdadm/mdcheck:73 creates /var/lib/mdcheck as root
/usr/share/mdadm/mdcheck:91 writes mdadm --detail output to root-owned temp file
/usr/share/mdadm/mdcheck:93 state files live under /var/lib/mdcheck/MD_UUID_$MD_UUID
```

Config/state ownership:

```text
-rw-r--r-- root:root /etc/fstab
-rw-r--r-- root:root /etc/default/mdadm
drwxr-xr-x root:root /etc/mdadm
drwxr-xr-x root:root /boot
```

## Attacker probes

```sh
runuser -u attacker -- /sbin/e2scrub_all -n /tmp
# e2scrub_all must be run as root

runuser -u attacker -- /sbin/e2scrub -n /tmp
# e2scrub must be run as root

runuser -u attacker -- /usr/sbin/xfs_scrub /tmp
# /tmp: Not a XFS mount point.

runuser -u attacker -- /sbin/fstrim -n /tmp
# /tmp: 0 B (dry run) trimmed
```

`mdcheck` has a visible shell-risk shape (`source $tmp`), but the temp file is rooted under `/var/lib/mdcheck` and is populated from root-run `mdadm --detail --export "$dev"` for `/dev/md?*` devices. The attacker cannot create MD devices, cannot write `/var/lib/mdcheck`, and there were no default MD arrays in the Docker target.

## Dead end

The root services consume kernel/LVM/MD block-device state and root-owned config, not attacker-writable filesystem paths. The directly invokable helpers reject uid1001 before privileged operations or operate only on caller-accessible paths without privilege. No root context, root file write, or service-account pivot was achieved.

Cleanup: no `/var/lib/mdcheck/.md-check-*`, no attacker-owned `/run/lxd_agent`, and no filesystem-maintenance probe artifacts remained.
