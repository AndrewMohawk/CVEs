# Negative: filesystem, RAID, trim, and scrub maintenance helpers

Status: no validated LPE from a normal non-sudo user in the stock Ubuntu 24.04 Server Docker target.

## Target proof

Target container: `ubuntu24-server-lpe-target`

Relevant package versions:

```text
e2fsprogs 1.47.0-2.4~exp1ubuntu4.1
lvm2 2.03.16-3ubuntu3.2
mdadm 4.3-1ubuntu2.1
systemd 255.4-1ubuntu8.15
util-linux 2.39.3-9ubuntu6.5
xfsprogs 6.6.0-1ubuntu2.1
```

The target is the stock server task image built with `ubuntu-minimal`, `ubuntu-standard`, and `ubuntu-server`; `apt-get -s full-upgrade` reported `0 upgraded, 0 newly installed, 0 to remove`.

## Default root timers and units

The following maintenance paths exist in the stock server image:

```text
e2scrub_all.timer active waiting
e2scrub_all.service inactive dead
e2scrub_reap.service inactive dead
xfs_scrub_all.timer disabled/inactive in the Docker target despite preset enabled
mdcheck_start.timer enabled but inactive because it is WantedBy=mdmonitor.service
mdmonitor.service static inactive
mdmonitor-oneshot.timer enabled but inactive
fstrim.timer enabled but inactive, condition unmet: ConditionVirtualization=!container
```

Relevant unit evidence:

```text
/usr/lib/systemd/system/e2scrub_all.timer:5:OnCalendar=Sun *-*-* 03:10:00
/usr/lib/systemd/system/e2scrub_all.timer:8:Persistent=true
/usr/lib/systemd/system/e2scrub_all.service:3:ConditionCapability=CAP_SYS_ADMIN
/usr/lib/systemd/system/e2scrub_all.service:4:ConditionPathIsReadWrite=/var/lib
/usr/lib/systemd/system/e2scrub_all.service:5:ConditionDirectoryNotEmpty=|/run/systemd/system
/usr/lib/systemd/system/e2scrub_all.service:10:Environment=SERVICE_MODE=1
/usr/lib/systemd/system/e2scrub_all.service:11:ExecStart=/sbin/e2scrub_all
/usr/lib/systemd/system/e2scrub@.service:9:PrivateNetwork=true
/usr/lib/systemd/system/e2scrub@.service:10:ProtectSystem=true
/usr/lib/systemd/system/e2scrub@.service:11:PrivateTmp=false
/usr/lib/systemd/system/e2scrub@.service:12:AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_RAWIO
/usr/lib/systemd/system/e2scrub@.service:14:NoNewPrivileges=true
/usr/lib/systemd/system/e2scrub@.service:15:User=root
/usr/lib/systemd/system/e2scrub@.service:19:ExecStart=/sbin/e2scrub -t %I
/usr/lib/systemd/system/mdcheck_start.timer:12:OnCalendar=Sun *-*-1..7 1:00
/usr/lib/systemd/system/mdcheck_start.timer:13:RandomizedDelaySec=24h
/usr/lib/systemd/system/mdcheck_start.timer:14:Persistent=true
/usr/lib/systemd/system/mdcheck_start.timer:17:WantedBy=mdmonitor.service
/usr/lib/systemd/system/mdcheck_start.service:15:Environment="MDADM_CHECK_DURATION=6 hours"
/usr/lib/systemd/system/mdcheck_start.service:16:ExecStart=/usr/share/mdadm/mdcheck --duration ${MDADM_CHECK_DURATION}
/usr/lib/systemd/system/mdmonitor-oneshot.service:13:EnvironmentFile=-/etc/default/mdadm
/usr/lib/systemd/system/mdmonitor-oneshot.service:14:ExecStart=sh -c '[ "$AUTOSCAN" != "true" ] || /sbin/mdadm --monitor --oneshot --scan'
/usr/lib/systemd/system/xfs_scrub_all.timer:11:OnCalendar=Sun *-*-* 03:10:00
/usr/lib/systemd/system/xfs_scrub_all.timer:12:RandomizedDelaySec=60m
/usr/lib/systemd/system/xfs_scrub_all.timer:13:Persistent=true
/usr/lib/systemd/system/xfs_scrub_all.service:8:ConditionACPower=true
/usr/lib/systemd/system/xfs_scrub_all.service:15:ExecStart=/usr/sbin/xfs_scrub_all
/usr/lib/systemd/system/fstrim.timer:4:ConditionVirtualization=!container
/usr/lib/systemd/system/fstrim.timer:5:ConditionPathExists=!/etc/initrd-release
/usr/lib/systemd/system/fstrim.timer:8:OnCalendar=weekly
/usr/lib/systemd/system/fstrim.timer:11:Persistent=true
/usr/lib/systemd/system/fstrim.service:8:ExecStart=/sbin/fstrim --listed-in /etc/fstab:/proc/self/mountinfo --verbose --quiet-unsupported
```

## Interesting code paths

`mdadm` has an injection-looking path, but the temporary file is created and populated by root in a root-owned directory from root-selected md devices:

```text
/usr/share/mdadm/mdcheck:68:tmp=/var/lib/mdcheck/.md-check-$$
/usr/share/mdadm/mdcheck:73:mkdir -p /var/lib/mdcheck
/usr/share/mdadm/mdcheck:74:find /var/lib/mdcheck -name "MD_UUID*" -type f -mtime +8 -delete
/usr/share/mdadm/mdcheck:91:mdadm --detail --export "$dev" | grep '^MD_UUID=' > $tmp
/usr/share/mdadm/mdcheck:92:source $tmp
/usr/share/mdadm/mdcheck:93:MDADM_CHECK_STATE=/var/lib/mdcheck/MD_UUID_$MD_UUID
```

`e2scrub_all` and `e2scrub` both use `eval` on `lsblk` output, but the selected block-device metadata is root/kernel controlled in the default server state:

```text
/sbin/e2scrub_all:21:PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
/sbin/e2scrub_all:23:test -n "${SERVICE_MODE}" -a "`id -u`" -ne 0 && echo "e2scrub_all must be run as root" && exit 1
/sbin/e2scrub_all:32:conffile="/etc/e2scrub.conf"
/sbin/e2scrub_all:118:lvs ...
/sbin/e2scrub_all:123:lsblk ... | while read vars; do eval "${vars}"
/sbin/e2scrub_all:174:systemctl start "e2scrub@${tgt_esc}"
/sbin/e2scrub:26:PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
/sbin/e2scrub:28:test -n "${SERVICE_MODE}" -a "`id -u`" -ne 0 && echo "e2scrub must be run as root" && exit 1
/sbin/e2scrub:37:conffile="/etc/e2scrub.conf"
/sbin/e2scrub:111:lsblk ... | while read vars; do
/sbin/e2scrub:112:eval "${vars}"
/sbin/e2scrub:190:/sbin/e2fsck ...
/sbin/e2scrub:195:/sbin/tune2fs ...
/sbin/e2scrub:199:/sbin/tune2fs ...
/sbin/e2scrub:216:lvcreate ...
```

`xfs_scrub_all` uses JSON-formatted `lsblk` output and fixed binaries:

```text
/usr/sbin/xfs_scrub_all:47:lsblk --paths --list --json --output FSTYPE,PATH
/usr/sbin/xfs_scrub_all:94:systemd-escape --template xfs_scrub@.service --path
/usr/sbin/xfs_scrub_all:110:systemctl start ...
/usr/sbin/xfs_scrub_all:178:/usr/sbin/xfs_scrub -b -n
```

## Unprivileged triggers

As `attacker`:

```sh
/sbin/e2scrub_all
/sbin/e2scrub
/usr/share/mdadm/mdcheck -n /tmp
/usr/sbin/xfs_scrub_all -n /tmp
/usr/sbin/xfs_scrub -n /tmp
/sbin/fstrim -n /tmp
```

Observed results:

```text
e2scrub_all must be run as root
e2scrub must be run as root
mdcheck: invalid option / non-root invocation only
/tmp: Not a XFS mount point.
0 B (dry run) trimmed
```

No direct helper invocation crossed privilege boundaries.

## Control checks

User-controlled configuration was not available:

```text
/etc/default/mdadm root:root 0644
/etc/mdadm/mdadm.conf root:root 0644
/etc/fstab root:root 0644
/boot root:root 0755
/etc/initramfs-tools/* root:root
```

`/etc/e2scrub.conf` was absent in the target or root-owned if created by package configuration; the normal user could not write it.

## Dead end

`e2scrub_all.timer` is a real default root timer, but it selects LVM/ext filesystems from root-owned block and LVM metadata. A normal non-sudo user in the default server state cannot create a malicious LVM/ext target or mutate `/etc/e2scrub.conf`.

`mdcheck` contains a suspicious `source $tmp` pattern, but `$tmp` is root-created in `/var/lib/mdcheck` and populated from `mdadm --detail --export` over root-selected `/dev/md*` devices. The default target has no active md arrays, and `attacker` cannot create `/dev/md*` or write `/var/lib/mdcheck`.

`xfs_scrub_all` is not active in this Docker systemd target and requires XFS mounts/devices the user cannot create in stock default state.

`fstrim.timer` is explicitly inactive in the Docker target because of `ConditionVirtualization=!container`. Even outside a container, the service reads root-owned `/etc/fstab` and `/proc/self/mountinfo` and does not execute attacker input.

## Cleanup

No persistent cleanup was required. The probes did not create root-owned files or units.

## Why scanners may miss or over-rank it

This area has several LLM-interesting primitives: root timers, shell scripts, `eval`, `source`, and block-device metadata parsing. Generic SAST tends to over-rank those patterns without proving whether a normal user can control the specific metadata source in the stock server state.

## Suggested hardening

No Ubuntu Security issue is claimed from this candidate. Defense-in-depth ideas only:

```text
- Replace shell `eval` on `lsblk` output in e2scrub scripts with structured parsing.
- Avoid `source` in mdcheck; parse `MD_UUID=` as data and validate with a strict UUID regex.
- Keep maintenance timers gated by root-owned configuration and device metadata.
- Add autopkgtests that run these helpers from an unprivileged account and verify no privilege boundary is crossed.
```
