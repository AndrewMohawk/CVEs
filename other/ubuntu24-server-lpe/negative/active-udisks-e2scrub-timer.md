# active UDisks loop devices versus e2scrub_all timer

Result: no validated root LPE. This pass joined two previously interesting surfaces: an active local non-sudo user can create UDisks loop devices from an attacker-owned ext4 image, and `e2scrub_all.timer` is enabled by default. In the stock Docker target the root service did not consume the attacker loop device and did not create any root proof.

## Target proof

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`.

Relevant packages:

```text
e2fsprogs 1.47.0-2.4~exp1ubuntu4.1
lvm2      2.03.16-3ubuntu3.2
systemd   255.4-1ubuntu8.15
udisks2   2.10.1-6ubuntu1.3
```

`e2scrub_all.timer` is enabled and active. `e2scrub_all.service` runs `/sbin/e2scrub_all` as root with `SERVICE_MODE=1`.

## Trigger

Probe script:

```sh
ubuntu24-server-lpe/pocs/active_udisks_e2scrub_probe.sh ubuntu24-server-lpe-target
```

The script logs in `selfauth` on tty1, creates an ext4 image, asks UDisks to create loop devices, then runs the root e2scrub paths while the loop devices exist.

Active local user proof:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
/dev/tty1
Seat=seat0
TTY=tty1
Active=yes
State=active
```

UDisks loop setup from that non-admin session succeeded:

```text
Mapped file /home/selfauth/active-udisks-e2scrub/ext.img as /dev/loop0.
Mapped file /home/selfauth/active-udisks-e2scrub/ext.img as /dev/loop1.
NAME="loop0" FSTYPE="ext4" LABEL="E2SCRUB_IN" TYPE="loop" PATH="/dev/loop0"
NAME="loop1" FSTYPE="ext4" LABEL="E2SCRUB_IN" TYPE="loop" PATH="/dev/loop1"
```

## Why it did not escalate

The default service-mode path is disabled unless the root-owned config enables periodic scrubbing:

```text
/etc/e2scrub.conf:5:# periodic_e2scrub=1
/sbin/e2scrub_all:28:periodic_e2scrub=0
/sbin/e2scrub_all:78:if [ -n "${SERVICE_MODE}" -a "${periodic_e2scrub}" -ne 1 ]; then ...
```

The probe's `bash -x` run showed the default root service exits before target scanning:

```text
+ '[' -n 1 -a 0 -ne 1 ']'
+ '[' 0 -eq 0 ']'
+ exitcode 0
+ exit 0
```

Even forcing non-service `-A` mode did not select the UDisks loop devices, because `e2scrub_all` builds its target list from LVM logical volumes:

```text
/sbin/e2scrub_all:118 lvs -o lv_path --noheadings -S "lv_active=active,lv_role=public,lv_role!=snapshot,vg_free>=${snap_size_mb}"
/sbin/e2scrub_all:123 lsblk ... $devices
```

Live result with the attacker ext4 loops present:

```text
## lvs source list
<empty>
## root e2scrub_all all mode
++ lvs -o lv_path --noheadings -S 'lv_active=active,lv_role=public,lv_role!=snapshot,vg_free>=256'
+ local devices=
+ '[' -z '' ']'
+ return 0
```

Starting the actual systemd service with the loop devices present only produced a clean no-op:

```text
Starting e2scrub_all.service - Online ext4 Metadata Check for All Filesystems...
e2scrub_all.service: Deactivated successfully.
Finished e2scrub_all.service - Online ext4 Metadata Check for All Filesystems.
```

Root proof markers were absent:

```text
ls: cannot access '/tmp/active-udisks-e2scrub-root': No such file or directory
ls: cannot access '/root/active-udisks-e2scrub-root': No such file or directory
```

## Cleanup

The probe deleted the UDisks loops, removed `/home/selfauth/active-udisks-e2scrub` and `/tmp/active-udisks-e2scrub`, restarted `getty@tty1.service`, and terminated the test login. Final verification:

```text
losetup -a | grep active-udisks-e2scrub: no output
systemctl is-system-running: running
systemctl --failed: 0 loaded units listed
```

## Scanner-miss note

This is exactly the sort of cross-boundary path a generic scanner can over-rank: UDisks gives active users root-mediated loop setup, and e2scrub has root timers plus shell `eval` on `lsblk` output. The missing exploitability condition is the target source: default service mode is off, and the non-service scan only considers LVM logical volumes, not user-created UDisks loop devices.

## Triage conclusion

No Ubuntu Security issue from this candidate. Hardening remains the same as the broader e2scrub note: avoid shell `eval` on block metadata and keep periodic scrubbing disabled unless explicitly configured by root.
