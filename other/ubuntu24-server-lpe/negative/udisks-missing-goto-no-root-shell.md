# Negative: udisks2 missing-goto root-shell validation

Result: the missing-goto bug is real and reachable by an active non-admin user, but I did not validate a standalone regular-user-to-root shell on this Ubuntu 24.04 target.

## What was proven

An active `selfauth` logind session can keep its D-Bus unique name alive after the first mounted-state error. In that condition, stock `udisks2 2.10.1-6ubuntu1.3` falls through and runs filesystem helpers as root on a mounted user loop image.

Confirmed helper argv:

```text
ext4 Check   -> e2fsck -f -n -C 1 /dev/loopN
ext4 Repair  -> e2fsck -f -y -C 1 /dev/loopN
vfat Check   -> fsck.vfat -n /dev/loopN
vfat Repair  -> fsck.vfat -a /dev/loopN
ntfs Check   -> ntfsfix -n /dev/loopN
ntfs Repair  -> ntfsfix -d /dev/loopN
ntfs Resize  -> ntfsresize --no-progress-bar -s 33554432 /dev/loopN
xfs Check    -> xfs_repair -n /dev/loopN
xfs Repair   -> xfs_repair /dev/loopN
btrfs Check  -> btrfsck /dev/loopN
btrfs Repair -> btrfsck --repair /dev/loopN
```

The mounted images are mounted with `nosuid,nodev`, and helper execution uses fixed argv arrays plus root-owned `PATH` entries. The system bus policy denies `org.freedesktop.DBus.UpdateActivationEnvironment`, and `/usr/local/{sbin,bin}` is not writable by the regular user, so helper PATH replacement was not available.

## Why this is not yet an LPE PoC

The bug gives root execution of filesystem maintenance helpers against an attacker-controlled mounted loop image, then `udisksd` crashes from stale `GDBusMethodInvocation` reuse/double-complete. I did not find a controllable root file write outside the image, command injection, writable helper search path, or current helper memory-corruption exploit on the installed helper versions.

The old public e2fsprogs code-execution issues are patched in this target's `e2fsprogs 1.47.0-2.4~exp1ubuntu4.1`; the package changelog includes the CVE-2022-1304 patch.

## Repro artifacts

Regular-user trigger:

```sh
python3 ubuntu24-server-lpe/pocs/udisks_missing_goto_helper_exec_poc.py --fstype ext4 --method Repair
```

Root-side validation harnesses used during triage:

```sh
./tools/run-udisks-gdb-probe.sh ubuntu24-server-lpe-target Check ext4
./tools/run-udisks-strace-probe.sh ubuntu24-server-lpe-target Repair ext4
```

Representative logs:

```text
ubuntu24-server-lpe/logs/udisks-missing-goto-Check-vfat.out
ubuntu24-server-lpe/logs/udisks-missing-goto-Repair-vfat.out
ubuntu24-server-lpe/logs/udisks-missing-goto-Check-ntfs.out
ubuntu24-server-lpe/logs/udisks-missing-goto-Repair-ntfs.out
ubuntu24-server-lpe/logs/udisks-missing-goto-Check-xfs.out
ubuntu24-server-lpe/logs/udisks-missing-goto-Repair-xfs.out
ubuntu24-server-lpe/logs/udisks-missing-goto-Resize-ntfs.out
ubuntu24-server-lpe/logs/udisks-missing-goto-Check-btrfs.out
ubuntu24-server-lpe/logs/udisks-missing-goto-Repair-btrfs.out
```
